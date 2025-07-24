from collections import defaultdict
from copy import deepcopy
import json
from experiments import PirateShipExperiment
from deployment import Deployment
from deployment_aci import AciDeployment
import os
from typing import List, Tuple
from abc import ABC, abstractmethod
import pickle
from time import sleep
from pprint import pprint
from ssh_utils import copy_file_from_remote_public_ip, run_remote_public_ip, copy_remote_public_ip, run_local
from x5chain_certificate_authority import X5ChainCertificateAuthority
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64
from pyscitt import crypto
from cryptography.hazmat.primitives import hashes


DEFAULT_CA_NAME = "CCF"
CCF_VERSION = "ccf-6.0.5"
PLATFORM = "virtual" # "virtual", "snp"
NUM_CLIENTS = 100
RUNTIME = "60s"
SPAWN_RATE = 5
CUSTOM_EKU = "1.3.6.1.5.5.7.3.36"
KEY_TYPE = "ec"
ALG = "ES256"
EC_CURVE = "P-256"

class ScittExperiment(PirateShipExperiment):
    def gen_crypto(self, config_dir, nodelist, client_cnt):
        crypto_info = super().gen_crypto(config_dir, nodelist, client_cnt) # Call the base class method to generate pirateship crypto things

        # Now generate the SCITT crypto things
        # This tries to mimic the original SCITT-CCF logic
        keys_dir = os.path.join(config_dir, "keys")
        run_local([
            f"mkdir -p {keys_dir}"
        ])

        # Generate the CA certificate and private key
        print("Generating CA certificate and private key")
        cert_authority = X5ChainCertificateAuthority(kty=KEY_TYPE)
        identity = cert_authority.create_identity(
            alg=ALG, kty=KEY_TYPE, ec_curve=EC_CURVE, add_eku=CUSTOM_EKU
        )
        with open(os.path.join(keys_dir, "cacert_privk.pem"), "w") as f:
            f.write(identity.private_key)
        cert_bundle = b""
        for cert in identity.x5c:
            pemcert = x509.load_pem_x509_certificate(cert.encode())
            cert_bundle += pemcert.public_bytes(serialization.Encoding.PEM)
        with open(os.path.join(keys_dir, "cacert.pem"), "wb") as f:
            f.write(cert_bundle)

        print("Generating CA encryption keypair")
        # Generate the member0 certificate and private key
        member0_privk, member0_pubk = crypto.generate_keypair(kty="ec")
        with open(os.path.join(keys_dir, "member0_privk.pem"), "w") as f:
            f.write(member0_privk)
        member0_cert = crypto.generate_cert(member0_privk, ca=False)
        with open(os.path.join(keys_dir, "member0_cert.pem"), "w") as f:
            f.write(member0_cert)
        member0_enc_privk, member0_enc_pubk = crypto.generate_keypair(kty="rsa")
        with open(os.path.join(keys_dir, "member0_enc_pubk.pem"), "w") as f:
            f.write(member0_enc_pubk)
        with open(os.path.join(keys_dir, "member0_enc_privk.pem"), "w") as f:
            f.write(member0_enc_privk)

        last_cert_pem = identity.x5c[-1]
        last_cert = x509.load_pem_x509_certificate(last_cert_pem.encode())
        fingerprint_bytes = last_cert.fingerprint(hashes.SHA256())
        root_fingerprint = base64.urlsafe_b64encode(fingerprint_bytes).decode('ascii').strip('=')
        cts_policy = "function apply(phdr) { if (!phdr.cwt.iss) {return 'Issuer not set'} else if (phdr.cwt.iss !== 'did:x509:0:sha256:"+root_fingerprint+"::eku:"+CUSTOM_EKU+"') { return 'Invalid issuer'; } return true; }"
        print("Generated CTS policy:", cts_policy)
        with open(os.path.join(config_dir, "cts_policy.js"), "w") as f:
            f.write(cts_policy)
        issuer = f"did:x509:0:sha256:{root_fingerprint}::eku:{CUSTOM_EKU}"
        with open(os.path.join(config_dir, "issuer.txt"), "w") as f:
            f.write(issuer)
        
        print("Generating COSE files for clients")
        cose_dir = os.path.join(config_dir, "cose")
        run_local([
            f"mkdir -p {cose_dir}"
        ])
        claim_payload = {"claim": "This is a test claim"}
        json_payload = json.dumps(claim_payload).encode('utf-8')
        for c in range(self.num_clients):
            key = identity.private_key
            signer = crypto.Signer(
                key, issuer=issuer, x5c=identity.x5c
            )
            registration_info = {arg.name: arg.value() for arg in []}
            signed_statement = crypto.sign_statement(
                signer, json_payload, "application/json", None, registration_info, cwt=True
            )
            with open(os.path.join(cose_dir, f"claim{c}.cose"), "wb") as f:
                f.write(signed_statement)
        run_local([
            f"cp {os.path.join(os.path.dirname(__file__), 'locustfile.py')} {config_dir}/locustfile.py"
        ])
        return crypto_info


    def copy_back_build_files(self):
        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        TARGET_BINARIES = ["scitt"]

        # Copy the target/release to build directory
        for bin in TARGET_BINARIES:
            copy_file_from_remote_public_ip(f"{remote_repo}/target/release/{bin}", os.path.join(self.local_workdir, "build", bin), self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)

    def generate_arbiter_script(self):

        script_base = f"""#!/bin/bash
set -e
set -o xtrace

# This script is generated by the experiment pipeline. DO NOT EDIT.
SSH_CMD="ssh -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"
SCP_CMD="scp -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"

# SSH into each VM and run the binaries
"""
        # Plan the binaries to run
        for repeat_num in range(self.repeats):
            print("Running repeat", repeat_num)
            _script = script_base[:]
            leader = None
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" not in bin: continue
                    binary_name = "scitt"
                    if not leader:
                        leader = vm

                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'RUST_BACKTRACE=full  {self.remote_workdir}/build/{binary_name} {self.remote_workdir}/configs/{bin}_config.json > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err' &
PID="$PID $!"
"""
            # setup/open cluster
            _script += f"""
sleep 30
$SSH_CMD {self.dev_ssh_user}@{leader.private_ip} <<EOF
curl -X POST "https://{leader.private_ip}:4001/policy" -H "Content-Type: application/txt" --upload-file {self.remote_workdir}/configs/cts_policy.js -k
EOF
"""
            # run clients
            client_n = 0
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin: continue
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} <<'EOF' &
. /opt/scitt-ccf-ledger/venv/bin/activate
locust -f {self.remote_workdir}/configs/locustfile.py \
    --headless \
    --skip-log \
    --json \
    --host https://{leader.private_ip}:4001 \
    --users {self.num_clients_per_vm[client_n]} \
    --spawn-rate {self.num_clients_per_vm[client_n]} \
    --run-time {self.duration} \
    --csv {self.remote_workdir}/logs/{repeat_num}/{bin} \
    --csv-full-history \
    --scitt-statements {self.remote_workdir}/configs/cose  > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err
EOF

CLIENT_PIDS="$CLIENT_PIDS $!"
"""
                    client_n += 1

            # kill cluster
            _script += f"""
for pid in $CLIENT_PIDS; do
    wait $pid || true
done

# Kill the binaries. First with a SIGINT, then with a SIGTERM, then with a SIGKILL
echo -n $PID | xargs -d' ' -I{{}} kill -2 {{}} || true
echo -n $PID | xargs -d' ' -I{{}} kill -15 {{}} || true
echo -n $PID | xargs -d' ' -I{{}} kill -9 {{}} || true
sleep 10

# Kill the binaries in SSHed VMs as well. Calling SIGKILL on the local SSH process might have left them orphaned.
# Make sure not to kill the tmux server.
# Then copy the logs back and delete any db files. Cleanup for the next run.
"""
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin:
                        binary_name = "scitt"
                    elif "client" in bin:
                        binary_name = "client"
                # Copy the logs back
                    _script += f"""
echo "Trying to kill things"
result="1"
while [ "$result" != "0" ]; do
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -2 -c {binary_name}' || true
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -15 -c {binary_name}' || true
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -9 -c {binary_name}' || true
     result=$($SSH_CMD {self.dev_ssh_user}@{vm.private_ip} "pgrep -x '{binary_name}' > /dev/null && echo 1 || echo 0")
     echo "Result: $result"
done
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'rm -rf /data/*' || true
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.log {self.remote_workdir}/logs/{repeat_num}/{bin}.log || true
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.err {self.remote_workdir}/logs/{repeat_num}/{bin}.err || true
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}_stats_history.csv {self.remote_workdir}/logs/{repeat_num}/{bin}_stats_history.csv || true
"""

            _script += f"""
sleep 30
"""

            # pkill -9 -c server also kills tmux-server. So we can't run a server on the dev VM.
            # It kills the tmux session and the experiment. And we end up with a lot of orphaned processes.

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")
