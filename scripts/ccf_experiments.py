from collections import defaultdict
from copy import deepcopy
import json
from experiments import BaseExperiment, copy_file_from_remote_public_ip
from deployment import Deployment
from deployment_aci import AciDeployment
import os
from typing import List, Tuple
from abc import ABC, abstractmethod
import pickle
from time import sleep
from pprint import pprint
from ssh_utils import run_remote_public_ip, copy_remote_public_ip, run_local
from x5chain_certificate_authority import X5ChainCertificateAuthority
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64
from pyscitt import crypto
from cryptography.hazmat.primitives import hashes


PLATFORM = "virtual" # "virtual", "snp"
SPAWN_RATE = 5
CUSTOM_EKU = "1.3.6.1.5.5.7.3.36"
KEY_TYPE = "ec"
ALG = "ES256"
EC_CURVE = "P-256"

# the initial idea was to make this an abstract class to support different types of CCF systems
# for now, it is just a SCITT-CCF experiment, but that can change
#class CCFExperiment(BaseExperiment, ABC):
class CCFExperiment(BaseExperiment):
    # if we make this an abstract class, we need to set the path to the CCF lib, as well as some extra config probably
    # since this is not clear based on a single example, I left it concrete for now
    # @abstractmethod 
    # def get_library_path(self) -> str:
    #     pass

    # @abstractmethod
    def save_if_done(self) -> None:
        pass

    # main calls this, it does not make as much sense for a non-PirateShip experiment
    def get_build_details(self) -> Tuple[str, str]:
        return (None, None, None)

    def deploy(self,
               deployment: Deployment,
               last_git_hash="",
               last_git_diff="",
               last_build_command="") -> None:
        assert isinstance(deployment, AciDeployment) # for now, this only supports container deployments
        if self.done():
            print("Experiment already done")

        # Create the necessary directories
        workdir = os.path.join(deployment.workdir, "experiments", self.name)
        build_dir, config_dir, log_dir_base, log_dirs = self.create_directory(workdir)
        # self.tag_source(workdir) # 
        # self.tag_experiment(workdir)
        self.dev_vm = deployment.dev_vm
        self.dev_ssh_user = deployment.ssh_user
        self.dev_ssh_key = deployment.ssh_key
        # Hard dependency on Linux style paths
        self.remote_workdir = f"/home/{deployment.ssh_user}/{deployment.workdir}/experiments/{self.name}"
        self.generate_configs(deployment, config_dir)
        self.local_workdir = workdir


        # CCF has load of dependencies. It is not easy to install once a copy to the other VMs
        # for now, everything is installed on the dockerfile
        # if we change this, it is a matter of calling some sort of `remote_build` but for all VMs (not just dev_vm)

        # Generate the shell script to run the experiment
        self.generate_arbiter_script()

        # Save myself (again)
        with open(os.path.join(workdir, "experiment.pkl"), "wb") as f:
            pickle.dump(self, f)

        # Save myself (again) to keep the pristine state
        with open(os.path.join(workdir, "experiment_pristine.pkl"), "wb") as f:
            pickle.dump(self, f)

        # Save myself in text (again)
        with open(os.path.join(workdir, "experiment.txt"), "w") as f:
            pprint(self, f)

    def gen_crypto(self, config_dir):
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
        cts_policy = {
            "authentication": {
                "allowUnauthenticated": True
            },
            "policy": {
                "policyScript": "export function apply(phdr) { if (!phdr.cwt.iss) {return 'Issuer not set'} else if (phdr.cwt.iss !== 'did:x509:0:sha256:"+root_fingerprint+"::eku:"+CUSTOM_EKU+"') { return 'Invalid issuer'; } return true; }"
            }
        }
        print("Generated CTS policy:", cts_policy)
        with open(os.path.join(config_dir, "cts_policy.json"), "w") as f:
            json.dump(cts_policy, f, indent=4)
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


    def generate_configs(self, deployment: Deployment, config_dir):
        # If config_dir is not empty, assume the configs have already been generated
        if len(os.listdir(config_dir)) > 0:
            print("Skipping config generation for experiment", self.name)
            return
        # Number of nodes in deployment may be < number of nodes in deployment
        # So we reuse nodes.
        # As a default, each deployed node gets its unique port number
        # So there will be no port clash.

        rr_cnt = 0
        nodelist = []
        nodes = {}
        node_configs = {}
        vms = []
        node_list_for_crypto = {}
        if self.node_distribution == "uniform":
            vms = deployment.get_all_node_vms()
        elif self.node_distribution == "sev_only":
            vms = deployment.get_nodes_with_tee("sev")
        # elif self.node_distribution == "tdx_only":
        #     vms = deployment.get_nodes_with_tee("tdx")
        elif self.node_distribution == "nontee_only":
            vms = deployment.get_nodes_with_tee("nontee")
        else:
            vms = deployment.get_wan_setup(self.node_distribution)

        self.binary_mapping = defaultdict(list)
        self.getRequestHosts = []

        self.leader_listen_addr = None
        self.ledger_directory = self.base_node_config.get("ledger_directory", "ledger")
        self.snapshot_directory = self.base_node_config.get("snapshot_directory", "snapshots")
        for node_num in range(1, self.num_nodes + 1):
            port = deployment.node_port_base + node_num
            node_port = deployment.node_port_base + node_num + 1000
            _vm = vms[rr_cnt % len(vms)]
            listen_addr_public = f"{_vm.private_ip}:{port}"
            node_to_node_addr_public = f"{_vm.private_ip}:{node_port}"
            listen_addr = f"0.0.0.0:{port}"
            node_to_node_addr = f"0.0.0.0:{node_port}"
            if self.leader_listen_addr is None:
                name = "leader"
                self.leader_listen_addr = listen_addr_public
                self.leader = _vm
            else:
                name = f"node{node_num}"
            domain = f"{name}.ccf.org"
            self.binary_mapping[_vm].append(name)

            private_ip = _vm.private_ip
            rr_cnt += 1
            connect_addr = f"{private_ip}:{port}"

            nodelist.append(name[:])
            nodes[name] = {"addr": connect_addr, "domain": domain}

            node_list_for_crypto[name] = (connect_addr, domain)

            config = deepcopy(self.base_node_config)
            config["net_config"]["name"] = name
            config["net_config"]["addr"] = listen_addr
            node_configs[name] = config
            ccf_config = {
                "enclave": {
                    "file": f"/opt/scitt-ccf-ledger/build/app/libscitt.{PLATFORM}.so",
                    "platform": PLATFORM.capitalize(),
                    "type": "Release"
                },
                "network": {
                    "node_to_node_interface": {
                        "bind_address": node_to_node_addr,
                        "published_address": node_to_node_addr_public,
                    },
                    "rpc_interfaces": {
                        "interface_name": {
                            "bind_address": listen_addr,
                            "published_address": listen_addr_public,
                        }
                    }
                },
                "ledger_signatures": {
                    "tx_count": self.base_node_config.get("sig_tx_count", 5_000),
                    "delay": self.base_node_config.get("sig_delay", "1000ms"),
                },
                "worker_threads": self.base_node_config.get("worker_threads", 14),
                "snapshots": {
                    "directory": self.snapshot_directory,
                    "tx_count": self.base_node_config.get("snapshot_tx_count", 10_000),
                },
                "ledger": {
                    "directory": self.ledger_directory,
                },
                "node_certificate": {
                    "curve_id": self.base_node_config.get("curve_id", "Secp384R1"),
                },
                "memory": {
                    "circuit_size": self.base_node_config.get("circuit_size", "16MB"),
                    "max_msg_size": self.base_node_config.get("max_msg_size", "64MB"),
                    "max_fragment_size": self.base_node_config.get("max_fragment_size", "256KB"),
                },
                "historical_cache_soft_limit": self.base_node_config.get("historical_cache_soft_limit", "100MB"),
            }
            if name == "leader":
                ccf_config["command"] = {
                    "type": "Start",
                    "service_certificate_file": "/tmp/service_cert.pem",
                    "start": {
                        "constitution_files": [
                            "/tmp/scitt/share/scitt/constitution/validate.js",
                            "/tmp/scitt/share/scitt/constitution/apply.js",
                            "/tmp/scitt/share/scitt/constitution/resolve.js",
                            "/tmp/scitt/share/scitt/constitution/actions.js",
                            "/tmp/scitt/share/scitt/constitution/scitt.js"
                        ],
                        "members": [
                            {
                                "certificate_file": f"{self.remote_workdir}/configs/keys/member0_cert.pem",
                                "encryption_public_key_file": f"{self.remote_workdir}/configs/keys/member0_enc_pubk.pem",
                            }
                        ]
                    }
                }
            else:
                assert self.leader_listen_addr is not None, "Leader address should be set before joining nodes"
                ccf_config["command"] = {
                    "type": "Join",
                    "service_certificate_file": "/tmp/service_cert.pem",
                    "join": {
                        "target_rpc_address": self.leader_listen_addr,
                        "retry_timeout": "1s"
                    }
                }

            with open(os.path.join(config_dir, f"{name}_ccf_config.json"), "w") as f:
                json.dump(ccf_config, f, indent=4)

        if self.client_region == -1:
            client_vms = deployment.get_all_client_vms()
        else:
            client_vms = deployment.get_all_client_vms_in_region(self.client_region)
        self.client_vms = client_vms[:]

        self.gen_crypto(config_dir)

        self.num_clients_per_vm = [self.num_clients // len(client_vms) for _ in range(len(client_vms))]
        self.num_clients_per_vm[-1] += (self.num_clients - sum(self.num_clients_per_vm))
        for client_vm_num in range(len(client_vms)):
            self.binary_mapping[client_vms[client_vm_num]].append(f"client{client_vm_num}")

        run_local([
            f"cp {os.path.join(os.path.dirname(__file__), 'locustfile.py')} {config_dir}/locustfile.py"
        ])


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
            
            # start leader
            _script += f"""
$SSH_CMD {self.dev_ssh_user}@{self.leader.private_ip} <<'EOF' &
rm -f cchost.pid
rm -rf snapshots/
rm -rf ledger/
rm -f nodecert.pem
/opt/ccf_{PLATFORM}/bin/cchost --config {self.remote_workdir}/configs/leader_ccf_config.json > {self.remote_workdir}/logs/{repeat_num}/leader.log 2> {self.remote_workdir}/logs/{repeat_num}/leader.err
EOF
PID="$PID $!"
sleep 5
"""
            if self.measure_resources:
                _script += f"""
$SSH_CMD {self.dev_ssh_user}@{self.leader.private_ip} 'dool -tclmnd -o {self.remote_workdir}/logs/{repeat_num}/leader.stats.csv' &
PID="$PID $!"
"""

            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" not in bin: continue
            # get service cert
            # join leader
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} <<'EOF' &
curl -k https://{self.leader_listen_addr}/node/network | jq -r .service_certificate | head -n -1 > /tmp/service_cert.pem
rm -f cchost.pid
rm -rf snapshots/
rm -rf ledger/
rm -f nodecert.pem
/opt/ccf_{PLATFORM}/bin/cchost --config {self.remote_workdir}/configs/{bin}_ccf_config.json > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err
EOF
PID="$PID $!"
"""
                    if self.measure_resources:
                        _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'dool -tclmnd -o {self.remote_workdir}/logs/{repeat_num}/{bin}.stats.csv' &
PID="$PID $!"
"""

            # setup/open cluster
            _script += f"""
sleep 5
$SSH_CMD {self.dev_ssh_user}@{self.leader.private_ip} <<EOF
. /opt/scitt-ccf-ledger/venv/bin/activate
scitt governance activate_member \
    --url https://{self.leader_listen_addr} \
    --member-key {self.remote_workdir}/configs/keys/member0_privk.pem \
    --member-cert {self.remote_workdir}/configs/keys/member0_cert.pem \
    --development
scitt governance propose_configuration \
    --configuration {self.remote_workdir}/configs/cts_policy.json \
    --url https://{self.leader_listen_addr} \
    --member-key {self.remote_workdir}/configs/keys/member0_privk.pem \
    --member-cert {self.remote_workdir}/configs/keys/member0_cert.pem \
    --development
scitt governance propose_open_service \
    --url https://{self.leader_listen_addr} \
    --member-key {self.remote_workdir}/configs/keys/member0_privk.pem \
    --member-cert {self.remote_workdir}/configs/keys/member0_cert.pem \
    --next-service-certificate /tmp/service_cert.pem \
    --development
EOF
"""
            # run clients
            client_n = 0
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if not "client" in bin: continue
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} <<'EOF' &
. /opt/scitt-ccf-ledger/venv/bin/activate
locust -f {self.remote_workdir}/configs/locustfile.py \
    --headless \
    --skip-log \
    --json \
    --host https://{self.leader_listen_addr} \
    --users {self.num_clients_per_vm[client_n]} \
    --spawn-rate {self.num_clients_per_vm[client_n]} \
    --run-time {self.duration} \
    --csv {self.remote_workdir}/logs/{repeat_num}/{bin} \
    --csv-full-history {'--skip-confirmation' if self.base_client_config.get('skip_confirmation', False) else ''}\
    --validation-policy {self.remote_workdir}/configs/cts_policy.json \ 
    --policy-update-rate 0 \
    --scitt-statements {self.remote_workdir}/configs/cose  > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err
EOF

CLIENT_PIDS="$CLIENT_PIDS $!"
"""
                    client_n += 1
                    if self.measure_resources:
                        _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'dool -tclmnd -o {self.remote_workdir}/logs/{repeat_num}/{bin}.stats.csv' &
PID="$PID $!"
"""
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
$SCP_CMD -r {self.dev_ssh_user}@{self.leader.private_ip}:{self.ledger_directory} {self.remote_workdir}/logs/{repeat_num}/ledger || true
"""
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin or "leader" in bin:
                        binary_name = "cchost"
                    else:
                        binary_name = "client"
                # Copy the logs back
                    _script += f"""
echo "Trying to kill things"
result="1"
while [ "$result" != "0" ]; do
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -2 -c {binary_name}' || true
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -15 -c {binary_name}' || true
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill -9 -c {binary_name}' || true
     $SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'pkill python3' || true # kill resource measurement (dool)
     result=$($SSH_CMD {self.dev_ssh_user}@{vm.private_ip} "pgrep -x '{binary_name}' > /dev/null && echo 1 || echo 0")
     echo "Result: $result"
done
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'rm -rf /data/*' || true
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.log {self.remote_workdir}/logs/{repeat_num}/{bin}.log || true
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.err {self.remote_workdir}/logs/{repeat_num}/{bin}.err || true
"""
                    if self.measure_resources:
                        _script += f"""
$SCP_CMD {self.dev_ssh_user}@{vm.private_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.stats.csv {self.remote_workdir}/logs/{repeat_num}/{bin}.stats.csv || true
"""

            _script += f"""
sleep 10
"""

            # pkill -9 -c server also kills tmux-server. So we can't run a server on the dev VM.
            # It kills the tmux session and the experiment. And we end up with a lot of orphaned processes.

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")
