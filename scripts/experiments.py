from dataclasses import dataclass
from deployment import Deployment
from deployment_aci import AciDeployment
from ssh_utils import run_local, run_remote_public_ip, copy_remote_public_ip, copy_file_from_remote_public_ip, copy_dir_from_remote_public_ip
from crypto import gen_keys_and_certs, TLS_CERT_SUFFIX, TLS_PRIVKEY_SUFFIX, ROOT_CERT_SUFFIX, PUB_KEYLIST_NAME, SIGN_PRIVKEY_SUFFIX
from copy import deepcopy
from pprint import pprint
import pickle
from collections import defaultdict
import json
from time import sleep
from typing import List, Tuple
import os
from abc import ABC, abstractmethod


DEFAULT_CA_NAME = "Pft"


@dataclass
class BaseExperiment(ABC):
    name: str
    group_name: str
    seq_num: int
    repeats: int
    duration: int
    num_nodes: int
    num_clients: int
    base_node_config: dict
    base_client_config: dict
    node_distribution: str
    client_region: int
    build_command: str
    git_hash_override: str
    project_home: str
    controller_must_run: bool

    @abstractmethod
    def deploy(self,
               deployment: Deployment,
               last_git_hash="",
               last_git_diff="",
               last_build_command="") -> None:
        pass

    @abstractmethod
    def get_build_details(self) -> Tuple[str, str]:
        pass

    def run_plan(self) -> Tuple[List[str], int]:
        if self.done():
            return [], 0 # May arise if this experiment is brought back from the dead
        self.__done__ = False

        # Find which repeats have logs copied to local machine.
        # I will not check for integrity of the log dir.
        # If the log dir is not empty, I will assume the logs are complete.
        # If that is not the case, delete the logs manually.
        maybe_incomplete_repeats = []
        for i in range(self.repeats):
            dirname = os.path.join(self.local_workdir, "logs", str(i))
            print("Checking locally:", dirname)
            # Does this dir have any files?
            if len(os.listdir(dirname)) > 0:
                print(f"Skipping repeat {i} for experiment {self.name}")
                continue
            maybe_incomplete_repeats.append(i)

        # Does the remote workdir have the logs?
        need_to_run_repeats = []
        available_remotely = 0
        for i in maybe_incomplete_repeats:
            dirname = os.path.join(self.remote_workdir, "logs", str(i))
            print("Checking remotely:", dirname)
            res = run_remote_public_ip([
                f"ls {dirname}"
            ], self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True)[0]
            if len(res) == 0:
                need_to_run_repeats.append(i)
            else:
                print(f"Logs for repeat {i} already exist in remote")
                available_remotely += 1

        print("Need to run repeats:", need_to_run_repeats)

        script_lines = [f"sh {self.remote_workdir}/arbiter_{i}.sh" for i in need_to_run_repeats]

        return script_lines, available_remotely

    def save_if_done(self):
        # Check if all the logs are present
        for i in range(self.repeats):
            dirname = os.path.join(self.local_workdir, "logs", str(i))
            if len(os.listdir(dirname)) == 0:
                print(f"Logs for repeat {i} are missing. Experiment {self.name} is not done.")
                return

        self.__done__ = True
        with open(os.path.join(self.local_workdir, "experiment.pkl"), "wb") as f:
            pickle.dump(self, f)
        print("Experiment", self.name, "is done.")

    def set_local_workdir(self, workdir):
        self.local_workdir = workdir

    def get_local_workdir(self):
        return self.local_workdir

    def done(self):
        try:
            done = self.__done__
            return done
        except Exception:
            return False

    def tag_experiment(self, workdir):
        with open(os.path.join(workdir, "experiment.txt"), "w") as f:
            pprint(self, f)

        with open(os.path.join(workdir, "experiment.pkl"), "wb") as f:
            pickle.dump(self, f)

    def create_directory(self, workdir):
        build_dir = os.path.join(workdir, "build")
        config_dir = os.path.join(workdir, "configs")
        log_dir_base = os.path.join(workdir, "logs")
        log_dirs = [
            os.path.join(log_dir_base, str(i))
            for i in range(self.repeats)
        ]

        run_local([
            f"mkdir -p {d}"
            for d in [build_dir] + [config_dir] + log_dirs
        ])

        return build_dir, config_dir, log_dir_base, log_dirs


class PirateShipExperiment(BaseExperiment):

    def tag_source(self, workdir):
        if self.git_hash_override is None:
            git_hash, patch = run_local([
                "git rev-parse HEAD",
                "git diff"
            ])
        else:
            git_hash = self.git_hash_override
            patch = ""

        patch += "\n\n"

        with open(os.path.join(workdir, "git_hash.txt"), "w") as f:
            f.write(git_hash)

        with open(os.path.join(workdir, "diff.patch"), "w") as f:
            f.write(patch)


    def gen_crypto(self, config_dir, nodelist, client_cnt):
        participants = gen_keys_and_certs(nodelist, DEFAULT_CA_NAME, client_cnt, config_dir)
        print(participants)
        return {
            k: (
                os.path.join(config_dir, f"{k}{TLS_CERT_SUFFIX}"), # tls_cert_path
                os.path.join(config_dir, f"{k}{TLS_PRIVKEY_SUFFIX}"), # tls_key_path
                os.path.join(config_dir, f"{DEFAULT_CA_NAME}{ROOT_CERT_SUFFIX}"), # tls_root_ca_cert_path
                os.path.join(config_dir, PUB_KEYLIST_NAME), # allowed_keylist_path
                os.path.join(config_dir, f"{k}{SIGN_PRIVKEY_SUFFIX}"), # signing_priv_key_path
            ) for k in participants
        }


    def generate_configs(self, deployment: Deployment, config_dir, log_dir):
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
        elif self.node_distribution == "tdx_only":
            vms = deployment.get_nodes_with_tee("tdx")
        elif self.node_distribution == "nontee_only":
            vms = deployment.get_nodes_with_tee("nontee")
        else:
            vms = deployment.get_wan_setup(self.node_distribution)

        self.binary_mapping = defaultdict(list)

        for node_num in range(1, self.num_nodes+1):
            port = deployment.node_port_base + node_num
            listen_addr = f"0.0.0.0:{port}"
            name = f"node{node_num}"
            domain = f"{name}.pft.org"

            _vm = vms[rr_cnt % len(vms)]
            self.binary_mapping[_vm].append(name)

            private_ip = _vm.private_ip
            rr_cnt += 1
            connect_addr = f"{private_ip}:{port}"

            nodelist.append(name[:])
            nodes[name] = {
                "addr": connect_addr,
                "domain": domain
            }

            node_list_for_crypto[name] = (connect_addr, domain)

            config = deepcopy(self.base_node_config)
            config["net_config"]["name"] = name
            config["net_config"]["addr"] = listen_addr
            #TODO(natacha): Remove hardcoded dependency on /data/
            config["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"{log_dir}/{name}-db"
            #config["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"/data/{name}-db"


            node_configs[name] = config

        if self.client_region == -1:
            client_vms = deployment.get_all_client_vms()
        else:
            client_vms = deployment.get_all_client_vms_in_region(self.client_region)


        self.num_clients_per_vm = [self.num_clients // len(client_vms) for _ in range(len(client_vms))]
        self.num_clients_per_vm[-1] += (self.num_clients - sum(self.num_clients_per_vm))

        crypto_info = self.gen_crypto(config_dir, node_list_for_crypto, len(client_vms))


        for k, v in node_configs.items():
            tls_cert_path, tls_key_path, tls_root_ca_cert_path,\
            allowed_keylist_path, signing_priv_key_path = crypto_info[k]

            v["net_config"]["nodes"] = deepcopy(nodes)
            v["consensus_config"]["node_list"] = nodelist[:]
            v["consensus_config"]["learner_list"] = []
            v["net_config"]["tls_cert_path"] = tls_cert_path
            v["net_config"]["tls_key_path"] = tls_key_path
            v["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
            v["rpc_config"]["allowed_keylist_path"] = allowed_keylist_path
            v["rpc_config"]["signing_priv_key_path"] = signing_priv_key_path

            # Only simulate Byzantine behavior in node1.
            if "evil_config" in v and v["evil_config"]["simulate_byzantine_behavior"] and k != "node1":
                v["evil_config"]["simulate_byzantine_behavior"] = False
                v["evil_config"]["byzantine_start_block"] = 0

            with open(os.path.join(config_dir, f"{k}_config.json"), "w") as f:
                json.dump(v, f, indent=4)

        for client_num in range(len(client_vms)):
            config = deepcopy(self.base_client_config)
            client = "client" + str(client_num + 1)
            config["net_config"]["name"] = client
            config["net_config"]["nodes"] = deepcopy(nodes)

            tls_cert_path, tls_key_path, tls_root_ca_cert_path,\
            allowed_keylist_path, signing_priv_key_path = crypto_info[client]

            config["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
            config["rpc_config"] = {"signing_priv_key_path": signing_priv_key_path}

            config["workload_config"]["num_clients"] = self.num_clients_per_vm[client_num]
            config["workload_config"]["duration"] = self.duration

            self.binary_mapping[client_vms[client_num]].append(client)

            with open(os.path.join(config_dir, f"{client}_config.json"), "w") as f:
                json.dump(config, f, indent=4)

        # Controller config
        config = deepcopy(self.base_client_config)
        name = "controller"
        config["net_config"]["name"] = name
        config["net_config"]["nodes"] = deepcopy(nodes)

        tls_cert_path, tls_key_path, tls_root_ca_cert_path,\
        allowed_keylist_path, signing_priv_key_path = crypto_info[name]

        config["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
        config["rpc_config"] = {"signing_priv_key_path": signing_priv_key_path}

        config["workload_config"]["num_clients"] = 1
        config["workload_config"]["duration"] = self.duration

        with open(os.path.join(config_dir, f"{name}_config.json"), "w") as f:
            json.dump(config, f, indent=4)

        if self.controller_must_run:
            self.binary_mapping[client_vms[0]].append(name)





    def copy_back_build_files(self):
        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        TARGET_BINARIES = ["client", "server", "net-perf"]

        # Copy the target/release to build directory
        for bin in TARGET_BINARIES:
            copy_file_from_remote_public_ip(f"{remote_repo}/target/release/{bin}", os.path.join(self.local_workdir, "build", bin), self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)



    def remote_build(self):
        # If the local build dir is not empty, we assume the build has already been done
        if len(os.listdir(os.path.join(self.local_workdir, "build"))) > 0:
            print("Skipping build for experiment", self.name)
            return

        with open(os.path.join(self.local_workdir, "git_hash.txt"), "r") as f:
            git_hash = f.read().strip()

        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        cmds = [
            f"git clone {self.project_home} {remote_repo}"
        ]
        print(cmds)
        try:
            run_remote_public_ip(cmds, self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)
        except Exception as e:
            print("Failed to clone repo. It may already exist. Continuing...")

        cmds = [
            f"cd {remote_repo} && git checkout main",       # Move out of DETACHED HEAD state
            f"cd {remote_repo} && git fetch --all --recurse-submodules && git pull --all --recurse-submodules",
        ]
        try:
            run_remote_public_ip(cmds, self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)
        except Exception as e:
            print("Failed to pull repo. Continuing...")


        # Copy the diff patch to the remote
        copy_remote_public_ip(os.path.join(self.local_workdir, "diff.patch"), f"{remote_repo}/diff.patch", self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)

        # Setup git env
        cmd = []

        # Checkout the git hash and apply the diff
        cmds = [
            f"cd {remote_repo} && git reset --hard",
            f"cd {remote_repo} && git checkout {git_hash}",
            f"cd {remote_repo} && git submodule update --init --recursive",
            f"cd {remote_repo} && git apply --allow-empty --reject --whitespace=fix diff.patch",
        ]

        # Then build
        cmds.append(
            f"cd {remote_repo} && {self.build_command}"
        )

        try:
            run_remote_public_ip(cmds, self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=False)
        except Exception as e:
            print("Failed to build:", e)
            print("\033[91mTry committing the changes and pushing to the remote repo\033[0m")
            exit(1)
        sleep(0.5)

        self.copy_back_build_files()



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
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin:
                        binary_name = "server"
                    elif "client" in bin:
                        binary_name = "client"
                    elif "controller" in bin:
                        binary_name = "controller"

                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.private_ip} 'RUST_BACKTRACE=full  {self.remote_workdir}/build/{binary_name} {self.remote_workdir}/configs/{bin}_config.json > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err' &
PID="$PID $!"
"""

            _script += f"""
# Sleep for the duration of the experiment
sleep {self.duration}

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
                        binary_name = "server"
                    elif "client" in bin:
                        binary_name = "client"
                    elif "controller" in bin:
                        binary_name = "controller"

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
"""

            _script += f"""
sleep 30
"""

            # pkill -9 -c server also kills tmux-server. So we can't run a server on the dev VM.
            # It kills the tmux session and the experiment. And we end up with a lot of orphaned processes.

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")


    def bins_already_exist(self):
        TARGET_BINARIES = ["client", "controller", "server", "net-perf"]
        remote_repo = f"/home/{self.dev_ssh_user}/repo"

        res = run_remote_public_ip([
            f"ls {remote_repo}/target/release"
        ], self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True)

        return any([bin in res[0] for bin in TARGET_BINARIES])


    def get_build_details(self) -> Tuple[str, str]:
        '''
        Get the git hash and the diff patch and build command
        '''
        with open(os.path.join(self.local_workdir, "git_hash.txt"), "r") as f:
            git_hash = f.read().strip()
        with open(os.path.join(self.local_workdir, "diff.patch"), "r") as f:
            diff = f.read().strip()

        return git_hash, diff, self.build_command


    def deploy(self, deployment: Deployment, last_git_hash="", last_git_diff="", last_build_command=""):
        '''
        Generate necessary config
        Git checkout and apply diff, then build (if necessary), remotely.
        Copy back the binaries.
        '''
        if self.done():
            print("Experiment already done")
            return

        # Create the necessary directories
        workdir = os.path.join(deployment.workdir, "experiments", self.name)
        build_dir, config_dir, log_dir_base, log_dirs = self.create_directory(workdir)
        self.tag_source(workdir)
        self.tag_experiment(workdir)
        self.dev_vm = deployment.dev_vm
        self.dev_ssh_user = deployment.ssh_user
        self.dev_ssh_key = deployment.ssh_key
        self.generate_configs(deployment, config_dir, log_dir_base)
        self.set_local_workdir(workdir)

        # Hard dependency on Linux style paths
        self.remote_workdir = f"/home/{deployment.ssh_user}/{deployment.workdir}/experiments/{self.name}"

        # Clone repo in remote and build
        git_hash, git_diff, build_cmd = self.get_build_details()
        use_cached_build = git_hash == last_git_hash and git_diff == last_git_diff and build_cmd == last_build_command
        if not(use_cached_build and self.bins_already_exist()):
            self.remote_build()
        else:
            self.copy_back_build_files()

        # Call order: generate_configs, remote_build, generate_arbiter_script
        # DO NOT CHANGE THIS ORDER. Subclasses may depend on this order.

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



