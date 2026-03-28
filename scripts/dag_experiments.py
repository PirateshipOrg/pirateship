from dataclasses import dataclass, field
from deployment import Deployment
from experiments import Experiment, DEFAULT_CA_NAME
from ssh_utils import copy_file_from_remote_public_ip
from crypto import PUB_KEYLIST_NAME
from copy import deepcopy
from collections import defaultdict
import json
import os


@dataclass
class PirateshipDagExperiment(Experiment):
    experiment_type: str = field(default="dag", init=False, repr=True)

    def copy_back_build_files(self):
        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        TARGET_BINARIES = ["client", "controller", "server", "worker", "net-perf"]
        for bin in TARGET_BINARIES:
            copy_file_from_remote_public_ip(
                f"{remote_repo}/target/release/{bin}",
                os.path.join(self.local_workdir, "build", bin),
                self.dev_ssh_user, self.dev_ssh_key, self.dev_vm,
            )

    def bins_already_exist(self):
        TARGET_BINARIES = ["client", "controller", "server", "worker", "net-perf"]
        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        from ssh_utils import run_remote_public_ip
        res = run_remote_public_ip(
            [f"ls {remote_repo}/target/release"],
            self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True,
        )
        return any([bin in res[0] for bin in TARGET_BINARIES])

    def generate_configs(self, deployment: Deployment, config_dir, log_dir):
        if len(os.listdir(config_dir)) > 0:
            print("Skipping config generation for experiment", self.name)
            return

        rr_cnt = 0
        nodelist = []
        nodes = {}
        node_configs = {}
        node_list_for_crypto = {}
        node_vm_map = {}  # node name -> VM

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

        for node_num in range(1, self.num_nodes + 1):
            port = deployment.node_port_base + node_num
            name = f"node{node_num}"
            domain = f"{name}.pft.org"

            _vm = vms[rr_cnt % len(vms)]
            self.binary_mapping[_vm].append(name)
            node_vm_map[name] = _vm

            private_ip = _vm.private_ip
            rr_cnt += 1
            connect_addr = f"{private_ip}:{port}"

            nodelist.append(name[:])
            nodes[name] = {"addr": connect_addr, "domain": domain}
            node_list_for_crypto[name] = (connect_addr, domain)

            config = deepcopy(self.base_node_config)
            config["net_config"]["name"] = name
            config["net_config"]["addr"] = f"0.0.0.0:{port}"
            config["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"/data/{name}-db"
            node_configs[name] = config

        # Build worker address map — workers share their parent node's VM and crypto
        worker_names = [f"node{i}_worker" for i in range(1, self.num_nodes + 1)]
        worker_nodes_map = {}
        worker_configs = {}

        for node_num in range(1, self.num_nodes + 1):
            node_name = f"node{node_num}"
            worker_name = f"{node_name}_worker"
            worker_port = deployment.node_port_base + node_num + 1111
            domain = f"{node_name}.pft.org"

            _vm = node_vm_map[node_name]  # same VM as parent node
            private_ip = _vm.private_ip
            worker_connect_addr = f"{private_ip}:{worker_port}"

            worker_nodes_map[worker_name] = {"addr": worker_connect_addr, "domain": domain}
            self.binary_mapping[_vm].append(worker_name)

            config = deepcopy(self.base_node_config)
            config["net_config"]["name"] = worker_name
            config["net_config"]["addr"] = f"0.0.0.0:{worker_port}"
            config["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"/data/{worker_name}-db"
            worker_configs[worker_name] = config

        all_nodes_map = {}
        all_nodes_map.update(nodes)
        all_nodes_map.update(worker_nodes_map)

        if self.client_region == -1:
            client_vms = deployment.get_all_client_vms()
        else:
            client_vms = deployment.get_all_client_vms_in_region(self.client_region)

        # Generate crypto for nodes only; workers reuse parent node's keys
        crypto_info = self.gen_crypto(config_dir, node_list_for_crypto, len(client_vms))

        # Write node configs
        for k, v in node_configs.items():
            tls_cert_path, tls_key_path, tls_root_ca_cert_path, \
                allowed_keylist_path, signing_priv_key_path = crypto_info[k]

            v["net_config"]["nodes"] = deepcopy(all_nodes_map)
            v["consensus_config"]["node_list"] = nodelist[:]
            v["consensus_config"]["learner_list"] = []
            v["net_config"]["tls_cert_path"] = tls_cert_path
            v["net_config"]["tls_key_path"] = tls_key_path
            v["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
            v["rpc_config"]["allowed_keylist_path"] = allowed_keylist_path
            v["rpc_config"]["signing_priv_key_path"] = signing_priv_key_path

            if "evil_config" in v and v["evil_config"]["simulate_byzantine_behavior"] and k != "node1":
                v["evil_config"]["simulate_byzantine_behavior"] = False
                v["evil_config"]["byzantine_start_block"] = 0

            with open(os.path.join(config_dir, f"{k}_config.json"), "w") as f:
                json.dump(v, f, indent=4)

        # Append worker entries to keylist — workers share parent node's signing key
        keylist_file = os.path.join(config_dir, PUB_KEYLIST_NAME)
        with open(keylist_file, "r") as f:
            lines = f.read().strip().split("\n")
        node_pub_keys = {}
        for line in lines:
            parts = line.split(" ", 1)
            if len(parts) == 2:
                node_pub_keys[parts[0]] = parts[1]
        with open(keylist_file, "a") as f:
            for node_name in nodelist:
                worker_name = f"{node_name}_worker"
                if node_name in node_pub_keys:
                    f.write(f"{worker_name} {node_pub_keys[node_name]}\n")

        # Write worker configs (reuse parent node's crypto material)
        for node_num in range(1, self.num_nodes + 1):
            node_name = f"node{node_num}"
            worker_name = f"{node_name}_worker"
            tls_cert_path, tls_key_path, tls_root_ca_cert_path, \
                allowed_keylist_path, signing_priv_key_path = crypto_info[node_name]

            v = worker_configs[worker_name]
            v["net_config"]["nodes"] = deepcopy(all_nodes_map)
            v["consensus_config"]["node_list"] = nodelist[:]
            v["consensus_config"]["learner_list"] = worker_names[:]
            v["net_config"]["tls_cert_path"] = tls_cert_path
            v["net_config"]["tls_key_path"] = tls_key_path
            v["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
            v["rpc_config"]["allowed_keylist_path"] = allowed_keylist_path
            v["rpc_config"]["signing_priv_key_path"] = signing_priv_key_path

            with open(os.path.join(config_dir, f"{worker_name}_config.json"), "w") as f:
                json.dump(v, f, indent=4)

        # Client configs: each client connects only to its corresponding worker
        num_clients_per_vm = [self.num_clients // len(client_vms) for _ in range(len(client_vms))]
        num_clients_per_vm[-1] += (self.num_clients - sum(num_clients_per_vm))

        for client_num in range(len(client_vms)):
            config = deepcopy(self.base_client_config)
            client = f"client{client_num + 1}"
            worker_name = f"node{(client_num % self.num_nodes) + 1}_worker"
            config["net_config"]["name"] = client
            config["net_config"]["nodes"] = {worker_name: worker_nodes_map[worker_name]}

            tls_cert_path, tls_key_path, tls_root_ca_cert_path, \
                allowed_keylist_path, signing_priv_key_path = crypto_info[client]

            config["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
            config["rpc_config"] = {"signing_priv_key_path": signing_priv_key_path}
            config["workload_config"]["num_clients"] = num_clients_per_vm[client_num]
            config["workload_config"]["duration"] = self.duration

            self.binary_mapping[client_vms[client_num]].append(client)

            with open(os.path.join(config_dir, f"{client}_config.json"), "w") as f:
                json.dump(config, f, indent=4)

        # Controller config
        config = deepcopy(self.base_client_config)
        name = "controller"
        config["net_config"]["name"] = name
        config["net_config"]["nodes"] = deepcopy(all_nodes_map)

        tls_cert_path, tls_key_path, tls_root_ca_cert_path, \
            allowed_keylist_path, signing_priv_key_path = crypto_info[name]

        config["net_config"]["tls_root_ca_cert_path"] = tls_root_ca_cert_path
        config["rpc_config"] = {"signing_priv_key_path": signing_priv_key_path}
        config["workload_config"]["num_clients"] = 1
        config["workload_config"]["duration"] = self.duration

        with open(os.path.join(config_dir, f"{name}_config.json"), "w") as f:
            json.dump(config, f, indent=4)

        if self.controller_must_run:
            self.binary_mapping[client_vms[0]].append(name)

    def generate_arbiter_script(self):
        script_base = f"""#!/bin/bash
set -e
set -o xtrace

# This script is generated by the experiment pipeline. DO NOT EDIT.
SSH_CMD="ssh -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"
SCP_CMD="scp -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"

# SSH into each VM and run the binaries
"""
        for repeat_num in range(self.repeats):
            print("Running repeat", repeat_num)
            _script = script_base[:]

            def _binary_name(bin):
                if bin.endswith("_worker"):
                    return "worker"
                elif "node" in bin:
                    return "server"
                elif "client" in bin:
                    return "client"
                elif "controller" in bin:
                    return "controller"

            def _launch(vm, bin):
                binary_name = _binary_name(bin)
                return f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'RUST_BACKTRACE=full {self.remote_workdir}/build/{binary_name} {self.remote_workdir}/configs/{bin}_config.json > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err' &
PID="$PID $!"
"""

            # Pass 1: launch servers first
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin and not bin.endswith("_worker"):
                        _script += _launch(vm, bin)

            # Pass 2: launch workers
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if bin.endswith("_worker"):
                        _script += _launch(vm, bin)

            # Pass 3: launch clients (one per worker target) and controller
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" not in bin and not bin.endswith("_worker"):
                        if "client" in bin:
                            for node_num in range(1, self.num_nodes + 1):
                                worker_name = f"node{node_num}_worker"
                                _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'RUST_BACKTRACE=full {self.remote_workdir}/build/client {self.remote_workdir}/configs/{bin}_config.json --target {worker_name} > {self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.err' &
PID="$PID $!"
"""
                        else:
                            _script += _launch(vm, bin)

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
                    binary_name = _binary_name(bin)
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -2 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -15 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -9 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'rm -rf /data/*' || true
"""
                    if "client" in bin and "node" not in bin and not bin.endswith("_worker"):
                        for node_num in range(1, self.num_nodes + 1):
                            worker_name = f"node{node_num}_worker"
                            _script += f"""
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.log {self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.log || true
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.err {self.remote_workdir}/logs/{repeat_num}/{bin}_{worker_name}.err || true
"""
                    else:
                        _script += f"""
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.log {self.remote_workdir}/logs/{repeat_num}/{bin}.log || true
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.err {self.remote_workdir}/logs/{repeat_num}/{bin}.err || true
"""

            _script += f"""
sleep 60
"""

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")
