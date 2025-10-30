from collections import defaultdict
from copy import deepcopy
import json
from experiments import PirateShipExperiment, copy_file_from_remote_public_ip
from deployment import Deployment
import os
import subprocess
from typing import List

from ssh_utils import run_remote_public_ip, copy_remote_public_ip


class AppExperiment(PirateShipExperiment):
    def copy_back_build_files(self):
        remote_repo = f"/home/{self.dev_ssh_user}/repo"
        TARGET_BINARIES = [self.workload]

        # Copy the target/release to build directory
        for bin in TARGET_BINARIES:
            copy_file_from_remote_public_ip(f"{remote_repo}/target/release/{bin}", os.path.join(self.local_workdir, "build", bin), self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)

        remote_script_dir = f"{remote_repo}/scripts_v2/loadtest"
        TARGET_SCRIPTS = ["load.py", "locustfile.py", "docker-compose.yml", "toggle.py", "shamir.py", "zipfian.py"]

        # Copy the scripts to build directory
        for script in TARGET_SCRIPTS:
            copy_file_from_remote_public_ip(f"{remote_script_dir}/{script}", os.path.join(self.local_workdir, "build", script), self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)


    def bins_already_exist(self):
        TARGET_BINARIES = [self.workload]
        remote_repo = f"/home/{self.dev_ssh_user}/repo"

        remote_script_dir = f"{remote_repo}/scripts_v2/loadtest"
        TARGET_SCRIPTS = ["load.py", "locustfile.py", "docker-compose.yml", "toggle.py", "shamir.py", "zipfian.py"]


        res1 = run_remote_public_ip([
            f"find {remote_script_dir}"
        ], self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True)

        res2 = run_remote_public_ip([
            f"ls {remote_repo}/target/release"
        ], self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True)

        return all([bin in res2[0] for bin in TARGET_BINARIES]) and all([script in res1[0] for script in TARGET_SCRIPTS])
    

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
        self.getRequestHosts = []

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
            if node_num == 1:
                self.probableLeader = f"http://{private_ip}:{port + 1000}"
            self.getRequestHosts.append(f"http://{private_ip}:{port + 1000}") # This +1000 is hardcoded in contrib/kms/main.rs

            node_list_for_crypto[name] = (connect_addr, domain)

            config = deepcopy(self.base_node_config)
            config["net_config"]["name"] = name
            config["net_config"]["addr"] = listen_addr
            config["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"{log_dir}/{name}-db"


            node_configs[name] = config

        if self.client_region == -1:
            client_vms = deployment.get_all_client_vms()
        else:
            client_vms = deployment.get_all_client_vms_in_region(self.client_region)

        self.client_vms = client_vms[:]

        crypto_info = self.gen_crypto(config_dir, node_list_for_crypto, 0)
        

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

        self.getDistribution = self.base_client_config.get("getDistribution", 50)
        self.workers_per_client = self.base_client_config.get("workers_per_client", 1)
        self.total_client_vms = len(client_vms)
        self.total_worker_processes = self.total_client_vms * self.workers_per_client
        self.locust_master = self.client_vms[0]
        self.workload = self.base_client_config.get("workload", "kms")
        if self.workload == "smallbank":
            self.payment_threshold = str(self.base_client_config.get("payment_threshold", 1000))
        else:
            self.payment_threshold = ""

        self.total_machines = self.workers_per_client * self.total_client_vms

        users_per_clients = [self.num_clients // self.total_machines] * self.total_machines
        users_per_clients[-1] += self.num_clients - sum(users_per_clients)
        self.users_per_clients = users_per_clients


        for client_vm_num in range(len(client_vms)):
            for worker_num in range(self.workers_per_client):
                machineId = client_vm_num * self.workers_per_client + worker_num
                self.binary_mapping[client_vms[client_vm_num]].append(f"client{machineId}")

        self.binary_mapping[self.locust_master].append("loader")
        self.binary_mapping[self.locust_master].append("master")

        # Install pip and the dependencies in client vms.
        for vm in self.client_vms:
            run_remote_public_ip([
                f"sudo apt-get update",
                f"sudo apt-get install -y python3-pip",
                f"pip3 install locust",
                f"pip3 install locust-plugins[dashboards]",
                f"pip3 install aiohttp",
                f"pip3 install requests",
                f"pip3 install numpy",
            ], self.dev_ssh_user, self.dev_ssh_key, vm, hide=False)



        
    def generate_arbiter_script(self):

        script_base = f"""#!/bin/bash
set -e
set -o xtrace

# This script is generated by the experiment pipeline. DO NOT EDIT.
SSH_CMD="ssh -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"
SCP_CMD="scp -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"


# Stop old Grafana in dev vm.
$SSH_CMD {self.dev_ssh_user}@{self.dev_vm.public_ip} 'docker compose -f {self.remote_workdir}/build/docker-compose.yml down -v' || true

# Start up Grafana in dev vm.
$SSH_CMD {self.dev_ssh_user}@{self.dev_vm.public_ip} 'docker compose -f {self.remote_workdir}/build/docker-compose.yml up -d' || true

# SSH into each VM and run the binaries
"""
        # Plan the binaries to run
        for repeat_num in range(self.repeats):
            print("Running repeat", repeat_num)
            _script = script_base[:]
            for vm, bin_list in self.binary_mapping.items():
                # Boot up the nodes first
                for bin in bin_list:
                    if "node" in bin:
                        binary_name = self.workload
                    else:
                        continue

                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'RUST_BACKTRACE=full {self.remote_workdir}/build/{binary_name} {self.remote_workdir}/configs/{bin}_config.json {self.payment_threshold} > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err' &
PID="$PID $!"
"""
            _script += f"""
sleep 1
"""
            # Find where node1 is running. This is most probably the PirateShip leader.
            host = self.probableLeader
            
            # Run the load phase
            # Assume a throughput of 3000 rps (this is <0.01x of the max throughput of the system)
            load_phase_seconds = 5 + self.num_clients // 3000 # 5s min
            _script += f"""
# Run the load phase.
$SSH_CMD {self.dev_ssh_user}@{self.locust_master.public_ip} 'python3 {self.remote_workdir}/build/load.py {host} {self.num_clients} {self.total_client_vms} {self.workers_per_client} {self.workload} > {self.remote_workdir}/logs/{repeat_num}/loader.log 2> {self.remote_workdir}/logs/{repeat_num}/loader.err' &
PID="$PID $!"
sleep {load_phase_seconds}
"""
            # Run the locust master

            
            config_users = {
                "user_class_name": "TestUser",
                "getDistribution": self.getDistribution,
                "getRequestHosts": self.getRequestHosts,
                "workload": self.workload,
            }
            config_users_str = "'\"'\"'" + json.dumps(config_users) + "'\"'\"'" # Bash magic! https://stackoverflow.com/questions/1250079/how-to-escape-single-quotes-within-single-quoted-strings
            _script += f"""
# Run phase start

# Run the locust master
$SSH_CMD {self.dev_ssh_user}@{self.locust_master.public_ip} '/home/pftadmin/.local/bin/locust -f {self.remote_workdir}/build/locustfile.py --timescale --headless --master --users {self.num_clients} --spawn-rate {int(self.total_worker_processes * 100)} --host {host} --run-time {self.duration}s --config-users {config_users_str} --pguser postgres --pgpassword password > {self.remote_workdir}/logs/{repeat_num}/locust-master.log 2> {self.remote_workdir}/logs/{repeat_num}/locust-master.err' &
PID="$PID $!"
sleep 1

# Run all workers
"""
            for vm, bin_list in self.binary_mapping.items():
                # Boot up the nodes first
                for bin in bin_list:
                    if "client" in bin:
                        machineId = int(bin[6:])
                        config_users["machineId"] = machineId
                        config_users["max_users"] = self.users_per_clients[machineId]
                        config_users_str = "'\"'\"'" + json.dumps(config_users) + "'\"'\"'"
                    else:
                        continue

                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} '/home/pftadmin/.local/bin/locust -f {self.remote_workdir}/build/locustfile.py --timescale --headless --worker --master-host {self.locust_master.private_ip} --processes 1 --run-time {self.duration}s --config-users {config_users_str} --pguser postgres --pgpassword password --pghost {self.locust_master.private_ip} --pgport 5432 > {self.remote_workdir}/logs/{repeat_num}/{bin}.log 2> {self.remote_workdir}/logs/{repeat_num}/{bin}.err' &
PID="$PID $!"
"""
            
            # Run the toggle program in the locust master
            if self.duration > 200:
                toggle_ramp_up = 120
                toggle_duration = 60
            else:
                toggle_ramp_up = self.duration // 3
                toggle_duration = self.duration // 3

            _script += f"""
# Run the toggle program
$SSH_CMD {self.dev_ssh_user}@{self.locust_master.public_ip} 'python3 {self.remote_workdir}/build/toggle.py {host} {toggle_ramp_up} {toggle_duration} > {self.remote_workdir}/logs/{repeat_num}/toggle.log 2> {self.remote_workdir}/logs/{repeat_num}/toggle.err' &
PID="$PID $!"
"""
            
            
                    
            _script += f"""
# Sleep for the duration of the experiment
sleep {self.duration + 2}

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
                        binary_name = self.workload
                    else:
                        binary_name = "locust"
                
                # Copy the logs back
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -2 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -15 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -9 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'rm -rf {self.remote_workdir}/logs/*db' || true
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.log {self.remote_workdir}/logs/{repeat_num}/{bin}.log || true
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/{bin}.err {self.remote_workdir}/logs/{repeat_num}/{bin}.err || true
"""
                    
            _script += f"""
sleep 10

# We keep the Grafana container running until the next experiment.
"""
                    
            # pkill -9 -c server also kills tmux-server. So we can't run a server on the dev VM.
            # It kills the tmux session and the experiment. And we end up with a lot of orphaned processes.

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")

