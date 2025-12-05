from copy import deepcopy
import os
from pprint import pprint
import pickle
import json
import time
from time import sleep
import tqdm
import re
from ssh_utils import *


class Deployment:
    '''
    By default it is assumed that the deployment is done using Azure Terraform.
    Nodes are named as follows:
        nodepool_vmX_{tdx|sev|nontee}_locY_idZ
        clientpool_vmX_locY_idZ
    Override in a subclass the deployment-specific methods to change how nodes/containers are deployed.
    This deployment is specific to "SSH-able" deployments.
    Not suited for Docker/K8s deployments.

    For other SSH-able deployments, override the following methods:
        - deploy
        - teardown
        - __init__
    '''
    def parse_custom_layouts(self):
        """
        Custom layout toml format:

        [[deployment_config.custom_layout]]
        name = "layout1"

        # Order of regions will come from terraform
        nodes_per_region = [1, 0, 0, 1]
        """
        self.custom_layouts = {}
        if not("custom_layout" in self.raw_config):
            return
        
        custom_layouts = self.raw_config["custom_layout"]
        assert isinstance(custom_layouts, list)


        for layout in custom_layouts:
            name = layout["name"]
            nodes_per_region = layout["nodes_per_region"]
            # clients_per_region = layout["clients_per_region"]
            assert isinstance(nodes_per_region, list)
            # assert isinstance(clients_per_region, list)

            self.custom_layouts[name] = {
                "nodes_per_region": nodes_per_region,
                # "clients_per_region": clients_per_region
            }


    def __init__(self, config, workdir):
        self.mode = config["mode"]
        self.nodelist = []
        self.workdir = workdir
        self.raw_config = deepcopy(config)
        first_client = False
        if self.mode == "manual":
            self.populate_nodelist()

        self.ssh_user = config["ssh_user"]

        if os.path.isabs(config["ssh_key"]):
            self.ssh_key = config["ssh_key"]
        else:
            self.ssh_key = os.path.join(workdir, "deployment", config["ssh_key"])
        self.node_port_base = int(config["node_port_base"])

        self.parse_custom_layouts()

    def find_azure_tf_dir(self):
        '''
        Find where the terraform files are located.
        The search paths are hardcoded and are relative to the root of the repo.
        '''
        search_paths = [
            os.path.join("deployment", "azure-tf"),
            os.path.join("scripts_v2", "deployment", "azure-tf"),
        ]

        found_path = None
        for path in search_paths:
            if os.path.exists(path):
                found_path = os.path.abspath(path)
                break

        if found_path is None:
            raise FileNotFoundError("Azure Terraform directory not found")
        else:
            print(f"Found Azure Terraform directory at {found_path}")

        return found_path
    
    def prepare_dev_vm(self):
        '''
        Find where __prepare-dev-env.sh and ideal_bashrc are located.
        Copy them to the dev VM and run __prepare-dev-env.sh
        Search paths are hardcoded and are relative to the root of the repo.
        '''
        if self.dev_vm is None:
            raise ValueError("No dev VM found")
        
        # Find __prepare_dev_env.sh and ideal_bashrc
        search_paths = [
            "deployment",
            os.path.join("scripts_v2", "deployment"),
            os.path.join("deployment", "azure-tf"),
            os.path.join("scripts_v2", "deployment", "azure-tf"),
        ]

        for path in search_paths:
            if os.path.exists(os.path.join(path, "__prepare-dev-env.sh")) and os.path.exists(os.path.join(path, "ideal_bashrc")):
                found_path = os.path.abspath(path)
                break
        else:
            raise FileNotFoundError("Dev VM setup scripts not found")
        
        # Copy the scripts to the dev VM
        copy_remote_public_ip(os.path.join(found_path, "__prepare-dev-env.sh"), f"/home/{self.ssh_user}/__prepare-dev-env.sh", self.ssh_user, self.ssh_key, self.dev_vm)
        copy_remote_public_ip(os.path.join(found_path, "ideal_bashrc"), f"/home/{self.ssh_user}/ideal_bashrc", self.ssh_user, self.ssh_key, self.dev_vm)

        # Run the scripts
        run_remote_public_ip([
            "chmod +x __prepare-dev-env.sh",
            "./__prepare-dev-env.sh"
        ], self.ssh_user, self.ssh_key, self.dev_vm, hide=False)

        
    def get_ssh_key(self):
        tf_output_dir = os.path.abspath(os.path.join(self.workdir, "deployment"))
        tfstate_path = os.path.join(tf_output_dir, "terraform.tfstate")
        private_key = run_local([
            f"terraform output -state={tfstate_path} --raw cluster_private_key"
        ])[0]
        with open(self.ssh_key, "w") as f:
            f.write(private_key)

        run_local([
            "chmod 600 " + self.ssh_key
        ])


    def deploy(self):
        run_local([
            f"mkdir -p {self.workdir}",
            f"mkdir -p {self.workdir}/deployment",
        ])
        with open(os.path.join(self.workdir, "deployment", "deployment.txt"), "w") as f:
            pprint(self, f)

        if self.mode == "manual":
            # Manual must mean there is a nodelist specified in the toml file.
            # There is no need to deploy.
            # Save myself
            with open(os.path.join(self.workdir, "deployment", "deployment.pkl"), "wb") as f:
                pickle.dump(self, f)

            # Rewrite deployment.txt
            with open(os.path.join(self.workdir, "deployment", "deployment.txt"), "w") as f:
                pprint(self, f)
            return
        
        # Terraform deploy

        # Find the azure-tf directory relative to where the script is being called from
        found_path = self.find_azure_tf_dir()

        if found_path is None:
            raise FileNotFoundError("Azure Terraform directory not found")
        else:
            print(f"Found Azure Terraform directory at {found_path}")

        # There must exist a var-file in azure-tf/setups for the deployment mode
        var_file = os.path.join(found_path, "setups", f"{self.mode}.tfvars")
        if not os.path.exists(var_file):
            raise FileNotFoundError(f"Var file for deployment mode {self.mode} not found")

        tf_output_dir = os.path.abspath(os.path.join(self.workdir, "deployment"))
        plan_path = os.path.join(tf_output_dir, "main.tfplan")
        tfstate_path = os.path.join(tf_output_dir, "terraform.tfstate")

        # Does tfstate already exist?
        tfstate_exists = os.path.exists(tfstate_path)

        # Plan
        run_local([
            f"terraform -chdir={found_path} init",
            # f"terraform -chdir={found_path} refresh -no-color -var-file=\"{var_file}\" -var=\"username={self.ssh_user}\" -out={plan_path} -state={tfstate_path}" if tfstate_exists else "echo 'New plan needed'",
            f"terraform -chdir={found_path} plan -no-color -var-file=\"{var_file}\" -var=\"username={self.ssh_user}\" -out={plan_path} -state={tfstate_path} > {tf_output_dir}/plan.log 2>&1",
        ])

        # Apply
        run_local([
            f"terraform -chdir={found_path} apply -no-color -auto-approve -state={tfstate_path} {plan_path} > {tf_output_dir}/apply.log 2>&1",
        ])

        # Populate nodelist
        self.populate_nodelist()

        # Store the SSH key
        self.get_ssh_key()

        # Install dev dependencies on dev VM
        self.prepare_dev_vm()

        # Save myself
        with open(os.path.join(self.workdir, "deployment", "deployment.pkl"), "wb") as f:
            pickle.dump(self, f)

        # Rewrite deployment.txt
        with open(os.path.join(self.workdir, "deployment", "deployment.txt"), "w") as f:
            pprint(self, f)


    def copy_all_to_remote_public_ip(self, only_to_dev_vm=False):
        # Use rsync to copy the entire directory to all nodes
        if not only_to_dev_vm:
            nodelist = self.nodelist[:]
        else:
            nodelist = [self.dev_vm]
        print(f"Copying {self.workdir} to {len(nodelist)} nodes")

        for node in nodelist:
            run_remote_public_ip([
                f"mkdir -p {self.workdir}",
            ], self.ssh_user, self.ssh_key, node)

        res = run_local([
            f"rsync -avz -e 'ssh -o StrictHostKeyChecking=no -i {self.ssh_key}' {self.workdir}/* {self.ssh_user}@{node.public_ip}:~/{self.workdir}/"
            for node in nodelist
        ], hide=True, asynchronous=True)

        for (i, node) in enumerate(nodelist):
            print("Copied to", node.name, "Output (truncated):\n", "\n".join(res[i].split("\n")[-2:]))

    def sync_local_to_dev_vm(self):
        # Use rsync to copy workdir from dev VM to local
        run_local([
            f"rsync -avz -e 'ssh -o StrictHostKeyChecking=no -i {self.ssh_key}' {self.ssh_user}@{self.dev_vm.public_ip}:~/{self.workdir}/* {self.workdir}/"
        ], hide=False)

    def clean_dev_vm(self):
        run_remote_public_ip([
            f"rm -rf {self.workdir}"
        ], self.ssh_user, self.ssh_key, self.dev_vm)




    def populate_raw_node_list_from_terraform(self):
        found_path = self.find_azure_tf_dir()

        if found_path is None:
            raise FileNotFoundError("Azure Terraform directory not found")
        
        tf_output_dir = os.path.abspath(os.path.join(self.workdir, "deployment"))
        tfstate_path = os.path.join(tf_output_dir, "terraform.tfstate")

        rg_name = run_local([
            f"terraform output -state={tfstate_path} --raw resource_group_name"
        ])[0]

        print("Resource group name:", rg_name)

        # Use az cli to get the public and private IPs of all deployed vms in this resource group
        private_ips, public_ips = run_local([
            r'az vm list-ip-addresses --resource-group ' + rg_name
            + r' --query "[].{Name:virtualMachine.name, IP:virtualMachine.network.privateIpAddresses[0]}" --output json',

            r'az vm list-ip-addresses --resource-group ' + rg_name
            + r' --query "[].{Name:virtualMachine.name, IP:virtualMachine.network.publicIpAddresses[0].ipAddress}" --output json'
        ])

        private_ips = json.loads(private_ips)
        public_ips = json.loads(public_ips)

        vm_names = {vm["Name"] for vm in private_ips}

        node_list = {}
        for name in vm_names:
            private_ip = next(vm["IP"] for vm in private_ips if vm["Name"] == name)
            public_ip = next(vm["IP"] for vm in public_ips if vm["Name"] == name)
            
            if "tdx" in name:
                tee_type = "tdx"
            elif "sev" in name:
                tee_type = "sev"
            else:
                tee_type = "nontee"
            
            if "loc" in name:
                # Find the _locX_ part
                region_id = int(re.findall(r"loc(\d+)", name)[0])
            else:
                region_id = 0

            node_list[name] = {
                "private_ip": private_ip,
                "public_ip": public_ip,
                "tee_type": tee_type,
                "region_id": region_id
            }

        self.raw_config["node_list"] = node_list

        pprint(node_list)


    def populate_nodelist(self):
        if self.mode != "manual":
            self.populate_raw_node_list_from_terraform()
    
        first_client = False
        for name, info in self.raw_config["node_list"].items():
            public_ip = info["public_ip"]
            private_ip = info["private_ip"]
            is_client = name.startswith("client")
            dev_vm = False
            if is_client and not(first_client):
                is_coordinator = True
                first_client = True
                dev_vm = True
            else:
                is_coordinator = False
            if not(is_client):
                tee_type = info["tee_type"]
            else:
                tee_type = "nontee"
            
            if "region_id" in info:
                region_id = int(info["region_id"])
            else:
                region_id = 0

            self.nodelist.append(Node(name, public_ip, private_ip, tee_type, region_id, is_client, is_coordinator))

            if dev_vm:
                self.dev_vm = self.nodelist[-1]
        
        if not(first_client):
            raise ValueError("No client VM")

        
    def teardown(self):
        if self.mode == "manual":
            return
        
        found_path = self.find_azure_tf_dir()
        if found_path is None:
            raise FileNotFoundError("Azure Terraform directory not found")
        else:
            print(f"Found Azure Terraform directory at {found_path}")

        tf_output_dir = os.path.abspath(os.path.join(self.workdir, "deployment"))
        tfstate_path = os.path.join(tf_output_dir, "terraform.tfstate")


        while True:
            try:
                run_local([
                    f"terraform -chdir={found_path} apply -destroy -no-color -auto-approve -state={tfstate_path}",
                ], hide=False)
                break
            except Exception as e:
                print("Error while destroying VMs. Retrying...")
                print(e)

    def __repr__(self):
        s = f"Mode: {self.mode}\n"
        s += f"SSH user: {self.ssh_user}\n"
        s += f"SSH key path: {self.ssh_key}\n"
        s += f"Node port base: {self.node_port_base}\n"
        s += "++++ Nodelist +++++\n"
        for node in self.nodelist:
            s += f"{node}\n"

        s += "++++ Custom layouts +++++\n"
        for name, layout in self.custom_layouts.items():
            s += f"{name}: {layout}\n"

        return s
    
    def get_all_node_vms(self):
        return [
            vm for vm in self.nodelist if "node" in vm.name
        ]
    
    def get_all_client_vms(self):
        return [
            vm for vm in self.nodelist if "client" in vm.name
        ]
    
    def get_all_client_vms_in_region(self, loc: int):
        return [
            vm for vm in self.get_all_client_vms() if vm.region_id == loc
        ]
    
    def get_nodes_with_tee(self, tee):
        return [
            vm for vm in self.get_all_node_vms() if tee in vm.tee_type
        ]
    
    def get_wan_setup(self, layout):
        layout = self.custom_layouts[layout]
        nodes_per_region = layout["nodes_per_region"]
        curr_vms_per_region = [0] * len(nodes_per_region)
        vms = []
        all_nodes = self.get_all_node_vms()
        all_nodes.sort(key=lambda x: (x.region_id, x.tee_type, x.name))
        for node in all_nodes:
            if curr_vms_per_region[node.region_id] < nodes_per_region[node.region_id]:
                vms.append(node)
                curr_vms_per_region[node.region_id] += 1

        return vms

    
    def wait_till_end(self, num_cmds: int):
        status = ""
        total_lines = num_cmds + 2
        with tqdm.tqdm(total=total_lines) as pbar:
            while not("Done" in status):
                sleep(1)
                old_status = len(status.split("\n"))
                try:
                    status = run_remote_public_ip([
                        f"cat status.txt"
                    ], self.ssh_user, self.ssh_key, self.dev_vm)[0]
                except Exception as e:
                    continue
                new_status = len(status.split("\n"))
                pbar.update(new_status - old_status)

                try:
                    screen_status = run_remote_public_ip([
                        f"tmux list-sessions"
                    ], self.ssh_user, self.ssh_key, self.dev_vm)[0]
                except Exception as e:
                    pbar.display(f"Failed to get status: {e}")
                    screen_status = ""

                if "no server running" in screen_status:
                    pbar.display("Tmux session ended", pos=2)
                    # break
        
        print("Experiment ended")

    
    def run_job_in_dev_vm(self, cmds, wait_till_end=True):
        curr_unix_time = int(time.time())
        job_file = f"job_{curr_unix_time}.sh"
        job_dir = os.path.join(self.workdir, "jobs")
        run_local(["mkdir -p " + job_dir])

        job_path = os.path.join(job_dir, job_file)
        cmd = "\n\n".join([f"""{x} || true
echo "Command {i} exited with status $?" >> status.txt
""" for i, x in enumerate(cmds)])
        script = f"""#!/bin/bash
set -e
set -o xtrace

# This script is generated by the experiment pipeline. DO NOT EDIT.

echo "Running {job_file}" > status.txt

{cmd}

echo "Done {job_file}" >> status.txt
"""
        with open(job_path, "w") as f:
            f.write(script)

        # Copy job dir to dev VM
        self.copy_all_to_remote_public_ip(only_to_dev_vm=True)

        session_name = job_file.replace(".", "_")

        # Run the script in a screen session in dev VM
        ssh_cmd = f"tmux new-session -d -s {session_name} 'sh {self.workdir}/jobs/{job_file} > arbiter_log.txt 2>&1'"
        res = run_remote_public_ip([
            ssh_cmd + " && echo 'Tmux session started'"
        ], self.ssh_user, self.ssh_key, self.dev_vm, hide=True)

        print(ssh_cmd, res)

        if wait_till_end:
            self.wait_till_end(len(cmds))
            
