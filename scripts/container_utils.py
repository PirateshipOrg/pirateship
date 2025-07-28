# Utility scriptsto launch confidential containers in Azure 

import os
import subprocess
import yaml
import json
from ssh_utils import execute_command, execute_command_args
from os import cpu_count
from psutil import virtual_memory
import tempfile
import re

# Generate fully qualified registry image name from 'base' image name
def get_full_image_name(acr_prefix, image_name):
    return acr_prefix + ".azurecr.io/" + image_name

# Build docker Image (no argments expected)
def build_image(full_image_name, docker_folder, ssh_public_key):
    print("Building docker image {}".format(full_image_name))
    try: 
        print(execute_command(f"cp {ssh_public_key} {docker_folder}"))
        print(execute_command("docker build -t " + full_image_name + " " + docker_folder))
    # print(executeCommand("docker build --no-cache -t " + fullImageName + " " + dockerFolder))
        print("Docker image built")
    except subprocess.CalledProcessError as e:
        print("Error building docker image: ", e.stderr)


# Push Docker Image To the Registry. Note that the ACR Prefixi must be the full *.azurecr.io name
# and have been registered through the Azure container registry. 
def push_image(acr_prefix, full_image_name, password=None):
    print("Pushing docker image {}".format(full_image_name))
    # Obtain Password if don't already have token
    if password is None:
        cmd = ["az", "acr", "login", "-n", acr_prefix,"--expose-token","--output", "tsv", "--query","accessToken"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        password = result.stdout
    cmd = "docker login -u 00000000-0000-0000-0000-000000000000 -p " + password + " " + acr_prefix + ".azurecr.io"
    print(execute_command(cmd))
    print(execute_command("docker push " + full_image_name))
    print("Docker image pushed")

# Log out from Docker
def docker_logout():
    print(execute_command("docker logout"))


# Returns token to access the Azure Container Registry
def get_acr_token(acr_prefix):
    return execute_command("az acr login --name " + acr_prefix + " --expose-token --output tsv --query accessToken")

# When running in confidential containers, need to populate the ccePolicy parameter 
# in the ARM Template.  The CCE policy is used for attestation. The tool takes the ARM 
# template as an input to generate the policy. The policy enforces the specific container
# images, environment variables, mounts, and commands, which can then be validated when the 
# container group starts up
def update_sku(template, image_name):
    # Use the Azure Confcom extension to generate the signature.
    # This call automatically updates the template but requires an ok prompt to override, so we make a copy 
    parameters = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "primary-image": {
                "value": image_name
            },
            "sku-type": {
                "value": "Confidential"
            }
        }

    }
    template_with_sku = f"{template}.with-sku.json"
    # open temporaty file to write parameters  using python temp files
    with tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix='.json') as tmpfile:
        json.dump(parameters, tmpfile, indent=4)
        tmpfile.flush()
        execute_command(f"cp {template} {template_with_sku}")
        print(execute_command(f"az confcom acipolicygen -y -a {template_with_sku} -p {tmpfile.name}"))
    return template_with_sku

# Cancels deployment
def cancel_deployment(resource_group, deployment_name):
    print(execute_command_args(["az", "deployment", "group", "cancel",
                               "--resource-group",  resource_group,
                               " --name ", deployment_name]))

# Update the ARM template with the appropriate primary image, region, deployment etc. 
# and launch deployment
def launchDeployment(template_file, resource_group, deployment_name, acr_prefix, primary_image, ssh_key_raw, acr_token, location, server_port, local, total_node_count, confidential=False):
    print("Launching deployment")
    if not local:  
        print(execute_command_args(["az", "deployment", "group", "create", 
                                  "--resource-group", resource_group,
                                  "--template-file", template_file,
                                  "--parameters", "ssh=" +  ssh_key_raw, 
                                  "--parameters", "location=" + location,
                                  "--parameters", "name=" + deployment_name,
                                  "--parameters", "primary-image=" + get_full_image_name(acr_prefix, primary_image) ,
                                  "--parameters", "sku-type=Confidential" if confidential else "sku-type=Standard",
                                  "--parameters", "port=" + str(server_port),
                                  "--parameters", "registry=" +  acr_prefix + ".azurecr.io",
                                  "--parameters", "acr-token=" + acr_token]))
    else: 
        # PirateShip is quite resource intensive... cpu and memory quotas can be a way to run clusters on a single local machine 
        # if you think this is outside the scope od aci deployment (which it is), I can take it away and just create a utility script that handles this
        print(execute_command(f"docker run -d -p {str(server_port)}:22 --cpus={(cpu_count() - 0.5) / total_node_count:.2f} --memory={(virtual_memory().total - 500_000_000) // total_node_count}b --name {deployment_name} {primary_image}"))
        print("Container {} launched.".format(deployment_name))

# Cancels deloyments
def delete_deployment(resource_group, deployment_name, local=False):
    if not local:
        resource_group = " --resource-group " + resource_group
        name = " --name " + deployment_name
        print("Executing command: az deployment group delete " + resource_group + " " +  name)
        print(execute_command("az deployment group delete " + resource_group + " " + name))
    else:
        print(execute_command_args(["docker", "rm", "-f", deployment_name]))

# Obtains the public Ip address of all currently running containers in a specific deployment
# and resource group
def obtain_ip_address(resource_group, deployment_name, local): 
    if not local: 
        result = execute_command("az container show -g " + resource_group + " -n " + deployment_name + " --query ipAddress.ip -o tsv") 
    else:
        # Get Internal IP Address of Docker Container Using Docker Inspect
        result = execute_command_args(["docker", "inspect", "-f",  "\'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\'", deployment_name])
        result = result.strip("'")  # Remove single quotes around the IP address
    if not is_valid_ip(result):
        print("Error: Invalid IP address obtained for deployment " + deployment_name)
        return None
    print("IP Address of " + deployment_name + " is " + result)
    return result 

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None

# Extracts deployment configuration. Takes in a yaml file
# and returns a list of pairs where the first entry is the region
# and the next entry is the number of containers to deploy in that region
# TODO(natacha) add extra fields to describe the amount of resources that should be
# allocated to each container)
# TODO(natacha): standardise configuration such that same configuration 
# can be used for TF and container deployments
def extract_config(config_file):
      with open(config_file, 'r') as stream:
         try:
               config = yaml.safe_load(stream)
               return config
         except yaml.YAMLError as exc:
               print(exc)
               return None


# Collects all public IP addresses in a resource group and returns them in a json format
def collect_all_ip_address_json(resourceGroup, local):
    if not local:
        result = execute_command("az container list -g " + resourceGroup + " --query [].{Name:name,IP:ipAddress.ip} -o json")
    else:
        result = execute_command_args(["docker", "inspect", "-f", "\'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}\'", deploymentName])
        #TODO(natacha): Local Json not implemented yet
    print(result)
    return result

def lift_cpu_quota(deploymentName):
    previous_quota = execute_command_args(["docker", "inspect", "-f", "\'{{.HostConfig.CpuQuota}}\'", deploymentName])
    execute_command_args(["docker", "update", "--cpus", str(cpu_count()), deploymentName])
    return previous_quota

def set_cpu_quota(deploymentName, quota):
    execute_command_args(["docker", "update", "--cpus", str(quota), deploymentName])