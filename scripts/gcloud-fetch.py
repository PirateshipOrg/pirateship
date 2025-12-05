from subprocess import Popen, PIPE

GCLOUD = "/opt/homebrew/share/google-cloud-sdk/bin/gcloud"

def run_gcloud(command):
    return Popen(
        f'{GCLOUD} {command}',
        shell=True,
        stdout=PIPE,
        stderr=PIPE,
    ).stdout.read().decode('utf-8').split("\n")

all_node_list = run_gcloud(
    'compute instances list --filter="Name ~ pool" --format="table(Name, INTERNAL_IP, EXTERNAL_IP)"'
)
all_node_list = [line.split() for line in all_node_list if line.strip()][1:] # Skip header


client_list = [x for x in all_node_list if "client" in x[0]]
node_list = [x for x in all_node_list if not("client" in x[0])]

print("[deployment_config.node_list]")

for i, node in enumerate(node_list):
    print(f"[deployment_config.node_list.nodepool_vm{i}]")
    print(f"private_ip = \"{node[1]}\"")
    print(f"public_ip = \"{node[2]}\"")

    if "sev" in node[0]:
        tee_type = "sev"
    elif "tdx" in node[0]:
        tee_type = "tdx"
    else:
        tee_type = "nontee"

    print(f"tee_type = \"{tee_type}\"")
    print(f"region_id = 0")
    print()

for i, node in enumerate(client_list):
    print(f"[deployment_config.node_list.clientpool_vm{i}]")
    print(f"private_ip = \"{node[1]}\"")
    print(f"public_ip = \"{node[2]}\"")