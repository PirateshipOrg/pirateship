#!/bin/bash

# Deploy Pirateship platforms from configuration file
# Usage: ./deploy-platform.sh <config-file> [resource-group-name]

set -e

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <config-file> [resource-group-name]"
    echo "Example: $0 setups/lan.conf"
    echo "Example: $0 setups/wan.conf pirateship-dev"
    exit 1
fi

CONFIG_FILE=$1
RESOURCE_GROUP=${2:-"pirateship-arm"}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SSH_KEY_FILE="$PROJECT_ROOT/cluster_key.pub"
SSH_PRIV_KEY_FILE="$PROJECT_ROOT/cluster_key.pem"

# Validate config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found at $CONFIG_FILE"
    exit 1
fi

# Validate SSH key exists
if [ ! -f "$SSH_KEY_FILE" ]; then
    echo "Error: SSH key file not found at $SSH_KEY_FILE"
    echo "Please ensure cluster_key.pub exists in the project root"
    exit 1
fi

# Read SSH key
SSH_KEY_DATA=$(cat "$SSH_KEY_FILE")

# Source the config file
source "$CONFIG_FILE"

# Validate required variables
if [ -z "${platform_locations:-}" ] || [ -z "${sevpool_count:-}" ] || [ -z "${clientpool_count:-}" ]; then
    echo "Error: Config file must define platform_locations, sevpool_count, and clientpool_count arrays"
    exit 1
fi

# Set defaults for VM sizes if not specified
sev_vm_size=${sev_vm_size:-"Standard_D4s_v3"}
client_vm_size=${client_vm_size:-"Standard_D2s_v3"}
enable_confidential_computing=${enable_confidential_computing:-false}

echo "=== Deploying Pirateship Multi-Platform Setup ==="
echo "Config: $CONFIG_FILE"
echo "Resource Group: $RESOURCE_GROUP"
echo "Platform Locations: ${platform_locations[*]}"
echo "SSH Key: $SSH_KEY_FILE"
echo

# Create resource group in the first location
FIRST_LOCATION=${platform_locations[0]}
echo "Creating resource group in $FIRST_LOCATION..."
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$FIRST_LOCATION" \
    --output table

echo

# Deploy each platform
for i in "${!platform_locations[@]}"; do
    location="${platform_locations[$i]}"
    sev_count="${sevpool_count[$i]}"
    client_count="${clientpool_count[$i]}"
    
    echo "=== Deploying Platform $((i+1))/${#platform_locations[@]} ==="
    echo "Location: $location"
    echo "SEV VMs: $sev_count"
    echo "Client VMs: $client_count"
    
    # Skip if both counts are 0
    if [ "$sev_count" -eq 0 ] && [ "$client_count" -eq 0 ]; then
        echo "Skipping $location (no VMs to deploy)"
        echo
        continue
    fi
    
    # Deploy ARM template for this platform
    DEPLOYMENT_NAME="platform-$location-$(date +%s)"
    echo "Deployment: $DEPLOYMENT_NAME"
    
    az deployment group create \
        --resource-group "$RESOURCE_GROUP" \
        --template-file "$SCRIPT_DIR/platform-template.json" \
        --parameters \
            location="$location" \
            sevVmCount="$sev_count" \
            clientVmCount="$client_count" \
            sshPublicKey="$SSH_KEY_DATA" \
            sevVmSize="$sev_vm_size" \
            clientVmSize="$client_vm_size" \
            enableConfidentialComputing="$enable_confidential_computing" \
        --name "$DEPLOYMENT_NAME" \
        --output table \
        --verbose --debug 2> /tmp/deployment_errors.log

    echo "Platform $location deployed successfully!"
    echo
done

echo "=== All Platforms Deployed ==="
echo "Getting public IP addresses..."
az vm list-ip-addresses \
    --resource-group "$RESOURCE_GROUP" \
    --output table

echo
echo "=== Running VM Initialization ==="
echo "Initializing all VMs concurrently..."

# Get all VM public IPs for initialization
VM_IPS=$(az vm list-ip-addresses --resource-group "$RESOURCE_GROUP" --query "[].virtualMachine.network.publicIpAddresses[0].ipAddress" --output tsv | grep -v "^$")

# Counter for tracking initialization jobs
init_jobs=()

# Function to initialize a single VM
init_vm() {
    local vm_ip=$1
    local log_file="/tmp/vm_init_${vm_ip}.log"
    
    echo "Starting initialization of VM $vm_ip..."
    
    # Wait for VM to be ready for SSH (up to 10 minutes)
    local max_attempts=60
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i $SSH_PRIV_KEY_FILE pftadmin@"$vm_ip" "echo 'VM ready $vm_ip'" &>/dev/null; then
            break
        fi
        echo "Waiting for VM $vm_ip to be ready for SSH (attempt $attempt/$max_attempts)..."
        sleep 10
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        echo "ERROR: VM $vm_ip failed to become ready for SSH" | tee "$log_file"
        return 1
    fi
    
    echo "VM $vm_ip is ready for SSH"
    
    # Copy initialization script
    echo "Copying initialization script to VM $vm_ip..."
    if ! scp -o StrictHostKeyChecking=no -i $SSH_PRIV_KEY_FILE "$SCRIPT_DIR/init.sh" pftadmin@"$vm_ip":~/ &>"$log_file"; then
        echo "ERROR: Failed to copy init script to VM $vm_ip. See $log_file for details"
        cat "$log_file"
        return 1
    fi
    
    # Run initialization script
    echo "Running initialization script on VM $vm_ip..."
    if ssh -o StrictHostKeyChecking=no -i $SSH_PRIV_KEY_FILE pftadmin@"$vm_ip" "chmod +x ~/init.sh && ~/init.sh" &>>"$log_file"; then
        echo "VM $vm_ip initialization script completed"
        
        # Verify SSH still works after initialization
        echo "Verifying SSH connectivity to VM $vm_ip after initialization..."
        local verify_attempts=5
        local verify_attempt=1
        while [ $verify_attempt -le $verify_attempts ]; do
            if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i $SSH_PRIV_KEY_FILE pftadmin@"$vm_ip" "echo 'SSH verification successful'" &>/dev/null; then
                echo "VM $vm_ip initialization completed successfully - SSH connectivity verified"
                return 0
            fi
            echo "SSH verification attempt $verify_attempt/$verify_attempts failed for VM $vm_ip, retrying..."
            sleep 5
            verify_attempt=$((verify_attempt + 1))
        done
        
        echo "WARNING: VM $vm_ip initialization completed but SSH verification failed"
        echo "The VM may require a reboot for all changes to take effect"
        return 0
    else
        echo "ERROR: VM $vm_ip initialization failed. See $log_file for details"
        cat "$log_file"
        return 1
    fi
}

# Start initialization for all VMs in parallel
for vm_ip in $VM_IPS; do
    if [ -n "$vm_ip" ] && [ "$vm_ip" != "null" ]; then
        init_vm "$vm_ip" &
        init_jobs+=($!)
    fi
done

# Wait for all initialization jobs to complete
init_failed=0
for job in "${init_jobs[@]}"; do
    if ! wait "$job"; then
        init_failed=1
    fi
done

if [ $init_failed -eq 1 ]; then
    echo "WARNING: Some VM initializations failed. Check the logs above for details."
else
    echo "All VMs initialized successfully!"
fi

echo
echo "=== TOML Configuration Format ==="
echo "# Copy this configuration to your experiment TOML file:"
echo

# Get VM IP information and format as TOML
VM_INFO=$(az vm list-ip-addresses --resource-group "$RESOURCE_GROUP" --output json)

# Parse SEV VMs (nodepool)
echo "$VM_INFO" | jq -r '.[] | select(.virtualMachine.name | startswith("sev-vm-")) | 
  "[\(.virtualMachine.name | gsub("sev-vm-"; "deployment_config.node_list.nodepool_vm"))]
private_ip = \"\(.virtualMachine.network.privateIpAddresses[0])\"
public_ip = \"\(.virtualMachine.network.publicIpAddresses[0].ipAddress)\"
tee_type = \"sev\"
region_id = 0
"'

# Parse Client VMs (clientpool)
echo "$VM_INFO" | jq -r '.[] | select(.virtualMachine.name | startswith("client-vm-")) | 
  "[\(.virtualMachine.name | gsub("client-vm-"; "deployment_config.node_list.clientpool_vm"))]
private_ip = \"\(.virtualMachine.network.privateIpAddresses[0])\"
public_ip = \"\(.virtualMachine.network.publicIpAddresses[0].ipAddress)\"
"'

echo
echo "=== SSH Access ==="
echo "You can SSH to the VMs using:"
echo "ssh -i $PROJECT_ROOT/cluster_key pftadmin@<public-ip>"
