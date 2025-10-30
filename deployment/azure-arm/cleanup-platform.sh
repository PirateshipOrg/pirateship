#!/bin/bash

# Cleanup a Pirateship platform deployment
# Usage: ./cleanup-platform.sh [resource-group-name]

set -e

RESOURCE_GROUP=${1:-"pirateship"}

echo "=== Cleanup Pirateship Deployment ==="
echo "Resource Group: $RESOURCE_GROUP"
echo

if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    echo "Resource group '$RESOURCE_GROUP' does not exist. Nothing to clean up."
    exit 0
fi

echo "Resources to be deleted:"
az resource list --resource-group "$RESOURCE_GROUP" --output table

echo

echo "Deleting resource group..."
az group delete \
    --name "$RESOURCE_GROUP" \
    --yes \
    --no-wait

echo "Cleanup initiated for resource group '$RESOURCE_GROUP'"
