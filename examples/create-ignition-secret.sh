#!/bin/bash
# Script to create a Kubernetes secret from an Ignition configuration file
# Usage: ./create-ignition-secret.sh <ignition-file> <secret-name> [namespace]

set -e


if [ $# -lt 2 ]; then
    echo "Usage: $0 <ignition-file> <secret-name> [namespace]"
    echo "Example: $0 ignition-coreos.json coreos-ignition-secret trusted-execution-clusters"
    exit 1
fi

IGNITION_FILE="$1"
SECRET_NAME="$2"
NAMESPACE="${3:-default}"

if [ ! -f "$IGNITION_FILE" ]; then
    echo "Error: Ignition file '$IGNITION_FILE' not found"
    exit 1
fi

echo "Creating Kubernetes secret '$SECRET_NAME' in namespace '$NAMESPACE' from '$IGNITION_FILE'..."
kubectl create secret generic "$SECRET_NAME" \
    --from-file=userdata="$IGNITION_FILE" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -
