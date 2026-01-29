#!/bin/bash

# Define the network name
NETWORK_NAME="proxy-net"

# Check if the network exists
if docker network ls --format '{{.Name}}' | grep -w "$NETWORK_NAME" > /dev/null; then
    echo "Network '$NETWORK_NAME' already exists."
else
    echo "Creating network '$NETWORK_NAME'..."
    docker network create "$NETWORK_NAME"
    if [ $? -eq 0 ]; then
        echo "Network '$NETWORK_NAME' created successfully."
    else
        echo "Failed to create network '$NETWORK_NAME'."
        exit 1
    fi
fi
