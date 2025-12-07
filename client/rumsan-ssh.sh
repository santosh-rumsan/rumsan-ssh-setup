#!/bin/bash

# Base URL for the repository
BASE_URL="https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main"

# Create rumsan-ssh-app folder
mkdir -p rumsan-ssh-app
cd rumsan-ssh-app

# Download rs_client.sh
curl -O ${BASE_URL}/client/rs_client.sh

# Download oauth_login.py
curl -O ${BASE_URL}/client/oauth_login.py

# Make rs_client.sh executable
chmod +x rs_client.sh

# Run rs_client.sh
./rs_client.sh
