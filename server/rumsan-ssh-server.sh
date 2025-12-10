#!/bin/bash

# curl -fsSL https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main/server/rumsan-ssh-server.sh -o rumsan-ssh-server.sh && chmod +x rumsan-ssh-server.sh && ./rumsan-ssh-server.sh

# Base URL for the repository
BASE_URL="https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main"

# Create rs-ssh-server folder
mkdir -p _rumsan-ssh-server
cd _rumsan-ssh-server

# Get the latest commit hash
COMMIT_HASH=$(curl -s https://api.github.com/repos/santosh-rumsan/rumsan-ssh-setup/commits/main | jq -r '.sha' | head -1)

# Check if commit hash is different from the saved one
if [ ! -f .latest_commit ] || [ "$(cat .latest_commit)" != "$COMMIT_HASH" ]; then
  echo "Downloading files (commit changed or first time)"
  
  # Download rs_setup_server.sh
  curl -O ${BASE_URL}/server/rs_setup_server.sh
  
  # Download ping.sh
  curl -O ${BASE_URL}/server/ping.sh
  
  # Save the new commit hash
  echo "$COMMIT_HASH" > .latest_commit
else
  echo "No changes detected (commit hash unchanged)"
fi

# Make scripts executable
chmod +x rs_setup_server.sh
chmod +x ping.sh

# Run rs_setup_server.sh
./rs_setup_server.sh