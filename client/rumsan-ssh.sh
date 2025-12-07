#!/bin/bash

# curl -fsSL https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main/client/rumsan-ssh.sh -o rumsan-ssh.sh && chmod +x rumsan-ssh.sh && ./rumsan-ssh.sh

# Base URL for the repository
BASE_URL="https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main"

# Create rs-ssh-app folder
mkdir -p _rumsan-ssh
cd _rumsan-ssh

# Get the latest commit hash
COMMIT_HASH=$(curl -s https://api.github.com/repos/santosh-rumsan/rumsan-ssh-setup/commits/main | jq -r '.sha' | head -1)

# Check if commit hash is different from the saved one
if [ ! -f .latest_commit ] || [ "$(cat .latest_commit)" != "$COMMIT_HASH" ]; then
  echo "Downloading files (commit changed or first time)"
  
  # Download rs_client.sh
  curl -O ${BASE_URL}/client/rs_client.sh
  
  # Download oauth_login.py
  curl -O ${BASE_URL}/client/oauth_login.py
  
  # Save the new commit hash
  echo "$COMMIT_HASH" > .latest_commit
else
  echo "No changes detected (commit hash unchanged)"
fi

# Make rs_client.sh executable
chmod +x rs_client.sh

# Run rs_client.sh
./rs_client.sh

