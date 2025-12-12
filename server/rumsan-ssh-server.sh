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

# Setup cron job for ping.sh to run every 30 minutes
setup_ping_cron() {
    local ping_script="$(pwd)/ping.sh"
    local cron_temp=$(mktemp)
    
    # Get existing cron jobs
    sudo crontab -l > "$cron_temp" 2>/dev/null || true
    
    # Check if the cron job already exists
    if ! grep -q "*/30.*ping.sh" "$cron_temp"; then
        # Add the new cron job (every 30 minutes)
        echo "*/30 * * * * $ping_script > /dev/null 2>&1" >> "$cron_temp"
        
        # Install the updated crontab
        sudo crontab "$cron_temp"
        echo "[INFO] Cron job added: ping.sh will run every 30 minutes"
    else
        echo "[INFO] Cron job already exists for ping.sh"
    fi
    
    # Clean up
    rm "$cron_temp"
}

# Setup the cron job
setup_ping_cron

# Run rs_setup_server.sh
./rs_setup_server.sh