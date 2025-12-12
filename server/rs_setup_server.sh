#!/bin/bash

# ==========================================
# SSH CA Host Setup Script for Ubuntu
# ==========================================

# Meta file to store configuration values
RUMSAN_PATH="/etc/ssh/rumsan"
sudo mkdir -p "$RUMSAN_PATH"
sudo chmod 755 "$RUMSAN_PATH"
META_FILE="$RUMSAN_PATH/meta.sh"
HOST_CACHE_FILE="$RUMSAN_PATH/hosts.json"

BASE_URL="https://ceamyckytvqemsjijavg.supabase.co/functions/v1"

# ==========================================
# Logging functions
# ==========================================

log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warning() {
    echo "[WARNING] $1"
}

# ==========================================
# Function definitions
# ==========================================

# Function to read from meta
read_meta() {
    local key=$1
    if [[ -f "$META_FILE" ]]; then
        grep "^${key}=" "$META_FILE" | cut -d'=' -f2-
    fi
}

# Function to write to meta
write_meta() {
    local key=$1
    local value=$2
    if [[ -f "$META_FILE" ]]; then
        # Update existing key or append if not found
        if grep -q "^${key}=" "$META_FILE"; then
            # Use different sed syntax for macOS vs Linux
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sudo sed -i .bak "s|^${key}=.*|${key}=${value}|" "$META_FILE"
            else
                sudo sed -i.bak "s|^${key}=.*|${key}=${value}|" "$META_FILE"
            fi
        else
            echo "${key}=${value}" | sudo tee -a "$META_FILE" > /dev/null
        fi
    else
        echo "${key}=${value}" | sudo tee "$META_FILE" > /dev/null
    fi
    sudo chmod 644 "$META_FILE"
}

# Function to read host cache
read_host_cache() {
    if [[ -f "$HOST_CACHE_FILE" ]]; then
        sudo cat "$HOST_CACHE_FILE"
    else
        echo "[]"
    fi
}

# Function to write host cache
write_host_cache() {
    local cache_data=$1
    echo "$cache_data" | sudo tee "$HOST_CACHE_FILE" > /dev/null
    sudo chmod 644 "$HOST_CACHE_FILE"
}

# Function to check if user has SUDO access
check_sudo_access() {
    local username=$1
    if sudo -l -U "$username" &>/dev/null 2>&1; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to find host in cache by username
find_host_in_cache() {
    local hostname=$1
    local username=$2
    local cache_data=$(read_host_cache)
    
    python3 -c "
import sys
import json

try:
    cache = json.loads('''$cache_data''')
    username = '$username'
    
    for host in cache:
        if host.get('username') == username:
            print(host.get('host_id', ''))
            sys.exit(0)
    
    # Not found
    print('')
except Exception as e:
    print(f'Error reading cache: {e}', file=sys.stderr)
    print('')
"
}

# Function to add or update host in cache
add_to_host_cache() {
    local hostname=$1
    local username=$2
    local host_id=$3
    local is_sudo=$4
    local cache_data=$(read_host_cache)
    
    python3 -c "
import sys
import json
from datetime import datetime

try:
    cache = json.loads('''$cache_data''')
    hostname = '$hostname'
    username = '$username'
    host_id = '$host_id'
    
    # Check if entry already exists and update it
    entry_found = False
    for host in cache:
        if host.get('username') == username:
            host['host_id'] = host_id
            host['is_sudo'] = '$is_sudo' == 'true'
            host['updated_at'] = datetime.now().isoformat()
            entry_found = True
            break
    
    # If not found, add new entry
    if not entry_found:
        cache.append({
            'username': username,
            'host_id': host_id,
            'is_sudo': '$is_sudo' == 'true',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        })
    
    # Sort by username for consistency
    cache = sorted(cache, key=lambda x: x.get('username', ''))
    
    print(json.dumps(cache, indent=2))
except Exception as e:
    print(f'Error updating cache: {e}', file=sys.stderr)
    sys.exit(1)
" | sudo tee "$HOST_CACHE_FILE" > /dev/null
    sudo chmod 644 "$HOST_CACHE_FILE"
}

# Function to register host with API and cache the result
register_and_cache_host() {
    local hostname=$1
    local username=$2
    local signature=$3
    local cloudflared=$4
    local public_key=$5
    local is_sudo=$6
    
    # Prepare API request
    local api_payload=$(cat <<EOF
{
  "signature": "$signature",
  "name": "$hostname",
  "principal": "$username",
  "cloudflared": "$cloudflared",
  "public_key": "$public_key",
  "is_sudo": $is_sudo
}
EOF
)

    echo "Calling API to register host..."
    local api_response=$(curl -s -X POST "$BASE_URL/host/add" \
      -H "Content-Type: application/json" \
      -d "$api_payload")

    if [[ -z "$api_response" ]]; then
        log_error "Failed to call API"
        return 1
    fi

    # Parse the response to get HOST_ID
    local host_id=$(echo "$api_response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('data', {}).get('id', ''))" 2>/dev/null)

    if [[ -z "$host_id" ]]; then
        log_error "Failed to get HOST_ID from API response"
        log_error "API Response: $api_response"
        return 1
    fi

    # Add to host cache
    add_to_host_cache "$hostname" "$username" "$host_id" "$is_sudo"
    
    # Return the HOST_ID
    echo "$host_id"
    return 0
}

# Check if Python is installed
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        log_info "Python 3 found: $(python3 --version)"
        return 0
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        log_info "Python found: $(python --version)"
        return 0
    else
        return 1
    fi
}

# Install Python based on the OS
install_python() {
    log_warning "Python is not installed. Attempting to install..."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            log_info "Installing Python via Homebrew..."
            brew install python3
        else
            log_error "Homebrew not found. Please install Homebrew from https://brew.sh/"
            log_error "Or install Python manually from https://www.python.org/downloads/"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux (Debian/Ubuntu)
        if command -v apt-get &> /dev/null; then
            log_info "Installing Python via apt-get..."
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
        # Linux (Fedora/RHEL)
        elif command -v dnf &> /dev/null; then
            log_info "Installing Python via dnf..."
            sudo dnf install -y python3 python3-pip
        # Linux (Arch)
        elif command -v pacman &> /dev/null; then
            log_info "Installing Python via pacman..."
            sudo pacman -S python
        else
            log_error "Could not detect package manager. Please install Python manually."
            exit 1
        fi
    else
        log_error "Unsupported OS. Please install Python manually from https://www.python.org/downloads/"
        exit 1
    fi
    
    if check_python; then
        log_info "Python installed successfully"
    else
        log_error "Failed to install Python"
        exit 1
    fi
}

# Ensure pip3 and required packages are installed
setup_dependencies() {
    log_info "Setting up dependencies..."
    
    # Install pip3 if not available
    if ! command -v pip3 &> /dev/null; then
        log_warning "pip3 not found, installing..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update
                sudo apt-get install -y python3-pip
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y python3-pip
            else
                log_error "Could not install pip3. Please install it manually."
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            if command -v brew &> /dev/null; then
                brew install python3
            else
                log_error "Could not install pip3. Please install Homebrew or Python manually."
                exit 1
            fi
        fi
    fi
    
    # Install required Python packages
    log_info "Installing required Python packages..."
    
    # Try normal installation first
    if pip3 install --user requests eciespy > /dev/null 2>&1; then
        log_info "Dependencies installed successfully"
    # If that fails due to PEP 668, try with --break-system-packages
    elif pip3 install --user --break-system-packages requests eciespy > /dev/null 2>&1; then
        log_info "Dependencies installed successfully (system packages mode)"
    else
        log_error "Failed to install dependencies. Please try manually:"
        log_error "  pip3 install --user requests eciespy"
        log_error "  OR: pip3 install --break-system-packages requests eciespy"
        exit 1
    fi
}

# Function to encrypt data with public key using ECIES
encrypt_with_public_key() {
    local public_key="$1"
    local data="$2"

    python3 -c "
import sys
try:
    from ecies import encrypt
    public_key = '$public_key'
    data = '$data'
    
    # Remove 0x prefix and convert to bytes
    pub_bytes = bytes.fromhex(public_key.replace('0x', ''))
    
    # Encrypt the data
    encrypted = encrypt(pub_bytes, data.encode('utf-8'))
    
    # Return as hex string with 0x prefix
    print('0x' + encrypted.hex())
except ImportError as e:
    print(f'Error: ecies module not found. Please ensure eciespy is installed.', file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f'Error during encryption: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Function to read user input with validation (no empty responses)
read_required_input() {
    local prompt="$1"
    local min_length=${2:-1}
    local input_value=""
    
    while true; do
        read -p "$prompt" input_value
        if [[ -z "$input_value" ]]; then
            log_error "Input cannot be empty. Please try again."
        elif [[ ${#input_value} -lt $min_length ]]; then
            log_error "Input must be at least $min_length characters long. Please try again."
        else
            echo "$input_value"
            return 0
        fi
    done
}

# Function to read yes/no input with validation
read_yes_no_input() {
    local prompt="$1"
    local input_value=""
    
    while true; do
        read -p "$prompt" input_value
        input_value=$(echo "$input_value" | tr '[:upper:]' '[:lower:]')
        
        if [[ "$input_value" == "yes" || "$input_value" == "y" || "$input_value" == "no" || "$input_value" == "n" ]]; then
            echo "$input_value"
            return 0
        else
            echo "Error: Please enter only 'yes', 'y', 'no', or 'n'."
        fi
    done
}

# Function to display interactive menu with arrow key navigation
select_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local selected=0
    
    # Hide cursor
    tput civis
    trap "tput cnorm; exit" EXIT INT TERM
    
    while true; do
        # Clear previous menu
        clear
        echo "$prompt"
        echo ""
        
        # Display options
        for i in "${!options[@]}"; do
            if [[ $i -eq $selected ]]; then
                echo -e "\033[32m● \033[0m${options[$i]}"
            else
                echo "  ${options[$i]}"
            fi
        done
        
        echo ""
        echo "Use ↑/↓ arrow keys to navigate, press Enter to select"
        
        # Read single character input
        read -rsn1 key
        
        if [[ $key == "" ]]; then
            # Enter key pressed
            echo ""
            tput cnorm
            return $selected
        elif [[ $key == $'\x1b' ]]; then
            # Escape sequence detected (arrow keys)
            read -rsn2 key
            case $key in
                '[A')
                    # Up arrow
                    if [[ $selected -gt 0 ]]; then
                        ((selected--))
                    fi
                    ;;
                '[B')
                    # Down arrow
                    if [[ $selected -lt $((${#options[@]} - 1)) ]]; then
                        ((selected++))
                    fi
                    ;;
            esac
        fi
    done
}

# Function to create or use existing SSH user
create_or_use_user() {
    select_menu "Do you want to create a new user or use existing user?" \
        "Create a new user" \
        "Use an existing user"
    
    local choice=$?
    
    if [[ $choice -eq 0 ]]; then
        # Create new user with random 12-letter lowercase username
        USERNAME=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 12)
        echo "Creating new user: $USERNAME (no password)..."
        if ! sudo useradd -m -s /bin/bash "$USERNAME"; then
            echo "Error: Failed to create user $USERNAME"
            exit 1
        fi
    else
        # Prompt for existing username (minimum 3 characters)
        EXISTING_USERNAME=$(read_required_input "Enter existing username: " 3)
        
        # Check if user exists
        if id "$EXISTING_USERNAME" &>/dev/null; then
            USERNAME="$EXISTING_USERNAME"
            echo "Using existing user: $USERNAME"
        else
            echo "Error: User $EXISTING_USERNAME does not exist"
            exit 1
        fi
    fi
}

########################################################################
###### MAIN SCRIPT INITIALIZATION ######
########################################################################
echo ""
echo "=========================================="
echo "Rumsan SSH Setup - Initializing..."
echo "=========================================="
echo ""

# Check if Python is installed, install if necessary
echo "Checking Python installation..."
if ! check_python; then
    install_python
fi

# Setup dependencies
echo "Installing dependencies..."
setup_dependencies

echo ""
echo "=========================================="
echo "Proceeding with SSH Configuration..."
echo "=========================================="
echo ""

########################################################################
###### Query API to get server's public key and save to meta ######
echo "Querying API for server's public key..."
RESPONSE=$(curl -s "$BASE_URL/host/public-key")

if [[ -z "$RESPONSE" ]]; then
    echo "Error: Failed to query API"
    exit 1
fi

# Parse JSON response
SERVER_PUBLIC_KEY=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['data']['publicKey'])" 2>/dev/null)
SERVER_COMPRESSED_KEY=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['data']['compressedKey'])" 2>/dev/null)
SERVER_ETH_ADDRESS=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['data']['ethAddress'])" 2>/dev/null)

if [[ -z "$SERVER_PUBLIC_KEY" || -z "$SERVER_COMPRESSED_KEY" || -z "$SERVER_ETH_ADDRESS" ]]; then
    echo "Error: Failed to parse API response"
    exit 1
fi

# Save to meta
write_meta "SERVER_PUBLIC_KEY" "$SERVER_PUBLIC_KEY"
write_meta "SERVER_COMPRESSED_KEY" "$SERVER_COMPRESSED_KEY"
write_meta "SERVER_ETH_ADDRESS" "$SERVER_ETH_ADDRESS"

echo "Saved public key data to meta"

########################################################################
###### Check if host already exists in cache, if so exit ######
# Note: We check the cache instead of meta since a host is unique by hostname+username
# For now, we'll skip this check and allow re-registration with different usernames

########################################################################
###### Download CA public key from GitHub and save it at $RUMSAN_PATH ######
echo "Downloading CA public key from GitHub..."
CA_PUB_KEY=$(curl -s https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main/static/ca_public_key)

if [[ -z "$CA_PUB_KEY" ]]; then
  echo "Error: Failed to download CA public key"
  exit 1
fi

# 3Create folder for CA
CA_DIR="$RUMSAN_PATH"
echo "Creating CA directory at $CA_DIR..."
sudo mkdir -p "$CA_DIR"
sudo chmod 755 "$CA_DIR"

# Save the downloaded CA public key
echo "Saving CA public key to $CA_DIR/rumsan_ca.pub..."
echo "$CA_PUB_KEY" | sudo tee "$CA_DIR/rumsan_ca.pub" >/dev/null
sudo chmod 644 "$CA_DIR/rumsan_ca.pub"

######################################################################
###### Create/update $RUMSAN_PATH/rumsan_sshd_config ######
RUMSAN_SSHD_CONFIG="$RUMSAN_PATH/rumsan_sshd_config"

echo "Creating/updating $RUMSAN_SSHD_CONFIG..."
sudo tee "$RUMSAN_SSHD_CONFIG" > /dev/null << EOF
TrustedUserCAKeys $RUMSAN_PATH/rumsan_ca.pub
PubkeyAuthentication yes
PasswordAuthentication no
EOF

sudo chmod 644 "$RUMSAN_SSHD_CONFIG"

########################################################################
###### Update /etc/ssh/sshd_config to include rumsan_sshd_config ######
SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup sshd_config first
# sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak_$(date +%F_%T)"

# Check if Include $RUMSAN_PATH/rumsan_sshd_config already exists
if ! grep -q "^Include $RUMSAN_PATH/rumsan_sshd_config" "$SSHD_CONFIG"; then
    echo "Adding Include statement for rumsan_sshd_config..."
    # Find the last Include statement and add after it
    LAST_INCLUDE_LINE=$(grep -n "^Include " "$SSHD_CONFIG" | tail -1 | cut -d: -f1)
    if [[ -n "$LAST_INCLUDE_LINE" ]]; then
        # Use awk to insert the line - works on both macOS and Ubuntu
        sudo awk -v line="$LAST_INCLUDE_LINE" -v path="$RUMSAN_PATH" 'NR==line {print; print "Include " path "/rumsan_sshd_config"; next} {print}' "$SSHD_CONFIG" | sudo tee "$SSHD_CONFIG.tmp" > /dev/null
        sudo mv "$SSHD_CONFIG.tmp" "$SSHD_CONFIG"
    else
        # If no Include statement exists, add it to the end
        echo "Include $RUMSAN_PATH/rumsan_sshd_config" | sudo tee -a "$SSHD_CONFIG" > /dev/null
    fi
fi

########################################################################
###### Generate and save HOST_PRIVATE_KEY and HOST_PUBLIC_KEY ######
###### Using secp256k1 Ethereum-style keys ######
CACHED_PRIVATE_KEY=$(read_meta "HOST_PRIVATE_KEY")
CACHED_PUBLIC_KEY=$(read_meta "HOST_PUBLIC_KEY")

if [[ -n "$CACHED_PRIVATE_KEY" && -n "$CACHED_PUBLIC_KEY" ]]; then
    HOST_PRIVATE_KEY="$CACHED_PRIVATE_KEY"
    HOST_PUBLIC_KEY="$CACHED_PUBLIC_KEY"
    echo "Using cached HOST_PRIVATE_KEY and HOST_PUBLIC_KEY"
else
    # Generate a secp256k1 private key using openssl
    # Create a temporary EC private key in PEM format
    TEMP_PRIV=$(mktemp)
    openssl ecparam -name secp256k1 -genkey -noout -out "$TEMP_PRIV" 2>/dev/null
    
    # Extract the private key in hex format (256-bit private key)
    PRIVATE_KEY_HEX=$(openssl ec -in "$TEMP_PRIV" -text -noout 2>/dev/null | grep 'priv:' -A 3 | tail -n +2 | tr -d ':\n ' | sed 's/^0*//')
    
    # Pad to 64 characters if needed
    while [ ${#PRIVATE_KEY_HEX} -lt 64 ]; do
        PRIVATE_KEY_HEX="0${PRIVATE_KEY_HEX}"
    done
    
    # Extract the public key (uncompressed format from DER)
    PUBLIC_KEY_HEX=$(openssl ec -in "$TEMP_PRIV" -pubout -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 65)
    
    # Compress the public key (Ethereum-style compressed format)
    if [[ ${#PUBLIC_KEY_HEX} -ge 130 ]]; then
        # Extract x and y coordinates (skip first byte 04)
        X_COORD=${PUBLIC_KEY_HEX:2:64}
        Y_COORD=${PUBLIC_KEY_HEX:66:64}
        
        # Check if Y is even or odd (last hex digit of Y coordinate)
        LAST_DIGIT=${Y_COORD: -1}
        if [[ $((0x$LAST_DIGIT % 2)) -eq 0 ]]; then
            PREFIX="02"
        else
            PREFIX="03"
        fi
        
        COMPRESSED_PUBLIC_KEY="${PREFIX}${X_COORD}"
    else
        # Fallback if extraction fails
        COMPRESSED_PUBLIC_KEY="$PUBLIC_KEY_HEX"
    fi
    
    # Clean up temp file
    rm -f "$TEMP_PRIV"
    
    # Format with 0x prefix (Ethereum-style)
    HOST_PRIVATE_KEY="0x${PRIVATE_KEY_HEX}"
    HOST_PUBLIC_KEY="0x${COMPRESSED_PUBLIC_KEY}"
    
    # Save to meta
    write_meta "HOST_PRIVATE_KEY" "$HOST_PRIVATE_KEY"
    write_meta "HOST_PUBLIC_KEY" "$HOST_PUBLIC_KEY"
fi

########################################################################
###### Register host with API ######
echo ""
echo ""
echo "========================================="
echo "!!! YOUR ACTION NEEDED !!!"
echo "Answer the following to register your host"
echo "========================================="

# Create or use existing user
create_or_use_user

# Check if HOST_NAME already exists in meta, otherwise ask for it
CACHED_HOST_NAME=$(read_meta "HOST_NAME")
if [[ -n "$CACHED_HOST_NAME" ]]; then
    HOST_NAME="$CACHED_HOST_NAME"
    echo "Using cached host name: $HOST_NAME"
else
    # Ask for host name (minimum 3 characters)
    HOST_NAME=$(read_required_input "Enter host name (URL or IP to access via SSH): " 3)
    # Save to meta
    write_meta "HOST_NAME" "$HOST_NAME"
fi

# Check if CLOUDFLARED already exists in meta, otherwise ask for it
CACHED_CLOUDFLARED=$(read_meta "CLOUDFLARED")
if [[ -n "$CACHED_CLOUDFLARED" ]]; then
    CLOUDFLARED="$CACHED_CLOUDFLARED"
    echo "Using cached cloudflared setting: $CLOUDFLARED"
else
    # Ask if cloudflared
    CLOUDFLARED_INPUT=$(read_yes_no_input "Is this a Cloudflared host? (yes/no): ")
    if [[ "$CLOUDFLARED_INPUT" == "yes" || "$CLOUDFLARED_INPUT" == "y" ]]; then
        CLOUDFLARED="true"
    else
        CLOUDFLARED="false"
    fi
    # Save to meta
    write_meta "CLOUDFLARED" "$CLOUDFLARED"
fi

# Check if user has SUDO access
log_info "Checking SUDO access for user $USERNAME..."
IS_SUDO=$(check_sudo_access "$USERNAME")
if [[ "$IS_SUDO" == "true" ]]; then
    log_info "User $USERNAME has SUDO access"
else
    log_info "User $USERNAME does not have SUDO access"
fi

# Get current timestamp in milliseconds
TIMESTAMP_SECONDS=$(date +%s)
TIMESTAMP=$((TIMESTAMP_SECONDS * 1000))

# Encrypt timestamp with SERVER_PUBLIC_KEY using ECIES
SIGNATURE=$(encrypt_with_public_key "$SERVER_PUBLIC_KEY" "$TIMESTAMP")
if [[ -z "$SIGNATURE" ]]; then
    echo "Error: Failed to encrypt timestamp"
    exit 1
fi

# Check if host already exists in cache
CACHED_HOST_ID=$(find_host_in_cache "$HOST_NAME" "$USERNAME")
if [[ -n "$CACHED_HOST_ID" ]]; then
    echo "Host already registered in cache!"
    HOST_ID="$CACHED_HOST_ID"
    echo "✅ Host setup already complete!"
    exit 0
else
    # Register with API and cache the result
    HOST_ID=$(register_and_cache_host "$HOST_NAME" "$USERNAME" "$SIGNATURE" "$CLOUDFLARED" "$HOST_PUBLIC_KEY" "$IS_SUDO")
    if [[ -z "$HOST_ID" ]]; then
        echo "Error: Failed to register host"
        exit 1
    fi
fi

echo "✅ Host registered successfully!"

########################################################################
###### Restart SSH service safely ######
echo "Restarting sshd..."
sudo systemctl restart ssh

########################################################################
###### Display final info ######
echo ""
echo ""
echo "====================================="
echo "User: $USERNAME"
echo "SUDO Access: $IS_SUDO"
echo "HOST_ID: $HOST_ID"
echo "CA Public Key saved at: $CA_DIR/rumsan_ca.pub"
echo "Custom SSH config: $RUMSAN_SSHD_CONFIG"
echo "Meta file: $META_FILE"
echo "Host cache file: $HOST_CACHE_FILE"
echo "======================================"
echo "✅ Host setup complete!"
echo "======================================"