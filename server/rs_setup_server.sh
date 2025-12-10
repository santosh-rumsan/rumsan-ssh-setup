#!/bin/bash

# ==========================================
# SSH CA Host Setup Script for Ubuntu
# ==========================================

# Meta file to store configuration values
RUMSAN_PATH="/etc/ssh/rumsan"
sudo mkdir -p "$RUMSAN_PATH"
sudo chmod 755 "$RUMSAN_PATH"
META_FILE="$RUMSAN_PATH/meta.sh"

BASE_URL="https://ceamyckytvqemsjijavg.supabase.co/functions/v1"

# Virtual environment directory
VENV_DIR="./venv"

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

# Ensure Python venv module is available (for Linux systems)
ensure_venv() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Check if python3-venv is available
        if ! $PYTHON_CMD -m venv --help &> /dev/null; then
            log_warning "Python venv module not found. Installing python3-venv..."
            if command -v apt-get &> /dev/null; then
                # Extract Python version (e.g., python3.12)
                PYTHON_VERSION=$($PYTHON_CMD --version | awk '{print $2}' | cut -d'.' -f1-2)
                sudo apt-get update
                sudo apt-get install -y python${PYTHON_VERSION}-venv
            else
                log_error "Could not install python venv. Please install it manually."
                exit 1
            fi
        fi
    fi
}

# Setup virtual environment
setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
        log_info "Virtual environment created"
    fi
}

# Activate virtual environment and install dependencies
setup_dependencies() {
    log_info "Setting up dependencies..."
    
    # Check if venv exists and can be activated
    if [ -f "$VENV_DIR/bin/activate" ]; then
        # Activate virtual environment
        source "$VENV_DIR/bin/activate" || {
            log_warning "Could not activate virtual environment, using system Python"
        }
        VENV_PIP="$VENV_DIR/bin/pip"
    else
        log_warning "Virtual environment not fully set up, using system Python for pip"
        VENV_PIP="pip3"
    fi
    
    # Upgrade pip
    if [ -f "$VENV_DIR/bin/pip" ]; then
        "$VENV_DIR/bin/pip" install --upgrade pip > /dev/null 2>&1 || true
    else
        # Try to install pip if it's not available
        if ! command -v pip3 &> /dev/null; then
            log_warning "pip3 not found, attempting to install..."
            if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update
                    sudo apt-get install -y python3-pip
                elif command -v dnf &> /dev/null; then
                    sudo dnf install -y python3-pip
                fi
            fi
        fi
    fi
    
    # Install required packages using the appropriate pip
    log_info "Installing required Python packages..."
    if [ -f "$VENV_DIR/bin/pip" ]; then
        "$VENV_DIR/bin/pip" install requests eciespy > /dev/null 2>&1 || log_warning "Some packages could not be installed via venv pip"
    else
        pip3 install --user requests eciespy > /dev/null 2>&1 || log_warning "Some packages could not be installed"
    fi
    
    log_info "Dependencies installed successfully"
}

# Function to encrypt data with public key using ECIES
encrypt_with_public_key() {
    local public_key="$1"
    local data="$2"

    # Use the virtual environment's Python if it exists
    local PYTHON_TO_USE="$PYTHON_CMD"
    if [ -f "$VENV_DIR/bin/python3" ]; then
        PYTHON_TO_USE="$VENV_DIR/bin/python3"
    fi

    $PYTHON_TO_USE -c "
import sys
try:
    from ecies import encrypt
except ImportError:
    print('Installing required packages...', file=sys.stderr)
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'eciespy'])
    from ecies import encrypt

public_key = '$public_key'
data = '$data'

# Remove 0x prefix and convert to bytes
pub_bytes = bytes.fromhex(public_key.replace('0x', ''))

# Encrypt the data
encrypted = encrypt(pub_bytes, data.encode('utf-8'))

# Return as hex string with 0x prefix
print('0x' + encrypted.hex())
"
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

# Ensure venv module is available (Linux systems may need python3-venv installed)
echo "Checking Python venv module..."
ensure_venv

# Setup virtual environment
echo "Setting up virtual environment..."
setup_venv

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
###### Check if HOST_ID already exists in meta, if so exit ######
EXISTING_HOST_ID=$(read_meta "HOST_ID")
if [[ -n "$EXISTING_HOST_ID" ]]; then
    echo "!!!!!!! HOST_ID already exists in meta. Setup appears to be complete. Exiting."
    exit 0
fi

########################################################################
###### Create a user ######
# Check if user has already been created
CACHED_USERNAME=$(read_meta "USERNAME")

if [[ -n "$CACHED_USERNAME" ]]; then
    USERNAME="$CACHED_USERNAME"
    echo "Found existing user from cache: $USERNAME"
    # Verify the user still exists
    if id "$USERNAME" &>/dev/null; then
        echo "User $USERNAME already exists, skipping creation..."
    else
        echo "Cached user $USERNAME does not exist, creating it..."
        sudo useradd -m -s /bin/bash "$USERNAME"
    fi
else
    # Create new user with random 12-letter lowercase username
    USERNAME=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 12)
    echo "Creating new user: $USERNAME (no password)..."
    sudo useradd -m -s /bin/bash "$USERNAME"
    # Cache the username for future runs
    write_meta "USERNAME" "$USERNAME"
fi

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

# Get current timestamp in milliseconds
TIMESTAMP_SECONDS=$(date +%s)
TIMESTAMP=$((TIMESTAMP_SECONDS * 1000))

# Encrypt timestamp with SERVER_PUBLIC_KEY using ECIES
SIGNATURE=$(encrypt_with_public_key "$SERVER_PUBLIC_KEY" "$TIMESTAMP")
if [[ -z "$SIGNATURE" ]]; then
    echo "Error: Failed to encrypt timestamp"
    exit 1
fi

# Ask for host name
read -p "Enter host name (URL or IP to access via SSH): " HOST_NAME
if [[ -z "$HOST_NAME" ]]; then
    echo "Error: Host name is required"
    exit 1
fi

# Ask if cloudflared
read -p "Is this a Cloudflared host? (yes/no): " CLOUDFLARED_INPUT
if [[ "$CLOUDFLARED_INPUT" == "yes" || "$CLOUDFLARED_INPUT" == "y" ]]; then
    CLOUDFLARED="true"
else
    CLOUDFLARED="false"
fi

# Prepare API request
API_PAYLOAD=$(cat <<EOF
{
  "signature": "$SIGNATURE",
  "name": "$HOST_NAME",
  "principal": "$USERNAME",
  "cloudflared": "$CLOUDFLARED",
  "public_key": "$HOST_PUBLIC_KEY"
}
EOF
)

echo "Calling API to register host..."
API_RESPONSE=$(curl -s -X POST "$BASE_URL/host/add" \
  -H "Content-Type: application/json" \
  -d "$API_PAYLOAD")

if [[ -z "$API_RESPONSE" ]]; then
    echo "Error: Failed to call API"
    exit 1
fi

# Parse the response to get HOST_ID
HOST_ID=$(echo "$API_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('data', {}).get('id', ''))" 2>/dev/null)

if [[ -z "$HOST_ID" ]]; then
    echo "Error: Failed to get HOST_ID from API response"
    echo "API Response: $API_RESPONSE"
    exit 1
fi

# Save HOST_ID to meta
write_meta "HOST_ID" "$HOST_ID"
echo "✅ Host registered successfully!"

########################################################################
###### Restart SSH service safely ######
echo "Restarting sshd..."
sudo systemctl restart ssh

########################################################################
###### Display final info ######
echo "====================================="
echo "✅ Host setup complete!"
echo "User: $USERNAME"
echo "HOST_ID: $HOST_ID"
echo "CA Public Key saved at: $CA_DIR/rumsan_ca.pub"
echo "Custom SSH config: $RUMSAN_SSHD_CONFIG"
echo "Meta file: $META_FILE"
echo "======================================"