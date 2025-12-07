#!/bin/bash

#######################################
# Google OAuth Login Script
# This script manages Python dependencies and initiates Google OAuth login
#######################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_APP="$SCRIPT_DIR/oauth_login.py"
VENV_DIR="$SCRIPT_DIR/venv"
RUMSAN_FOLDER_PATH="$HOME/.rumsan/.ssh"
TMP_FILE_PATH="$RUMSAN_FOLDER_PATH/ssh_access.sh"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to select SSH key interactively
select_ssh_key() {
    log_info "Listing available SSH public keys in ~/.ssh:"
    
    # Get list of .pub files
    pub_files=(~/.ssh/*.pub)
    
    if [ ${#pub_files[@]} -eq 0 ]; then
        log_error "No .pub files found in ~/.ssh"
        exit 1
    fi
    
    if [ ${#pub_files[@]} -eq 1 ]; then
        selected_file="${pub_files[0]}"
        log_info "Only one SSH key found, automatically selected: $selected_file"
    else
        # Display them
        for i in "${!pub_files[@]}"; do
            echo "$((i+1)). ${pub_files[i]}"
        done
        
        # Prompt for choice
        read -p "Choose a key (1-${#pub_files[@]}): " choice
        
        if ! [[ $choice =~ ^[0-9]+$ ]] || [ $choice -lt 1 ] || [ $choice -gt ${#pub_files[@]} ]; then
            log_error "Invalid choice"
            exit 1
        fi
        
        selected_file="${pub_files[$((choice-1))]}"
        log_info "Selected: $selected_file"
    fi
    
    # Create or update temp file
    temp_file="$TMP_FILE_PATH"
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$temp_file")"
    if [ -f "$temp_file" ]; then
        # Replace the values in the existing file
        sed -i '' "s|SSH_KEY_PATH=.*|SSH_KEY_PATH=\"$selected_file\"|" "$temp_file"
        sed -i '' "s|SSH_KEY=.*|SSH_KEY=\"$(cat "$selected_file" | awk '{print $1, $2}')\"|" "$temp_file"
    else
        cat > "$temp_file" << EOF
SSH_KEY_PATH="$selected_file"
SSH_KEY="$(cat "$selected_file" | awk '{print $1, $2}')"
EOF
    fi
    
    log_info "Selected key and path saved to file: $temp_file"
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
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip > /dev/null 2>&1
    
    # Install required packages
    log_info "Installing required Python packages..."
    pip install requests > /dev/null 2>&1
    
    log_info "Dependencies installed successfully"
}

# Check and install cloudflared if not present
check_and_install_cloudflared() {
    if ! command -v cloudflared &> /dev/null; then
        log_info "Cloudflared not found. Installing..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if command -v brew &> /dev/null; then
                brew install cloudflared
            else
                log_error "Homebrew not found. Please install cloudflared manually."
                exit 1
            fi
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command -v snap &> /dev/null; then
                sudo snap install cloudflared
            elif command -v apt &> /dev/null; then
                sudo apt update && sudo apt install -y cloudflared
            else
                log_error "No supported package manager found. Please install cloudflared manually."
                exit 1
            fi
        else
            log_error "Unsupported OS for cloudflared installation. Please install manually."
            exit 1
        fi
        if command -v cloudflared &> /dev/null; then
            log_info "Cloudflared installed successfully"
        else
            log_error "Failed to install cloudflared"
            exit 1
        fi
    else
        log_info "Cloudflared is already installed"
    fi
}

# Check and kill port if in use
check_and_kill_port() {
    local PORT=29670
    
    # Check if port is in use
    if lsof -i :$PORT &> /dev/null; then
        log_warning "Port $PORT is already in use. Attempting to free it..."
        
        # Get the PID of the process using the port
        local PID=$(lsof -i :$PORT -t)
        
        if [ -n "$PID" ]; then
            log_warning "Killing process $PID..."
            kill -9 "$PID" 2>/dev/null || true
            sleep 1
            log_info "Port $PORT freed successfully"
        fi
    else
        log_info "Port $PORT is available"
    fi
}

# Main execution
main() {
    log_info "Starting Google OAuth Login..."
    
    # Create rumsan folder if it doesn't exist
    mkdir -p "$RUMSAN_FOLDER_PATH"
    
    # Select SSH key interactively
    select_ssh_key
    
    # Check and kill port if in use
    check_and_kill_port
    
    # Check and install Python if needed
    if ! check_python; then
        install_python
    fi
    
    # Setup virtual environment
    setup_venv
    
    # Setup dependencies
    setup_dependencies
    
    # Check and install cloudflared if needed
    check_and_install_cloudflared
    
    # Run the Python OAuth application
    log_info "Launching OAuth login application..."
    source "$VENV_DIR/bin/activate"
    $PYTHON_CMD "$PYTHON_APP"
    
    # SSH login using the new certificate
    log_info "Attempting SSH login with certificate..."
    if [ -f "$TMP_FILE_PATH" ]; then
        source "$TMP_FILE_PATH"
        
        json_file="$RUMSAN_FOLDER_PATH/$RS_SERVER_ID.json"
        if [ -f "$json_file" ]; then
            # Parse JSON to get hostname, principal, and cloudflared
            hostname=$(python3 -c "import json; data=json.load(open('$json_file')); print(data['hosts']['name'])")
            principal=$(python3 -c "import json; data=json.load(open('$json_file')); print(data['hosts']['principal'])")
            cloudflared=$(python3 -c "import json; data=json.load(open('$json_file')); print(data['hosts']['cloudflared'])")
            
            # Get private key path (remove .pub extension)
            private_key="${SSH_KEY_PATH%.pub}"
            
            # Certificate file path
            cert_file="$RUMSAN_FOLDER_PATH/$RS_SERVER_ID.pub"
            
            # Add to rumsan ssh_config
            config_file="$RUMSAN_FOLDER_PATH/config"
            
            if grep -q "Host $hostname" "$config_file" 2>/dev/null; then
                log_info "Removing existing SSH config entry for $hostname"
                # Escape dots in hostname for sed regex
                hostname_escaped=$(echo "$hostname" | sed 's/\./\\./g')
                sed -i '' "/^Host $hostname_escaped$/,/^$/d" "$config_file"
                # Remove trailing blank lines
                while [[ $(tail -n 1 "$config_file" 2>/dev/null | wc -l) -eq 1 ]] && [[ -z $(tail -n 1 "$config_file" 2>/dev/null) ]]; do
                    sed -i '' '$d' "$config_file"
                done
            fi
            cat >> "$config_file" << EOF

Host $hostname
  HostName $hostname
  User $principal
  IdentityFile $private_key
  CertificateFile $cert_file
EOF
            if [ "$cloudflared" = "True" ]; then
                echo "  ProxyCommand $(which cloudflared) access ssh --hostname %h" >> "$config_file"
            fi
            cat >> "$config_file" << EOF
  ServerAliveInterval 240
EOF
            log_info "Added/Updated SSH config entry for $hostname"
            
            # Add Include to ~/.ssh/config if not present
            mkdir -p "$HOME/.ssh"
            ssh_config="$HOME/.ssh/config"
            if [ ! -f "$ssh_config" ]; then
                touch "$ssh_config"
            fi
            if ! grep -q "Include $RUMSAN_FOLDER_PATH/config" "$ssh_config"; then
                log_info "Adding Include directive to $ssh_config"
                # Find the line number of the last Include statement
                last_include_line=$(grep -n "^Include " "$ssh_config" 2>/dev/null | tail -1 | cut -d: -f1)
                if [ -z "$last_include_line" ]; then
                    # No includes found, add at the top
                    echo "Include $RUMSAN_FOLDER_PATH/config" | cat - "$ssh_config" > "$ssh_config.tmp" && mv "$ssh_config.tmp" "$ssh_config"
                else
                    # Insert after the last Include line
                    sed -i '' "${last_include_line}a\\
Include $RUMSAN_FOLDER_PATH/config
" "$ssh_config"
                fi
            fi
            
            # Set appropriate permissions (only if not already set)
            if [ "$(stat -f '%OLp' "$RUMSAN_FOLDER_PATH" 2>/dev/null)" != "700" ]; then
                chmod 700 "$RUMSAN_FOLDER_PATH"
            fi
            if [ "$(stat -f '%OLp' "$RUMSAN_FOLDER_PATH/config" 2>/dev/null)" != "600" ]; then
                chmod 600 "$RUMSAN_FOLDER_PATH/config"
            fi
            
            log_info "SSH connecting to $hostname as $principal..."
            ssh_cmd="ssh -i \"$private_key\" -o CertificateFile=\"$cert_file\" -o ServerAliveInterval=240"
            if [ "$cloudflared" = "True" ]; then
                ssh_cmd="$ssh_cmd -o ProxyCommand=\"$(which cloudflared) access ssh --hostname %h\""
            fi
            ssh_cmd="$ssh_cmd \"$principal@$hostname\""
            eval "$ssh_cmd"
        else
            log_error "Certificate JSON file not found: $json_file"
        fi
    else
        log_error "Temp file not found: $TMP_FILE_PATH"
    fi
    
    deactivate 2>/dev/null || true
}

# Run main function
main "$@"
