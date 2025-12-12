# Rumsan SSH Server Setup

This document explains the three server-side scripts that work together to set up and maintain a secure SSH Certificate Authority (CA) based authentication system for host machines.

## Overview

The Rumsan SSH setup consists of three interconnected scripts that automate the process of:
1. **Downloading and installing** the setup scripts from GitHub
2. **Configuring SSH CA authentication** on the host machine
3. **Maintaining host availability** through periodic health checks (pings)

## Scripts and Their Relationship

```
┌─────────────────────────────────────────────────────────────────┐
│                    rumsan-ssh-server.sh                         │
│  (Bootstrap Script - Downloads and orchestrates other scripts)  │
└───────────────────┬─────────────────────────────────────────────┘
                    │
                    │ Downloads and executes
                    │
                    ├──────────────────────────────┬───────────────┐
                    │                              │               │
                    ▼                              ▼               ▼
    ┌───────────────────────────┐  ┌────────────────────┐  ┌──────────────┐
    │   rs_setup_server.sh      │  │     ping.sh        │  │  Cron Job    │
    │  (One-time Setup)         │  │  (Health Check)    │  │  (Schedule)  │
    └───────────────────────────┘  └────────────────────┘  └──────────────┘
                    │                              ▲               │
                    │ Generates                    │               │
                    │ - Private/Public Keys        │               │
                    │ - SSH Config                 │               │
                    │ - Meta & Cache Files         │               │
                    │                              │               │
                    └──────────────────────────────┴───────────────┘
                           Reads from /etc/ssh/rumsan/
```

---

## 1. rumsan-ssh-server.sh

**Purpose**: Bootstrap script that downloads, installs, and orchestrates the entire SSH server setup.

### What It Does

1. **Downloads Scripts**: Fetches the latest versions of `rs_setup_server.sh` and `ping.sh` from GitHub
2. **Version Control**: Checks for updates using Git commit hash and only downloads if changes are detected
3. **Creates Directory Structure**: Sets up the `_rumsan-ssh-server` working directory
4. **Schedules Health Checks**: Configures a cron job to run `ping.sh` every 30 minutes
5. **Executes Setup**: Automatically runs `rs_setup_server.sh` to perform initial configuration

### Usage

```bash
# Quick start (download and run)
curl -fsSL https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main/server/rumsan-ssh-server.sh -o rumsan-ssh-server.sh && chmod +x rumsan-ssh-server.sh && ./rumsan-ssh-server.sh
```

### Key Features

- **Smart Updates**: Only downloads files when repository changes are detected
- **Automatic Cron Setup**: Ensures health checks run continuously without manual intervention
- **Idempotent**: Safe to run multiple times - won't duplicate cron jobs or downloads

### Output Files

- `_rumsan-ssh-server/.latest_commit`: Stores the current Git commit hash for version tracking
- Cron job: `*/30 * * * * /path/to/ping.sh`

---

## 2. rs_setup_server.sh

**Purpose**: Comprehensive one-time setup script that configures SSH CA authentication on the host machine.

### What It Does

1. **System Setup**
   - Checks and installs Python 3 if needed
   - Installs required dependencies (`requests`, `eciespy`, `coincurve`, `eth-keys`)
   
2. **CA Configuration**
   - Downloads the Rumsan CA public key from GitHub
   - Creates SSH configuration files at `/etc/ssh/rumsan/`
   - Updates `/etc/ssh/sshd_config` to trust the CA

3. **Key Generation**
   - Generates secp256k1 (Ethereum-style) private/public key pair for the host
   - Stores keys securely in meta file

4. **Host Registration**
   - Prompts for host information (hostname, user, cloudflared status)
   - Encrypts and signs data using ECIES and ECDSA
   - Registers host with the Rumsan API
   - Caches host information locally for future pings

5. **SSH Service**
   - Restarts SSH daemon to apply new configuration

### Usage

```bash
# Run directly (typically called by rumsan-ssh-server.sh)
./rs_setup_server.sh
```

### Interactive Prompts

During execution, you'll be asked to:
1. **Choose User**: Create a new user or use an existing one
2. **Host Name**: Enter the hostname or IP address
3. **Cloudflared**: Specify if this is a Cloudflare Tunnel host (yes/no)

### Key Files Created

```
/etc/ssh/rumsan/
├── rumsan_ca.pub              # CA public key for certificate validation
├── rumsan_sshd_config         # SSH daemon configuration snippet
├── meta.sh                    # Stores configuration (keys, settings)
└── hosts.json                 # Cache of registered hosts
```

### Meta File Structure

The `meta.sh` file stores:
- `HOST_PRIVATE_KEY`: secp256k1 private key (0x-prefixed hex)
- `HOST_PUBLIC_KEY`: Compressed public key (0x-prefixed hex)
- `HOST_NAME`: Hostname or IP address
- `CLOUDFLARED`: Boolean (true/false)
- `SERVER_PUBLIC_KEY`: API server's public key
- `SERVER_COMPRESSED_KEY`: API server's compressed key
- `SERVER_ETH_ADDRESS`: API server's Ethereum address

### Hosts Cache Structure

The `hosts.json` file contains:
```json
[
  {
    "username": "user1",
    "host_id": "uuid-from-api",
    "is_sudo": true,
    "created_at": "2025-12-12T10:00:00",
    "updated_at": "2025-12-12T10:00:00"
  }
]
```

---

## 3. ping.sh

**Purpose**: Periodic health check script that notifies the Rumsan API that the host is alive and accessible.

### What It Does

1. **Dependency Check**: Ensures Python packages (`coincurve`, `eth-keys`) are installed
2. **Read Configuration**: Loads `HOST_PRIVATE_KEY` from meta file
3. **Read Hosts**: Parses all registered hosts from `hosts.json`
4. **Generate Signatures**: For each host:
   - Creates a timestamp (in milliseconds)
   - Signs the timestamp with the host's private key using ECDSA
5. **Send Pings**: Posts signed data to the API endpoint `/host/ping`
6. **Report Results**: Displays success/failure summary

### Usage

```bash
# Manual execution
./ping.sh

# Automatic execution (via cron)
# Runs every 30 minutes (set up by rumsan-ssh-server.sh)
```

### API Communication

**Endpoint**: `POST /host/ping`

**Payload**:
```json
{
  "signature": "0x...",
  "timestamp": "1702380000000",
  "host_id": "uuid-from-registration"
}
```

### Exit Codes

- `0`: All pings successful
- `1`: One or more pings failed or configuration missing

### Output Example

```
[INFO] Setting up dependencies...
[INFO] Reading hosts from /etc/ssh/rumsan/hosts.json
[INFO] Pinging host: example.com (user1) with ID: abc-123
[SUCCESS] Ping sent successfully for [example.com]

[SUMMARY] Total hosts: 1
[SUMMARY] Successful pings: 1
[SUMMARY] Failed pings: 0
```

---

## System Requirements

### Operating Systems
- **Linux**: Ubuntu, Debian, Fedora, RHEL, Arch
- **macOS**: 10.13+ (with Homebrew recommended)

### Dependencies
- **Python 3**: Auto-installed if missing
- **pip3**: Auto-installed if missing
- **curl**: Required for API communication
- **jq**: Optional (fallback to Python if not available)
- **openssl**: For key generation
- **sudo**: Required for system-level configurations

### Python Packages (Auto-installed)
- `requests`: HTTP client
- `eciespy`: Elliptic Curve Integrated Encryption Scheme
- `coincurve`: secp256k1 cryptography
- `eth-keys`: Ethereum-style key handling

---

## Security Architecture

### Key Types
- **CA Public Key**: Downloaded from GitHub, used to validate SSH certificates
- **Host Private/Public Key**: secp256k1 pair, unique per host
- **Server Public Key**: Retrieved from API, used for ECIES encryption

### Cryptographic Operations
1. **Registration**: Data encrypted with server's public key using ECIES
2. **Health Checks**: Timestamp signed with host's private key using ECDSA (Ethereum-compatible)

### File Permissions
- `/etc/ssh/rumsan/`: `755` (readable/executable by all, writable by root)
- `meta.sh`: `644` (readable by all, writable by root)
- `hosts.json`: `644` (readable by all, writable by root)
- CA public key: `644` (readable by all, writable by root)

---

## Workflow: Complete Setup Process

### First-Time Installation

1. **Run Bootstrap Script**
   ```bash
   ./rumsan-ssh-server.sh
   ```

2. **Automatic Actions**
   - Downloads latest `rs_setup_server.sh` and `ping.sh`
   - Sets up cron job for pings every 30 minutes
   - Executes `rs_setup_server.sh`

3. **User Interaction** (via `rs_setup_server.sh`)
   - Answer prompts about user, hostname, cloudflared

4. **System Configuration**
   - Python and dependencies installed
   - SSH CA trust configured
   - Keys generated and stored
   - Host registered with API

5. **Ongoing Maintenance**
   - Cron job executes `ping.sh` every 30 minutes
   - Host status continuously updated with API

### Subsequent Runs

- If you run `rumsan-ssh-server.sh` again:
  - Checks for updates (downloads only if commit hash changed)
  - Skips setup if host is already registered (cached in `hosts.json`)
  - Updates cron job if not present

---

## Troubleshooting

### Common Issues

**1. Python Installation Fails**
```bash
# Manually install Python
# macOS:
brew install python3

# Ubuntu/Debian:
sudo apt-get update && sudo apt-get install -y python3 python3-pip

# Fedora/RHEL:
sudo dnf install -y python3 python3-pip
```

**2. Permission Denied**
```bash
# Ensure scripts are executable
chmod +x rumsan-ssh-server.sh rs_setup_server.sh ping.sh
```

**3. Cron Job Not Running**
```bash
# Check cron logs
sudo crontab -l | grep ping.sh

# Manually test ping
./ping.sh
```

**4. API Connection Failures**
- Verify internet connectivity
- Check firewall rules
- Ensure the API endpoint is accessible: `https://ceamyckytvqemsjijavg.supabase.co/functions/v1`

**5. SSH Service Restart Issues**
```bash
# Check SSH service status
sudo systemctl status ssh    # Ubuntu/Debian
sudo systemctl status sshd   # Fedora/RHEL/macOS

# Validate SSH config
sudo sshd -t
```

---

## API Endpoints

### Base URL
```
https://ceamyckytvqemsjijavg.supabase.co/functions/v1
```

### Endpoints Used

1. **GET /host/public-key**
   - Retrieves server's public key for encryption
   - Returns: `publicKey`, `compressedKey`, `ethAddress`

2. **POST /host/add**
   - Registers a new host
   - Payload: `signature`, `name`, `principal`, `cloudflared`, `public_key`, `is_sudo`
   - Returns: `host_id`

3. **POST /host/ping**
   - Health check for registered host
   - Payload: `signature`, `timestamp`, `host_id`
   - Returns: Success/error status

---

## File Locations Summary

| File | Location | Purpose |
|------|----------|---------|
| `rumsan-ssh-server.sh` | Downloaded location | Bootstrap script |
| `rs_setup_server.sh` | `_rumsan-ssh-server/` | Setup script |
| `ping.sh` | `_rumsan-ssh-server/` | Health check script |
| CA Public Key | `/etc/ssh/rumsan/rumsan_ca.pub` | Certificate validation |
| SSH Config | `/etc/ssh/rumsan/rumsan_sshd_config` | SSH daemon settings |
| Meta File | `/etc/ssh/rumsan/meta.sh` | Configuration storage |
| Hosts Cache | `/etc/ssh/rumsan/hosts.json` | Registered hosts |
| Commit Hash | `_rumsan-ssh-server/.latest_commit` | Version tracking |

---

## Maintenance

### Updating Scripts
```bash
# Re-run bootstrap to check for updates
./rumsan-ssh-server.sh
```

### Viewing Logs
```bash
# Check cron logs
grep CRON /var/log/syslog  # Ubuntu/Debian
grep CRON /var/log/cron    # Fedora/RHEL

# Check SSH logs
sudo tail -f /var/log/auth.log  # Ubuntu/Debian
sudo tail -f /var/log/secure    # Fedora/RHEL
```

### Removing Setup
```bash
# Remove cron job
sudo crontab -l | grep -v ping.sh | sudo crontab -

# Remove configuration
sudo rm -rf /etc/ssh/rumsan

# Remove Include from sshd_config
sudo sed -i '/Include.*rumsan_sshd_config/d' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh
```

---

## Support

For issues or questions:
- Repository: https://github.com/santosh-rumsan/rumsan-ssh-setup
- Check the scripts for inline comments and error messages
- Review logs at `/var/log/syslog` or `/var/log/auth.log`
