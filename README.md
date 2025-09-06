# YggSec-WG

A modern, secure WireGuard VPN management platform with built-in firewall and intrusion prevention system (IPS) capabilities.

<img width="1937" height="1354" alt="image" src="https://github.com/user-attachments/assets/9506d7b3-4a28-440d-8f1f-44c707568fb0" />

*Main dashboard showing WireGuard peers and network topology*

## Features

- **Secure WireGuard Management** - Web-based configuration and monitoring
- **Integrated Firewall** - nftables-based traffic control with GUI management
- **Intrusion Prevention** - Suricata IPS integration with real-time alerts
- **Network Monitoring** - Connection tracking and bandwidth usage
- **Hub & Spoke Topology** - Centralized VPN architecture with peer-to-peer communication
- **Dark/Light Theme** - Modern responsive web interface
- **Security Hardened** - CSRF protection, rate limiting, secure sessions
- **QR Code Support** - Mobile client configuration via QR codes

<img width="1934" height="1350" alt="image" src="https://github.com/user-attachments/assets/cec07991-f973-4f74-8fc1-786121dbdeb1" />


*Firewall rules management interface Dark Mode*

## Requirements

### System Requirements
- **OS**: Ubuntu 20.04+ / Debian 11+ (systemd required)
- **RAM**: Minimum 1GB (2GB+ recommended for IPS)
- **Storage**: 2GB+ free space
- **Network**: Root access for network configuration

### Package Dependencies

The installation script will automatically install these packages:

#### Core Dependencies
- `python3-venv` - Python virtual environment
- `python3-pip` - Python package manager
- `wireguard-tools` - WireGuard VPN utilities
- `nftables` - Modern Linux firewall
- `nginx` - Reverse proxy and TLS termination
- `openssl` - SSL/TLS certificates

#### Network & Monitoring
- `netplan.io` - Network configuration management
- `iputils-ping` - Network connectivity testing
- `net-tools` - Network utilities
- `conntrack` - Connection tracking tools

#### Security & IPS
- `suricata` - Intrusion Prevention System
- `suricata-update` - Signature updates

#### System Tools
- `rsync` - File synchronization
- `jq` - JSON processing
- `openssh-client` - SSH client utilities
- `openssh-server` - SSH server (optional)

## Installation

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/yggsec-wg.git
cd yggsec-wg
```

2. **Run the installation script:**
```bash
sudo ./scripts/init.sh
```

3. **Follow the interactive prompts:**
   - Select network interfaces (WAN/LAN)
   - Choose DHCP or static IP configuration
   - Configure optional LAN interface

<img width="1999" height="603" alt="image" src="https://github.com/user-attachments/assets/37f8d664-822a-49e1-84b1-48828167605a" />

*Interactive installation interface selection*

### Manual Installation Options

You can also specify custom installation directory:
```bash
sudo ./scripts/init.sh /custom/path/yggsec
```

## Permissions & Security Changes

The installation process makes several system-level changes for security and functionality:

### User & Group Creation
- Creates dedicated `yggsec` user (non-login shell)
- Restricts file access to application directories only

### Directory Structure & Permissions
```bash
/opt/yggsec/           # Application root (755, yggsec:yggsec)
├── keys/              # WireGuard private keys (700, yggsec:yggsec)
├── configs/           # Generated configurations (750, yggsec:yggsec)
├── templates/         # Web interface templates
├── static/           # CSS/JS assets
└── venv/             # Python virtual environment
```

### Network Capabilities
The service runs with minimal Linux capabilities:
- `CAP_NET_ADMIN` - Network interface management
- `CAP_NET_RAW` - Raw socket access for WireGuard
- `NoNewPrivileges=true` - Prevents privilege escalation

### Sudo Privileges
Limited sudo access for the `yggsec` user:
```bash
# /etc/sudoers.d/yggsec
yggsec ALL=(root) NOPASSWD: \
/usr/bin/wg, /usr/bin/wg-quick, /usr/sbin/ip, \
/usr/sbin/nft, /usr/bin/systemctl start suricata, \
/usr/bin/systemctl stop suricata, /usr/bin/systemctl restart suricata, \
/usr/bin/suricata-update
```

### Firewall Configuration
- Creates persistent nftables configuration in `/etc/nftables.d/`
- Opens ports 80/443 for web interface access
- Configures WireGuard port (51820/udp) if needed

### SSL/TLS Certificates
- Generates self-signed certificates for HTTPS
- Stored in `/etc/nginx/ssl/` with proper permissions (600/644)

![Security Configuration](screenshots/security.png)
*Security settings and capability configuration*

## Post-Installation Setup

### 1. Factory Reset (First Time Setup)

After installation, initialize the system:

```bash
sudo ADMIN_USERNAME=administrator ADMIN_PASSWORD=your_secure_password \
  /opt/yggsec/venv/bin/python /opt/yggsec/scripts/yggsec_setup.py factory-reset-all
```

This will:
- Create admin user account
- Initialize WireGuard topology
- Generate hub configuration
- Start all services

### 2. Access Web Interface

Navigate to your server's IP address:
- **HTTPS**: `https://your-server-ip`
- **Login**: Use the admin credentials you set

<img width="1618" height="1354" alt="image" src="https://github.com/user-attachments/assets/ac00c024-19a4-40df-a4cf-f8765f359fa7" />

*Secure login interface*

### 3. Add VPN Peers

1. Click "Add Spoke" in the web interface
2. Enter peer name and optional LAN subnet
3. Download configuration or scan QR code
4. Configure client device

<img width="1509" height="854" alt="image" src="https://github.com/user-attachments/assets/8d77c03e-1f9e-4c32-b5a7-d586ab256aae" />

*VPN peer configuration and QR code generation*

## Management Commands

### Service Control
```bash
# Check service status
sudo systemctl status yggsec

# View logs
sudo journalctl -u yggsec -f

# Restart service
sudo systemctl restart yggsec
```

### Admin Management
```bash
# Reset admin password only
sudo ADMIN_USERNAME=admin ADMIN_PASSWORD=newpassword \
  /opt/yggsec/venv/bin/python /opt/yggsec/scripts/yggsec_setup.py factory-reset

# Full factory reset (wipes all data)
sudo /opt/yggsec/venv/bin/python /opt/yggsec/scripts/yggsec_setup.py factory-reset-all
```

### WireGuard Operations
```bash
# Manual WireGuard control
sudo wg show
sudo systemctl status wg-quick@wg0

# Regenerate configurations
# Use web interface "Regenerate Configs" button
```

## Network Architecture

```
[Spoke Clients] ←→ [Internet] ←→ [WireGuard Hub]←→ [Firewall/IPS] ←→ [LAN]
                                       ↓
                                 [Web Interface]
```

- **Hub-and-Spoke**: All traffic routes through central hub
- **Firewall Integration**: nftables rules control inter-peer communication
- **IPS Protection**: Suricata monitors and blocks threats
- **Web Management**: Secure HTTPS interface for configuration

![Network Topology](screenshots/topology.png)
*Network architecture and traffic flow*

## Monitoring & Alerts

### Real-time Monitoring
- Connection status with ping testing
- Bandwidth usage tracking
- Active connection monitoring
- Firewall rule hit counters

<img width="1929" height="1347" alt="image" src="https://github.com/user-attachments/assets/71414d7e-2736-4fd2-842c-d332667dfff2" />



### Intrusion Prevention
- Real-time Suricata alerts
- Threat signature updates
- Traffic analysis and blocking
- Event logging and retention

<img width="1932" height="1353" alt="image" src="https://github.com/user-attachments/assets/bb319145-d333-4a9f-bf55-059f44277204" />

*Real-time network monitoring and IPS alerts*

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check system logs
sudo journalctl -u yggsec -n 50

# Verify permissions
sudo /opt/yggsec/scripts/permission.sh
```

**Web interface inaccessible:**
```bash
# Check nginx status
sudo systemctl status nginx

# Verify firewall rules
sudo nft list ruleset
```

**WireGuard not connecting:**
```bash
# Check WireGuard status
sudo wg show
sudo systemctl status wg-quick@wg0

# Regenerate configs via web interface
```

**IPS alerts not showing:**
```bash
# Check Suricata status  
sudo systemctl status suricata

# Update signatures
sudo suricata-update
```

## Security Considerations

- Change default admin password immediately
- Use strong passwords for all accounts
- Regularly update Suricata signatures
- Monitor system logs for anomalies
- Keep the system updated with security patches
- Configure proper firewall rules for your network

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Open an issue on GitHub
- Check the troubleshooting section above
- Review system logs for error messages

---

**⚠️ Important**: This software manages network security infrastructure. Always test in a non-production environment first and ensure you have alternative access methods before deploying in production.
