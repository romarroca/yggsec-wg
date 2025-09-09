# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### Private Disclosure

For security vulnerabilities, please use one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the Security tab in this repository
   - Click "Report a vulnerability"
   - Fill out the private vulnerability report

2. **GitHub Direct Message**
   - Contact the maintainer via GitHub profile
   - Subject: "YggSec WireG Security Vulnerability"
   - Include detailed description and steps to reproduce

### What to Include

Please include as much information as possible:
- Type of vulnerability (RCE, privilege escalation, etc.)
- Location of the vulnerable code
- Steps to reproduce the vulnerability
- Potential impact and attack scenarios
- Any suggested fixes or mitigations

### Response Timeline

- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours  
- **Status Updates**: Weekly until resolved
- **Fix Timeline**: Critical issues within 7 days, others within 30 days

### Disclosure Policy

We follow coordinated vulnerability disclosure:

1. **Report received** → Private acknowledgment
2. **Vulnerability confirmed** → Work on fix begins
3. **Fix developed** → Testing and validation
4. **Fix released** → Public disclosure coordinated
5. **Credit given** → Security researcher credited (if desired)

## Security Best Practices

### For Users

- **Strong Passwords**: Use strong, unique passwords for admin accounts
- **Regular Updates**: Keep YggSec WireG updated to latest version
- **Network Security**: Properly configure firewall rules
- **Access Control**: Limit administrative access
- **Monitoring**: Review logs regularly for suspicious activity

### For Administrators

- **Secure Installation**: Follow installation guide security notes
- **Certificate Management**: Use proper SSL/TLS certificates
- **Backup Security**: Secure configuration backups
- **Network Segmentation**: Isolate management interfaces
- **Audit Trails**: Enable comprehensive logging

### For Developers

- **Code Review**: All changes require security review
- **Input Validation**: Validate all user inputs
- **Privilege Separation**: Follow least privilege principle
- **Secure Defaults**: Configure secure defaults
- **Dependency Management**: Keep dependencies updated

## Security Features

YggSec WireG includes several security features:

### Authentication & Authorization
- Session-based authentication with timeout
- Rate limiting on login attempts
- Secure password hashing (Werkzeug)
- Systemd process sandboxing

### Network Security
- HTTPS-only web interface
- WireGuard VPN encryption
- nftables firewall integration
- Suricata IPS for threat detection

### System Security
- Systemd service hardening
- Capability-based privilege model
- NoNewPrivileges protection
- Secure file permissions

### Input Validation
- Comprehensive input validation
- SQL injection prevention
- Command injection prevention
- Path traversal protection

## Security Hardening Guide

### Recommended Settings

```bash
# Admin password will be prompted securely during setup
# (minimum 8 characters required, longer passwords recommended)

# Enable all security features
sudo systemctl enable suricata
sudo systemctl start suricata

# Regular security updates
sudo apt update && sudo apt upgrade
sudo suricata-update
```

### Security Checklist

- [ ] Changed default admin password
- [ ] Enabled HTTPS with valid certificates
- [ ] Configured proper firewall rules
- [ ] Enabled IPS (Suricata) monitoring
- [ ] Set up log monitoring and rotation
- [ ] Restricted network access to management interface
- [ ] Regularly update system and application
- [ ] Monitor for security advisories

## Known Security Considerations

### Network Exposure
- Web interface requires careful network exposure planning
- Management interface should be restricted to trusted networks
- Consider VPN-only access for remote management

### Privilege Requirements
- Service requires network administration capabilities
- Runs with minimal required privileges via systemd
- File permissions restrict access to sensitive configurations

### Dependencies
- Relies on system-level packages (WireGuard, nftables, Suricata)
- Regular dependency updates recommended
- Monitor for CVEs in core dependencies

## Security Updates

Security updates will be:
- Released as soon as possible for critical vulnerabilities
- Announced through GitHub Security Advisories
- Documented with clear upgrade instructions
- Coordinated with vulnerability reporters

## Hall of Fame

We recognize security researchers who help improve YggSec WireG security:

<!-- Security researchers will be listed here -->

## Contact

For security-related questions or concerns:
- Security vulnerabilities: Use private disclosure methods above
- General security questions: Create a GitHub Discussion
- Security feature requests: Create a GitHub Issue with security label
- Project maintainer: Contact via GitHub profile

---

Thank you for helping keep YggSec WireG secure! 🔒