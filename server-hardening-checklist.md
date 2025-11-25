#!/bin/bash

# Server Hardening Script
# Usage: sudo bash harden-server.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/server-hardening.log"
BACKUP_DIR="/root/hardening-backup-$(date +%Y%m%d)"

# Function to log messages
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

log "Starting server hardening process..."
log "Backup directory: $BACKUP_DIR"

# Function to backup file
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$BACKUP_DIR/${1//\//-}-$(date +%H%M%S).bak"
        log "Backed up $1"
    fi
}

# 1. System Update
log "Step 1: Updating system packages"
backup_file "/etc/apt/sources.list"
apt-get update && apt-get upgrade -y
apt-get install -y ufw fail2ban aide rkhunter lynis

# 2. SSH Hardening
log "Step 2: Hardening SSH configuration"
SSH_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSH_CONFIG"

# Change SSH port to random port
SSH_PORT=$(shuf -i 2222-65535 -n 1)

# Modify SSH config
sed -i "s/#Port 22/Port $SSH_PORT/" "$SSH_CONFIG"
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' "$SSH_CONFIG"
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' "$SSH_CONFIG"

# Add additional SSH security settings
cat >> "$SSH_CONFIG" << EOF

# Additional security settings
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers ubuntu
Protocol 2
IgnoreRhosts yes
HostbasedAuthentication no
RhostsRSAAuthentication no
 PermitUserEnvironment no
EOF

log "SSH port changed to: $SSH_PORT"
log "Restarting SSH service..."
systemctl restart sshd

# 3. Firewall Configuration
log "Step 3: Configuring firewall"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in "$SSH_PORT"/tcp
ufw allow in 80/tcp
ufw allow in 443/tcp
ufw --force enable

# 4. System Hardening
log "Step 4: Applying system hardening"

# Kernel parameters
SYSCTL_CONF="/etc/sysctl.conf"
backup_file "$SYSCTL_CONF"

cat >> "$SYSCTL_CONF" << EOF

# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Filesystem Security
fs.protected_regular = 1
fs.protected_fifos = 1
fs.suid_dumpable = 0

# Kernel Security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

# Apply sysctl settings
sysctl -p

# 5. Disable unnecessary services
log "Step 5: Disabling unnecessary services"
systemctl disable bluetooth 2>/dev/null || true
systemctl disable cups 2>/dev/null || true
systemctl disable avahi-daemon 2>/dev/null || true
systemctl disable rpcbind 2>/dev/null || true

# 6. Configure Fail2ban
log "Step 6: Configuring Fail2ban"
FAIL2BAN_LOCAL="/etc/fail2ban/jail.local"
backup_file "$FAIL2BAN_LOCAL"

cat > "$FAIL2BAN_LOCAL" << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 7. Configure AIDE
log "Step 7: Configuring AIDE"
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# 8. Configure rkhunter
log "Step 8: Configuring rkhunter"
RKHUNTER_CONF="/etc/rkhunter.conf"
backup_file "$RKHUNTER_CONF"

# Update rkhunter
rkhunter --update --sk

# 9. File permissions
log "Step 9: Setting secure file permissions"
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/ssh/sshd_config
chmod 640 /etc/sudoers

# 10. Create security monitoring script
log "Step 10: Creating security monitoring script"
cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash

LOG_FILE="/var/log/security-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

log_event() {
    echo "[$DATE] $1" >> $LOG_FILE
}

# Check failed logins
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    log_event "WARNING: High number of failed login attempts: $FAILED_LOGINS"
fi

# Check for new user accounts
NEW_USERS=$(grep "new user" /var/log/auth.log | tail -5)
if [ ! -z "$NEW_USERS" ]; then
    log_event "INFO: New user accounts created: $NEW_USERS"
fi

# Check disk usage
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    log_event "WARNING: High disk usage: ${DISK_USAGE}%"
fi

# Check running processes
SUSPICIOUS_PROCS=$(ps aux | grep -E '(nc|netcat|python.*socket|bash.*tcp)' | grep -v grep)
if [ ! -z "$SUSPICIOUS_PROCS" ]; then
    log_event "WARNING: Suspicious processes detected: $SUSPICIOUS_PROCS"
fi
EOF

chmod +x /usr/local/bin/security-monitor.sh

# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/security-monitor.sh") | crontab -

# 11. Install logrotate configuration
log "Step 11: Configuring log rotation"
cat > /etc/logrotate.d/security << 'EOF'
/var/log/security-monitor.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
}
EOF

# 12. Clean up
log "Step 12: Cleaning up"
apt-get autoremove -y
apt-get autoclean

# 13. Generate summary report
log "Step 13: Generating security report"
cat > /root/security-hardening-report.txt << EOF
Server Security Hardening Report
Generated: $(date)

System Information:
- Hostname: $(hostname)
- OS: $(lsb_release -d | cut -f2)
- Kernel: $(uname -r)

Changes Made:
1. SSH Port: Changed to $SSH_PORT
2. Firewall: UFW enabled with restrictive rules
3. Password Authentication: Disabled for SSH
4. Root Login: Disabled via SSH
5. Fail2ban: Configured and enabled
6. AIDE: Initial database created
7. Kernel Parameters: Hardened
8. Unnecessary Services: Disabled
9. File Permissions: Secured
10. Security Monitoring: Automated script installed

Important Notes:
- SSH is now running on port $SSH_PORT
- SSH key authentication is required
- All changes have been backed up to $BACKUP_DIR
- Monitor /var/log/security-monitor.log for security events
- Run 'aide --check' regularly to verify file integrity
- Run 'rkhunter --check --sk' for rootkit detection

Next Steps:
1. Create SSH keys for all users
2. Configure backup system
3. Set up centralized logging
4. Schedule regular security scans
5. Document and test incident response plan
EOF

log "Server hardening completed successfully!"
log "Report saved to: /root/security-hardening-report.txt"
log "Please reboot the system to apply all changes"

# Display final message
echo ""
echo -e "${GREEN}===========================================${NC}"
echo -e "${GREEN}  SERVER HARDENING COMPLETED!${NC}"
echo -e "${GREEN}===========================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT CHANGES:${NC}"
echo "• SSH Port: $SSH_PORT"
echo "• Password authentication: DISABLED"
echo "• Root login: DISABLED"
echo "• Firewall: ENABLED"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo "1. Create SSH keys for all users"
echo "2. Test SSH connection with new port"
echo "3. Configure your firewall to allow port $SSH_PORT"
echo "4. Review the report at /root/security-hardening-report.txt"
echo ""
echo -e "${YELLOW}BACKUP LOCATION:${NC} $BACKUP_DIR"
echo ""