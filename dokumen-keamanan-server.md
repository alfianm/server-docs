# Dokumentasi Keamanan Server

## 1. Kebijakan Keamanan Server

### 1.1 Prinsip Utama
- **Principle of Least Privilege**: Setiap layanan hanya memiliki akses yang minimal diperlukan
- **Defense in Depth**: Multiple layers of security
- **Regular Updates**: Patch management yang konsisten
- **Monitoring**: Pemantauan 24/7 terhadap aktivitas mencurigakan

### 1.2 Kebijakan Akses
- Akses SSH hanya dengan key-based authentication
- Multi-Factor Authentication (MFA) untuk akses kritikal
- IP whitelisting untuk akses admin
- Password policy: minimal 16 karakter, complexity, rotation setiap 90 hari

## 2. Hardening Sistem Operasi (Linux)

### 2.1 Update dan Patch Management
```bash
# Update sistem secara berkala
sudo apt update && sudo apt upgrade -y
# Atau untuk CentOS/RHEL
sudo yum update -y
```

### 2.2 Konfigurasi SSH Aman
```bash
# /etc/ssh/sshd_config
Port 2222                    # Ubah dari port default 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin user1 user2
```

### 2.3 Disable Layanan Tidak Perlu
```bash
# List semua layanan yang running
systemctl list-units --type=service --state=running

# Disable layanan tidak perlu
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
```

### 2.4 Kernel Hardening
```bash
# /etc/sysctl.conf
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

# Kernel ExecShield
kernel.exec-shield = 1
kernel.randomize_va_space = 2
```

## 3. Firewall Configuration

### 3.1 UFW (Uncomplicated Firewall)
```bash
# Reset rules
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow essential services
sudo ufw allow in on eth0 to any port 2222 proto tcp # SSH on custom port
sudo ufw allow in on eth0 to any port 80 proto tcp   # HTTP
sudo ufw allow in on eth0 to any port 443 proto tcp  # HTTPS
sudo ufw allow in on eth0 to any port 53 proto udp   # DNS

# Enable firewall
sudo ufw enable
```

### 3.2 IPTABLES Rules
```bash
#!/bin/bash
# flush semua rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (from specific IPs)
iptables -A INPUT -p tcp --dport 2222 -s 192.168.1.0/24 -j ACCEPT

# Rate limiting untuk SSH
iptables -A INPUT -p tcp --dport 2222 -m limit --limit 3/min --limit-burst 3 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## 4. Intrusion Detection System

### 4.1 Install Fail2ban
```bash
sudo apt install fail2ban -y
```

### 4.2 Konfigurasi Fail2ban
```ini
# /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 2222
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

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 600
bantime = 7200
```

### 4.3 Install dan Konfigurasi AIDE
```bash
# Install AIDE
sudo apt install aide -y

# Initialize database
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check integrity
sudo aide --check

# Update database setelah ada perubahan valid
sudo aide --update
```

## 5. Monitoring dan Logging

### 5.1 Konfigurasi Rsyslog
```bash
# /etc/rsyslog.d/50-security.conf
# Log semua login attempts
auth,authpriv.* /var/log/auth.log

# Log sudo usage
auth,authpriv.* /var/log/sudo.log

# Log firewall events
kern.* /var/log/kern.log

# Forward logs ke central log server (opsional)
*.* @@logserver.example.com:514
```

### 5.2 Script Monitoring Keamanan
```bash
#!/bin/bash
# /usr/local/bin/security-monitor.sh

# Log file
LOG_FILE="/var/log/security-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Fungsi logging
log_event() {
    echo "[$DATE] $1" >> $LOG_FILE
}

# Cek login attempts
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
if [ $FAILED_LOGINS -gt 10 ]; then
    log_event "WARNING: High number of failed login attempts: $FAILED_LOGINS"
fi

# Cek perubahan file sistem
/usr/bin/aide --check > /tmp/aide_check.txt 2>&1
if [ $? -ne 0 ]; then
    log_event "CRITICAL: File integrity check failed!"
    cat /tmp/aide_check.txt >> $LOG_FILE
fi

# Cek port terbuka
OPEN_PORTS=$(netstat -tuln | grep LISTEN)
log_event "Open ports: $OPEN_PORTS"

# Cek proses mencurigakan
SUSPICIOUS_PROCS=$(ps aux | grep -E '(nc|netcat|python.*socket|bash.*tcp)' | grep -v grep)
if [ ! -z "$SUSPICIOUS_PROCS" ]; then
    log_event "WARNING: Suspicious processes detected: $SUSPICIOUS_PROCS"
fi

# Cek disk usage
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    log_event "WARNING: High disk usage: ${DISK_USAGE}%"
fi
```

### 5.3 Cron Job untuk Monitoring
```bash
# Tambahkan ke crontab
# crontab -e
# Monitoring setiap 5 menit
*/5 * * * * /usr/local/bin/security-monitor.sh
# Full scan AIDE setiap hari jam 3 pagi
0 3 * * * /usr/bin/aide --check >> /var/log/aide-daily.log 2>&1
```

## 6. Backup dan Recovery

### 6.1 Kebijakan Backup
- Daily backup untuk data kritikal
- Weekly full system backup
- Backup storage offsite
- Enkripsi backup dengan GPG
- Test restore bulanan

### 6.2 Script Backup
```bash
#!/bin/bash
# /usr/local/bin/secure-backup.sh

BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
GPG_RECIPIENT="admin@company.com"

# Buat backup direktori penting
tar -czf - /etc /home /var/www /var/log 2>/dev/null | \
gpg --trust-model always --encrypt -r $GPG_RECIPIENT -o $BACKUP_DIR/system_$DATE.tar.gpg

# Backup database
mysqldump --single-transaction --all-databases | \
gpg --trust-model always --encrypt -r $GPG_RECIPIENT -o $BACKUP_DIR/db_$DATE.sql.gpg

# Hapus backup lama (30 hari)
find $BACKUP_DIR -name "*.gpg" -mtime +30 -delete

# Sync ke offsite server
rsync -avz --delete $BACKUP_DIR/ backup@remote-server:/backups/
```

## 7. Security Checklist

### 7.1 Installasi Awal
- [ ] Minimal OS installation
- [ ] Update semua packages
- [ ] Configure timezone
- [ ] Setup hostname
- [ ] Create user accounts dengan permission minimal

### 7.2 Network Security
- [ ] Configure firewall (deny by default)
- [ ] Disable IPv6 jika tidak digunakan
- [ ] Configure network interface security
- [ ] Setup VPN untuk remote access
- [ ] Disable wireless jika tidak digunakan

### 7.3 Service Security
- [ ] Remove unnecessary packages
- [ ] Configure SSH securely
- [ ] Disable unnecessary services
- [ ] Configure service-specific security
- [ ] Implement rate limiting

### 7.4 File System Security
- [ ] Configure proper file permissions
- [ ] Implement immutable bit untuk critical files
- [ ] Setup disk quota
- [ ] Configure /tmp dengan noexec,nosuid
- [ ] Implement file integrity monitoring

### 7.5 Application Security
- [ ] Install aplikasi dari trusted sources
- [ ] Configure aplikasi dengan minimal privileges
- [ ] Regular patch management
- [ ] Input validation
- [ ] Error handling yang aman

### 7.6 Monitoring dan Logging
- [ ] Configure centralized logging
- [ ] Setup alert system
- [ ] Regular security scans
- [ ] Log rotation dan retention policy
- [ ] Incident response plan

## 8. Incident Response

### 8.1 Langkah-langkah saat terjadi insiden:
1. **Identifikasi**: Deteksi anomali melalui monitoring
2. **Containment**: Isolasi sistem yang terkena
3. **Eradication**: Hapus malware dan patch vulnerabilities
4. **Recovery**: Restore dari backup yang bersih
5. **Lessons Learned**: Dokumentasikan dan perbaiki proses

### 8.2 Kontak Darurat
- Security Team: [Nomor telepon/email]
- Management: [Nomor telepon/email]
- ISP Provider: [Nomor kontak]
- Legal Counsel: [Nomor kontak]

## 9. Security Tools Recommended

### 9.1 Open Source Tools
- **OSSEC**: Host-based intrusion detection
- **OpenVAS**: Vulnerability scanning
- **Lynis**: Security auditing
- **ClamAV**: Antivirus
- **Tripwire**: File integrity monitoring

### 9.2 Paid Solutions
- **CrowdStrike**: Endpoint protection
- **Palo Alto**: Network security
- **Qualys**: Cloud security
- **Tenable**: Vulnerability management

## 10. Regular Maintenance

### 10.1 Harian
- Review system logs
- Check backup completion
- Monitor resource usage
- Review security alerts

### 10.1 Mingguan
- Update patches
- Review user access
- Security scan
- Backup test restore

### 10.3 Bulanan
- Full security audit
- Password rotation
- Review firewall rules
- Update documentation

### 10.4 Tahunan
- Penetration testing
- Security training
- Policy review
- Disaster recovery test