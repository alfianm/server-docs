# Dokumentasi Keamanan Server Lengkap

## 📚 Daftar Isi

1. [Pengantar](#pengantar)
2. [Struktur File](#struktur-file)
3. [Instalasi dan Konfigurasi](#instalasi-dan-konfigurasi)
4. [Panduan Pemakaian](#panduan-pemakaian)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)
7. [Maintenance Schedule](#maintenance-schedule)

## 🚀 Pengantar

Dokumentasi ini menyediakan solusi keamanan server yang komprehensif dengan fitur-fitur:

- **Hardening sistem operasi** dengan otomasi
- **Firewall management** dengan UFW dan IPTABLES
- **Real-time security monitoring** dengan alerting
- **Threat detection** dan malware scanning
- **Automated response** untuk insiden keamanan
- **Comprehensive reporting** dan analytics

## 📁 Struktur File

Setelah instalasi, Anda akan memiliki file-file berikut:

```
/var/www/
├── dokumen-keamanan-server.md      # Dokumen kebijakan lengkap
├── server-hardening-checklist.md   # Script otomasi hardening
├── firewall-config.sh             # Konfigurasi firewall
├── security-monitoring-suite.sh   # Suite monitoring keamanan
└── README-Keamanan-Server.md      # Dokumentasi ini (file ini)

/etc/
├── security-monitor/              # Konfigurasi monitoring
│   ├── config.json               # File konfigurasi utama
│   └── malicious-ips.txt         # List IP berbahaya
└── firewall/                      # Konfigurasi firewall
    ├── allowed-ips.txt           # IP yang diizinkan
    └── blocked-ips.txt           # IP yang diblokir

/usr/local/bin/
├── security-monitoring-suite     # Main monitoring script
├── firewall-monitor.sh           # Monitoring firewall
├── allow-ip.sh                   # Script untuk allow IP
└── block-ip.sh                   # Script untuk block IP

/var/log/
├── security-monitor/             # Log monitoring
│   ├── monitor.log              # Log utama
│   └── daily-report-*.html      # Laporan harian
└── firewall-setup.log           # Log setup firewall
```

## ⚙️ Instalasi dan Konfigurasi

### Prasyarat

- Server dengan OS Linux (Ubuntu/Debian/CentOS/RHEL)
- Akses root atau sudo
- Koneksi internet untuk install dependencies

### Langkah 1: Download dan Setup

```bash
# Download semua file ke server
wget https://example.com/security-files.tar.gz
# wget: Download file dari URL
# -q (quiet): Suppress output (opsional)

tar -xzf security-files.tar.gz
# tar: Tape archive utility
# -x: Extract files dari archive
# -z: Filter archive melalui gzip (decompress)
# -f: Use archive file (security-files.tar.gz)

cd /var/www
# cd: Change directory ke /var/www
# Biasanya document root untuk web server

# Buat file executable
chmod +x *.sh
# chmod: Change file permissions
# +x: Add execute permission
# *.sh: Wildcard untuk semua file dengan ekstensi .sh
# Membuat semua shell scripts bisa dieksekusi
```

### Langkah 2: Server Hardening

```bash
# Jalankan script hardening
sudo bash server-hardening-checklist.md
# sudo: Execute command dengan superuser privileges
# bash: Execute script dengan bash interpreter
# server-hardening-checklist.md: File script yang akan dieksekusi
# ⚠️ PENTING: Pastikan SSH keys sudah disetup sebelum menjalankan script ini!
```

**Apa yang dilakukan script ini:**
- Update sistem
- Configure SSH dengan port dinamis
- Setup firewall dasar
- Disable service tidak perlu
- Install security tools (fail2ban, aide, rkhunter)
- Create user accounts dengan permission minimal

⚠️ **PENTING:** Catat SSH port baru yang di-generate!

### Langkah 3: Firewall Configuration

```bash
# Setup firewall dengan UFW (Uncomplicated Firewall)
sudo bash firewall-config.sh ufw
# UFW: Interface yang lebih user-friendly untuk iptables
# Ideal untuk basic firewall rules

# Atau dengan IPTABLES untuk advanced configuration
sudo bash firewall-config.sh iptables
# iptables: Powerful firewall utility untuk Linux
# Support complex NAT, routing, dan filtering rules
# Lebih fleksibel tapi lebih kompleks dikonfigurasi
```

### Langkah 4: Install Security Monitoring

```bash
# Install monitoring suite
sudo bash security-monitoring-suite.sh --install
# --install: Mode instalasi untuk setup awal
# Script akan install dependencies dan konfigurasi service

# Start service
sudo systemctl start security-monitor
# start: Jalankan security monitoring service sekarang
# Untuk memulai monitoring langsung tanpa reboot

sudo systemctl enable security-monitor
# enable: Enable auto-start pada boot time
# Service akan otomatis berjalan saat server restart
```

### Langkah 5: Konfigurasi Alert

Edit konfigurasi email dan Slack webhook:

```bash
# Edit config
sudo nano /etc/security-monitor/config.json

# Update email dan webhook
{
    "alert_email": "admin@yourdomain.com",
    "slack_webhook_url": "https://hooks.slack.com/services/..."
}
```

## 📖 Panduan Pemakaian

### Firewall Management

```bash
# Allow IP baru
sudo /usr/local/bin/allow-ip.sh 192.168.1.100 "Office IP"
# allow-ip.sh: Script untuk menambah IP ke whitelist
# 192.168.1.100: IP address yang akan diizinkan
# "Office IP": Comment/deskripsi untuk alasan allow

# Block IP
sudo /usr/local/bin/block-ip.sh 1.2.3.4 "Suspicious activity"
# block-ip.sh: Script untuk memblokir IP address
# 1.2.3.4: IP yang akan diblokir dari server
# "Suspicious activity": Alasan pemblokiran untuk log

# Cek status firewall
sudo ufw status
# ufw status: Tampilkan status UFW firewall
# Output: Status (active/inactive) dan rules yang aktif

# atau
sudo iptables -L -n
# iptables -L: List semua rules
# -n: Numeric output (tidak resolve DNS)
# Lebih detail, menampilkan semua chains dan rules
```

### Monitoring Commands

```bash
# Cek status monitoring
sudo systemctl status security-monitor
# status: Tampilkan detailed status dari systemd service
# Output: Active/inactive, uptime, memory usage, recent logs

# View real-time logs
sudo tail -f /var/log/security-monitor/monitor.log
# tail -f: Follow log file secara real-time
# -f: Mode follow - menampilkan baris baru saat ditambahkan
# Perfect untuk monitoring live security events

# Generate test report
sudo /usr/local/bin/security-monitoring-suite --test
# --test: Generate test report untuk verifikasi setup
# Mengecek semua configuration dan connectivity

# View daily report
ls -la /var/log/security-monitor/daily-report-*.html
# ls -la: List files dengan detail information
# -l: Long format (permissions, size, date, owner)
# -a: Show all files (including hidden)
# Wildcard *.html untuk menampilkan semua HTML reports
```

### Security Checks

```bash
# Manual file integrity check
sudo aide --check
# aide: Advanced Intrusion Detection Environment
# --check: Compare current filesystem state dengan database baseline
# Mendeteksi file yang berubah, baru, atau dihapus tanpa otorisasi

# Scan malware dengan ClamAV
sudo clamscan -r /var/www
# clamscan: Clam AntiVirus scanner
# -r: Recursive scan semua subdirectories
# /var/www: Target directory untuk scan (web directory)
# Cocok untuk mendeteksi web shells dan malware

# Rootkit check
sudo rkhunter --check --sk
# rkhunter: Rootkit Hunter
# --check: Perform comprehensive system scan
# --sk atau --skip-keypress: Skip user prompts untuk non-interactive scan
# Mendeteksi rootkits, backdoors, dan local exploits
```

## 🔧 Troubleshooting

### SSH Tidak Bisa Connect

```bash
# 1. Cek jika SSH running
sudo systemctl status sshd
# systemctl: System control untuk systemd services
# status: Tampilkan detailed service information
# Output: Active status, PID, memory usage, recent logs

# 2. Cek port SSH
sudo netstat -tlnp | grep sshd
# netstat: Network statistics utility
# -t: TCP connections
# -l: Listening sockets
# -n: Numeric (no DNS resolution)
# -p: Show process ID/program name
# | grep sshd: Filter hanya SSH daemon process

# 3. Cek firewall rules
sudo ufw status
# UFW status check untuk port yang diizinkan

sudo iptables -L -n | grep 22
# iptables -L: List rules
# -n: Numeric output
# | grep 22: Cari port 22 (default SSH)

# 4. Coba connect dari server sendiri
ssh -p <PORT> localhost
# -p <PORT>: Specify port number (gunakan actual SSH port)
# localhost: Connect ke local machine
# Untuk testing jika SSH daemon berfungsi dengan benar
```

### Monitoring Service Tidak Running

```bash
# 1. Cek error log
sudo journalctl -u security-monitor -f
# journalctl: Query systemd journal logs
# -u security-monitor: Filter untuk specific unit
# -f: Follow mode (real-time seperti tail -f)
# Menampilkan detailed error messages dari systemd

# 2. Check config syntax
sudo /usr/local/bin/security-monitoring-suite --test
# --test: Validasi semua konfigurasi dan dependencies
# Memastikan semua requirement terpenuhi sebelum start service

# 3. Restart service
sudo systemctl restart security-monitor
# restart: Stop dan start service
# Refresh configuration dan reload semua dependencies
```

### False Positive Alerts

```bash
# 1. Review konfigurasi
sudo nano /etc/security-monitor/config.json

# 2. Adjust thresholds
{
    "alert_threshold": {
        "failed_login_attempts": 20,  // Increase from 10
        "cpu_usage": 95,              // Increase from 90
        "memory_usage": 95            // Increase from 90
    }
}

# 3. Whitelist IP jika perlu
sudo /usr/local/bin/allow-ip.sh <IP> "False positive"
```

## 📋 Best Practices

### 1. SSH Security

```bash
# Selalu gunakan SSH key authentication
ssh-keygen -t ed25519 -C "admin@yourdomain.com"
# ssh-keygen: Generate SSH key pair
# -t ed25519: Key type ED25519 (lebih aman dari RSA)
# -C "comment": Comment untuk identifikasi key
# Akan generate ~/.ssh/id_ed25519 (private) dan ~/.ssh/id_ed25519.pub (public)

# Disable password authentication setelah key setup
PasswordAuthentication no
# Edit di /etc/ssh/sshd_config
# Nonaktifkan password auth, wajib menggunakan SSH key

# Gunakan 2FA untuk admin access
apt install libpam-google-authenticator
# Install Google Authenticator PAM module
# Menambahkan TOTP (Time-based One-Time Password) sebagai second factor
# Setup: google-authenticator untuk tiap user
```

### 2. Password Policy

```bash
# Setup strong password policy
apt install libpam-pwquality
# Install PAM password quality checking library
# Enforce password complexity dan strength requirements

# Edit /etc/security/pwquality.conf
minlen = 16
# Minimum password length: 16 karakter

dcredit = -1
# dcredit: Digit credit, -1 = require minimal 1 digit

ucredit = -1
# ucredit: Uppercase credit, -1 = require minimal 1 uppercase

lcredit = -1
# lcredit: Lowercase credit, -1 = require minimal 1 lowercase

ocredit = -1
# ocredit: Other/pecial character credit, -1 = require minimal 1 special character
```

### 3. Regular Updates

```bash
# Auto security updates
sudo apt install unattended-upgrades
# Install package untuk automatic security updates
# Download dan install security patches otomatis

sudo dpkg-reconfigure -plow unattended-upgrades
# dpkg-reconfigure: Reconfigure Debian package
# -p low: Set priority ke low untuk pertanyaan
# Interaktif configuration untuk unattended-upgrades

# Manual update
sudo apt update && sudo apt upgrade
# Update package lists && upgrade semua packages
# Best practice: Jalankan weekly untuk critical updates
```

### 4. Backup Strategy

```bash
# Daily backup script
#!/bin/bash
rsync -avz --delete /etc /home /var/www backup@remote:/backups/
# rsync: Remote synchronization utility
# -a: Archive mode (preserve permissions, timestamps, symlinks)
# -v: Verbose output untuk monitoring
# -z: Compress data transfer
# --delete: Delete files di remote yang tidak ada di source
# backup@remote:/backups/: SSH connection ke remote backup server

mysqldump --all-databases | gzip > backup.sql.gz
# mysqldump: MySQL database dump utility
# --all-databases: Backup semua databases dalam single dump
# | gzip: Pipe output ke gzip untuk kompresi
# > backup.sql.gz: Redirect compressed output ke file
```

### 5. Log Management

```bash
# Configure log rotation
sudo nano /etc/logrotate.d/security
# nano: Text editor (atau gunakan vim/nano)
# /etc/logrotate.d/security: Custom log rotation configuration
# Define frequency, retention, dan compression rules

# Send logs to remote server
sudo nano /etc/rsyslog.d/remote.conf
# rsyslog: Reliable system logging daemon
# /etc/rsyslog.d/remote.conf: Custom rsyslog configuration
*.* @@logserver.example.com:514
# *.*: All facilities, all priorities
# @@: TCP protocol (single @ untuk UDP)
# logserver.example.com:514: Remote server dengan port 514 (syslog default)
```

## 📅 Maintenance Schedule

### Harian

- [ ] Review security alerts
- [ ] Check system resources
- [ ] Verify backups completed
- [ ] Review failed login attempts
- [ ] Check for suspicious processes

### Mingguan

- [ ] Update system packages
- [ ] Run full malware scan
- [ ] Review firewall logs
- [ ] Update block/allow lists
- [ ] Test restore from backup

### Bulanan

- [ ] Security audit review
- [ ] Update documentation
- [ ] Password rotation for critical accounts
- [ ] Review user access rights
- [ ] Performance tuning

### Tahunan

- [ ] Full penetration test
- [ ] Security training for team
- [ ] Update incident response plan
- [ ] Review security policies
- [ ] Disaster recovery test

## 📊 Monitoring Dashboard

Setting up monitoring dashboard (optional):

```bash
# Install Grafana
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
# wget -q: Quiet download GPG key
# -O -: Output ke stdout
# |: Pipe ke apt-key add untuk import repository key

echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
# echo: Print repository line
# | sudo tee: Write ke file dengan sudo privileges
# /etc/apt/sources.list.d/grafana.list: Repository configuration file

sudo apt update && sudo apt install grafana
# Update package list dan install Grafana
# Grafana: Open source analytics & monitoring solution

# Install Prometheus for metrics collection
sudo apt install prometheus
# Prometheus: Time series database dan monitoring system
# Collect metrics dari applications dan infrastructure

# Configure alerts in Grafana
# - CPU/Memory alerts: Resource utilization monitoring
# - Failed login alerts: Security event monitoring
# - Disk space alerts: Storage capacity warnings
# - Network anomaly alerts: Traffic pattern analysis
```

## 🚨 Incident Response

### Level 1: Low Priority

- Suspicious login attempt from unknown IP
- High resource usage
- Minor configuration change

**Actions:**
- Block IP if necessary
- Investigate logs
- Document incident

### Level 2: Medium Priority

- Successful breach attempt blocked
- Malware detected and quarantined
- Service disruption

**Actions:**
- Immediate isolation
- Full system scan
- Alert management
- Prepare incident report

### Level 3: Critical

- System compromised
- Data breach confirmed
- Ransomware detected

**Actions:**
- **IMMEDIATE**: Disconnect from network
- **IMMEDIATE**: Alert security team
- Preserve evidence
- Begin recovery process
- Report to authorities (if required)

## 📞 Emergency Contacts

```text
Security Team Lead: +62-812-3456-7890
System Administrator: +62-813-4567-8912
Management: +62-814-5678-9123
ISP Provider: 1-500-XXX
CERT Indonesia: 021-526-9331
```

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Linux Security Documentation](https://www.kernel.org/doc/Documentation/security/)

## 💡 Tips Tambahan

1. **Always test configurations in staging first**
2. **Keep offline backups of critical configs**
3. **Document all changes with timestamps**
4. **Use version control for configuration files**
5. **Implement principle of least privilege**
6. **Regular security awareness training**
7. **Have an incident response plan ready**
8. **Test disaster recovery regularly**

## 📈 Security Metrics to Track

- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Number of security incidents per month
- False positive rate
- Patch deployment time
- Backup success rate
- System uptime
- Failed login trend

---

**Terakhir Update:** 25 November 2024
**Version:** 1.0.0
**Maintainer:** Security Team

Untuk pertanyaan atau dukungan, hubungi: security-team@yourdomain.com