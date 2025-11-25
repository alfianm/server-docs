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
# apt update: Refresh indeks paket dari repository
# apt upgrade -y: Upgrade semua paket ke versi terbaru tanpa konfirmasi
# &&: Operator AND - hanya jalankan perintah kedua jika pertama berhasil
# -y: Yes to all prompts - non-interactive upgrade

# Atau untuk CentOS/RHEL
sudo yum update -y
# yum: Yellowdog Updater Modified - package manager untuk CentOS/RHEL
# update -y: Update semua packages dengan auto-confirmation
```

### 2.2 Konfigurasi SSH Aman
```bash
# /etc/ssh/sshd_config
Port 2222                    # Ubah dari port default 22 untuk menghindari scanner
PermitRootLogin no          # Nonaktifkan login langsung sebagai root
PasswordAuthentication no   # Wajibkan SSH key, nonaktifkan password
PubkeyAuthentication yes    # Aktifkan public key authentication
MaxAuthTries 3              # Batasi percobaan login mencegah brute force
ClientAliveInterval 300     # Kirim keepalive setiap 300 detik (5 menit)
ClientAliveCountMax 2       # Disconnect setelah 2 kali tidak ada response
AllowUsers admin user1 user2 # Hanya user tertentu yang boleh login
# Restart SSH setelah perubahan: sudo systemctl restart sshd
```

### 2.3 Disable Layanan Tidak Perlu
```bash
# List semua layanan yang running
systemctl list-units --type=service --state=running
# systemctl: System control utility untuk systemd services
# list-units: Tampilkan units yang aktif
# --type=service: Filter hanya service units
# --state=running: Hanya tampilkan yang sedang berjalan

# Disable layanan tidak perlu
sudo systemctl disable bluetooth
# disable: Nonaktifkan auto-start saat boot (service masih running sampai reboot)

sudo systemctl disable cups
# cups: Common UNIX Printing System - tidak diperlukan di server tanpa printer

sudo systemctl disable avahi-daemon
# avahi-daemon: mDNS/DNS-SD service - bisa expose informasi jaringan
# Gunakan juga: sudo systemctl stop service untuk stop sekarang
```

### 2.4 Kernel Hardening
```bash
# /etc/sysctl.conf
# Apply dengan: sudo sysctl -p
# -p: Load dan apply parameters dari file /etc/sysctl.conf

# Network Security - Mencegah serangan jaringan
net.ipv4.ip_forward = 0
# Nonaktifkan IP forwarding untuk mencegah server menjadi router

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Nonaktifkan ICMP redirects untuk mencegah MITM attacks

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Nonaktifkan source routing untuk mencegah IP spoofing

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# Nonaktifkan ICMP redirects untuk mencegah redirect attacks

net.ipv4.icmp_echo_ignore_broadcasts = 1
# Abaikan ICMP echo ke broadcast (Smurf attack protection)

net.ipv4.icmp_ignore_bogus_error_responses = 1
# Abaikan bogus ICMP error responses

net.ipv4.tcp_syncookies = 1
# Aktifkan SYN cookies untuk mencegah SYN flood attacks

# Filesystem Security - Melindungi filesystem
fs.protected_regular = 1
fs.protected_fifos = 1
# Lindungi file dan FIFO dari race condition attacks

fs.suid_dumpable = 0
# Nonaktifkan core dump untuk SUID programs (security risk)

# Kernel ExecShield - Proteksi eksekusi kernel
kernel.exec-shield = 1
# Aktifkan ExecShield ( hanya di beberapa distro )

kernel.randomize_va_space = 2
# ASLR - Address Space Layout Randomization (0=off, 1=conservative, 2=full)
# Membuat buffer overflow attacks lebih sulit
```

## 3. Firewall Configuration

### 3.1 UFW (Uncomplicated Firewall)
```bash
# Reset rules
sudo ufw --force reset
# Reset semua aturan ke default
# --force: Bypass confirmation prompt

# Default policies
sudo ufw default deny incoming
# Blokir semua incoming connection (default deny principle)

sudo ufw default allow outgoing
# Izinkan semua outgoing connection untuk operasi normal

# Allow essential services
sudo ufw allow in on eth0 to any port 2222 proto tcp # SSH on custom port
# allow in: Izinkan incoming traffic
# on eth0: Hanya interface eth0
# to any port 2222: Ke port 2222
# proto tcp: Protocol TCP

sudo ufw allow in on eth0 to any port 80 proto tcp   # HTTP
sudo ufw allow in on eth0 to any port 443 proto tcp  # HTTPS
sudo ufw allow in on eth0 to any port 53 proto udp   # DNS

# Enable firewall
sudo ufw enable
# Aktifkan firewall dengan aturan yang dikonfigurasi
# Akan menampilkan warning tentang existing SSH connections
```

### 3.2 IPTABLES Rules
```bash
#!/bin/bash
# flush semua rules
iptables -F
# -F: Flush/Remove semua rules di semua chains

iptables -X
# -X: Delete semua user-defined chains

iptables -t nat -F
iptables -t nat -X
# -t nat: Operasi pada NAT table

# Set default policies
iptables -P INPUT DROP
# -P INPUT DROP: Default policy DROP untuk incoming traffic
# Prinsip "deny by default"

iptables -P FORWARD DROP
# -P FORWARD DROP: Drop forwarded packets (router functionality)

iptables -P OUTPUT ACCEPT
# -P OUTPUT ACCEPT: Allow outgoing traffic

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# -A INPUT: Append rule ke INPUT chain
# -i lo: Interface input lo (loopback)
# -j ACCEPT: Jump to ACCEPT target

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# -m state: Load state module
# --state ESTABLISHED,RELATED: Connection yang sudah established atau related
# Membalas traffic dari outgoing connections

# Allow SSH (from specific IPs)
iptables -A INPUT -p tcp --dport 2222 -s 192.168.1.0/24 -j ACCEPT
# -p tcp: Protocol TCP
# --dport 2222: Destination port 2222
# -s 192.168.1.0/24: Source network 192.168.1.0/24

# Rate limiting untuk SSH
iptables -A INPUT -p tcp --dport 2222 -m limit --limit 3/min --limit-burst 3 -j ACCEPT
# -m limit: Load limit module
# --limit 3/min: Maksimal 3 connections per minute
# --limit-burst 3: Allow burst hingga 3 connections

# Save rules
iptables-save > /etc/iptables/rules.v4
# iptables-save: Export semua rules ke file
# > /etc/iptables/rules.v4: Redirect output ke file
# Install iptables-persistent untuk auto-load pada boot
```

## 4. Intrusion Detection System

### 4.1 Install Fail2ban
```bash
sudo apt install fail2ban -y
# Install Fail2ban - intrusion prevention software
# -y: Auto-confirm installation
# Fail2ban memonitor log files dan memblokir IP dengan malicious behavior
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
# AIDE: Advanced Intrusion Detection Environment
# File integrity checker untuk mendeteksi perubahan tidak sah

# Initialize database
sudo aide --init
# --init: Create initial database integrity files
# Proses scan semua filesystem dan buat checksum

sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# Rename database baru jadi database aktif
# aide.db.new adalah default output dari --init

# Check integrity
sudo aide --check
# --check: Compare current files dengan database
# Report file yang berubah, baru, atau dihapus

# Update database setelah ada perubahan valid
sudo aide --update
# --update: Update database dengan perubahan valid
# Gunakan setelah install/update software yang legitimate
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
# grep: Cari pattern "Failed password" di auth log
# wc -l: Word count - line count untuk jumlah kejadian
if [ $FAILED_LOGINS -gt 10 ]; then
    log_event "WARNING: High number of failed login attempts: $FAILED_LOGINS"
fi
# Alert jika failed login > 10

# Cek perubahan file sistem
/usr/bin/aide --check > /tmp/aide_check.txt 2>&1
# aide --check: Cek integrity files
# > /tmp/aide_check.txt: Redirect output ke temporary file
# 2>&1: Redirect stderr ke stdout (capture semua output)
if [ $? -ne 0 ]; then
    # $? -ne 0: Previous command exit code tidak 0 (error)
    log_event "CRITICAL: File integrity check failed!"
    cat /tmp/aide_check.txt >> $LOG_FILE
    # cat: Append hasil AIDE check ke log untuk analisis
fi

# Cek port terbuka
OPEN_PORTS=$(netstat -tuln | grep LISTEN)
# netstat -tuln:
# -t: TCP ports
# -u: UDP ports
# -l: Listening ports
# -n: Numeric output (no DNS resolution)
log_event "Open ports: $OPEN_PORTS"

# Cek proses mencurigakan
SUSPICIOUS_PROCS=$(ps aux | grep -E '(nc|netcat|python.*socket|bash.*tcp)' | grep -v grep)
# ps aux: List semua proses dengan detail
# grep -E: Extended regex untuk pattern matching
# nc|netcat: Cari netcat processes (sering digunakan untuk backdoor)
# python.*socket: Python scripts dengan socket programming
# bash.*tcp: Bash scripts dengan TCP connections
# grep -v grep: Exclude grep process dari hasil
if [ ! -z "$SUSPICIOUS_PROCS" ]; then
    # [ ! -z "$VAR" ]: String tidak kosong
    log_event "WARNING: Suspicious processes detected: $SUSPICIOUS_PROCS"
fi

# Cek disk usage
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
# df -h: Disk free - human readable format
# awk 'NR==2 {print $5}': Process baris ke-2, ambil kolom ke-5
# NR==2: Number Record = 2 (skip header)
# {print $5}: Print field ke-5 (persentase)
# sed 's/%//': Substitute/remove % character
if [ $DISK_USAGE -gt 90 ]; then
    log_event "WARNING: High disk usage: ${DISK_USAGE}%"
fi
# Alert jika disk usage > 90%
```

### 5.3 Cron Job untuk Monitoring
```bash
# Tambahkan ke crontab
# crontab -e
# Edit crontab user dengan default editor

# Monitoring setiap 5 menit
*/5 * * * * /usr/local/bin/security-monitor.sh
# Cron format: minute hour day month weekday
# */5: Setiap 5 menit
# *: Setiap jam
# *: Setiap hari
# *: Setiap bulan
# *: Setiap hari dalam minggu (0-7, 0=Sunday)

# Full scan AIDE setiap hari jam 3 pagi
0 3 * * * /usr/bin/aide --check >> /var/log/aide-daily.log 2>&1
# 0: Tepat pada menit ke-0
# 3: Jam 3 pagi (3 AM)
# *: Setiap hari
# *: Setiap bulan
# *: Setiap hari dalam minggu
# >> /var/log/aide-daily.log: Append output ke log file
# 2>&1: Redirect stderr ke stdout
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
# tar -czf: Create compressed tar archive
# -c: Create archive
# -z: Compress dengan gzip
# -f -: Output ke stdout
# 2>/dev/null: Suppress stderr messages
# |: Pipe output ke GPG untuk enkripsi
# gpg --encrypt: Enkripsi file dengan GPG
# --trust-model always: Auto-trust key
# -r $GPG_RECIPIENT: Encrypt untuk recipient
# -o: Output file

# Backup database
mysqldump --single-transaction --all-databases | \
gpg --trust-model always --encrypt -r $GPG_RECIPIENT -o $BACKUP_DIR/db_$DATE.sql.gpg
# mysqldump: Export MySQL database
# --single-transaction: Consistent backup tanpa locking tables
# --all-databases: Backup semua databases

# Hapus backup lama (30 hari)
find $BACKUP_DIR -name "*.gpg" -mtime +30 -delete
# find: Cari file
# -name "*.gpg": Filter ekstensi .gpg
# -mtime +30: Modified time lebih dari 30 hari
# -delete: Hapus file yang ditemukan

# Sync ke offsite server
rsync -avz --delete $BACKUP_DIR/ backup@remote-server:/backups/
# rsync: Remote sync untuk file transfer
# -a: Archive mode (preserve permissions, timestamps, etc)
# -v: Verbose output
# -z: Compress during transfer
# --delete: Delete files di destination yang tidak ada di source
# backup@remote-server:/backups/: SSH connection ke remote server
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