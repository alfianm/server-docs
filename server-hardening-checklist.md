#!/bin/bash

# Server Hardening Script
# Usage: sudo bash harden-server.sh
#
# Script ini melakukan otomasi hardening server Ubuntu/Debian dengan 13 langkah keamanan
# ⚠️ PENTING: Pastikan Anda memiliki SSH key sebelum menjalankan script ini!

set -euo pipefail
# set -e: Exit immediately if a command exits with a non-zero status
# set -u: Treat unset variables as an error
# set -o pipefail: Return value of a pipeline is the status of the last command to exit

# Colors for output
RED='\033[0;31m'      # For error messages
GREEN='\033[0;32m'    # For success messages
YELLOW='\033[1;33m'   # For warning messages
NC='\033[0m'          # No Color - reset to default

LOG_FILE="/var/log/server-hardening.log"
BACKUP_DIR="/root/hardening-backup-$(date +%Y%m%d)"
# BACKUP_DIR: Semua konfigurasi asli akan di-backup ke direktori ini
# Format: /root/hardening-backup-YYYYMMDD

# Function to log messages
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
    # tee -a: Menampilkan output ke layar DAN menyimpan ke log file
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1  # Exit script dengan status code 1 (error)
}

warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
fi
# $EUID: Effective User ID, 0 = root user
# Script harus dijalankan sebagai root karena banyak file sistem yang akan dimodifikasi

# Create backup directory
mkdir -p "$BACKUP_DIR"
# mkdir -p: Membuat direktori dengan struktur parent jika belum ada
# Direktori backup akan menyimpan semua konfigurasi asli sebelum diubah

log "Starting server hardening process..."
log "Backup directory: $BACKUP_DIR"

# Function to backup file
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$BACKUP_DIR/${1//\//-}-$(date +%H%M%S).bak"
        log "Backed up $1"
    fi
    # ${1//\//-}: Mengganti semua '/' dengan '-' untuk nama file backup
    # Contoh: /etc/ssh/sshd_config menjadi etc-ssh-sshd_config-HHMMSS.bak
}

# 1. System Update
log "Step 1: Updating system packages"
# Tujuan: Memastikan sistem memiliki patch keamanan terbaru
backup_file "/etc/apt/sources.list"
# Backup daftar repository APT sebelum update

apt-get update && apt-get upgrade -y
# apt-get update: Mengupdate indeks paket dari repository
# apt-get upgrade -y: Mengupgrade semua paket ke versi terbaru (tanpa konfirmasi interaktif)
# &&: Operator AND - hanya jalankan perintah kedua jika perintah pertama berhasil

apt-get install -y ufw fail2ban aide rkhunter lynis
# Menginstall tools keamanan penting:
# - ufw: Uncomplicated Firewall - firewall yang mudah dikonfigurasi
# - fail2ban: Intrusion Prevention System - memblokir IP yang mencoba brute force
# - aide: Advanced Intrusion Detection Environment - file integrity checker
# - rkhunter: Rootkit Hunter - mendeteksi rootkit dan malware
# - lynis: Security auditing tool - melakukan scan keamanan komprehensif

# 2. SSH Hardening
log "Step 2: Hardening SSH configuration"
# Tujuan: Mengamankan akses SSH dari serangan brute force dan unauthorized access
SSH_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSH_CONFIG"
# Backup konfigurasi SSH asli sebelum modifikasi

# Change SSH port to random port
SSH_PORT=$(shuf -i 2222-65535 -n 1)
# shuf: Generate random number
# -i 2222-65535: Range port yang aman (bukan port privileged < 1024)
# -n 1: Generate 1 angka random
# Menghindari scanner otomatis yang selalu scan port 22

# Modify SSH config menggunakan sed (stream editor)
sed -i "s/#Port 22/Port $SSH_PORT/" "$SSH_CONFIG"
# sed -i: Edit file in-place (mengubah file langsung)
# Ganti default port 22 dengan port random

sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG"
# Nonaktifkan login langsung sebagai root user
# User harus login sebagai user biasa lalu su -

sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG"
# ⚠️ PENTING: Wajib setup SSH key sebelum menjalankan script!
# Nonaktifkan authentication dengan password, gunakan SSH key saja

sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' "$SSH_CONFIG"
# Pastikan password kosong tidak diperbolehkan

sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' "$SSH_CONFIG"
# Batasi percobaan login menjadi 3 kali untuk mencegah brute force

# Add additional SSH security settings
cat >> "$SSH_CONFIG" << EOF
# cat >>: Append text ke akhir file
# Here document (EOF) untuk multiple lines input

# Additional security settings
ClientAliveInterval 300
ClientAliveCountMax 2
# ClientAliveInterval: Kirim keepalive message setiap 300 detik (5 menit)
# ClientAliveCountMax: Maksimal 2 kali tidak ada response sebelum disconnect
# Timeout total: 5 menit x 2 = 10 menit idle

AllowUsers ubuntu
# Hanya user 'ubuntu' yang boleh login via SSH
# Customizable: ganti dengan username yang Anda gunakan

Protocol 2
# Gunakan SSH Protocol 2 (lebih aman dari Protocol 1)

IgnoreRhosts yes
HostbasedAuthentication no
RhostsRSAAuthentication no
# Nonaktifkan authentication berbasis host (.rhosts, .shosts)

PermitUserEnvironment no
# Nonaktifkan user environment processing untuk mencegah privilege escalation
EOF

log "SSH port changed to: $SSH_PORT"
log "Restarting SSH service..."
systemctl restart sshd
# Restart service SSH untuk menerapkan perubahan konfigurasi
# ⚠️ PENTING: Pastikan Anda memiliki koneksi SSH aktif saat restart!

# 3. Firewall Configuration
log "Step 3: Configuring firewall"
# Tujuan: Memblokir trafik tidak sah dan hanya izinkan port yang diperlukan
ufw --force reset
# Reset semua aturan firewall ke default
# --force: Bypass confirmation prompt

ufw default deny incoming
# Blokir semua incoming connection secara default
# Prinsip "default deny" - hanya izinkan yang explicitly allowed

ufw default allow outgoing
# Izinkan semua outgoing connection dari server
# Diperlukan untuk update, download, DNS, dll

ufw allow in "$SSH_PORT"/tcp
# Izinkan koneksi SSH pada port baru (yang random)
# /tcp: Specify TCP protocol

ufw allow in 80/tcp
# Izinkan HTTP traffic untuk web server

ufw allow in 443/tcp
# Izinkan HTTPS traffic untuk web server SSL/TLS

ufw --force enable
# Aktifkan firewall dengan aturan yang telah dikonfigurasi
# --force: Bypass prompt "Command may disrupt existing ssh connections"

# 4. System Hardening
log "Step 4: Applying system hardening"
# Tujuan: Mengamankan kernel dan filesystem dari berbagai jenis serangan

# Kernel parameters
SYSCTL_CONF="/etc/sysctl.conf"
backup_file "$SYSCTL_CONF"
# Backup file konfigurasi kernel parameters

cat >> "$SYSCTL_CONF" << EOF
# Tambahkan parameter keamanan kernel ke akhir file

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
# Abaikan ICMP echo request ke broadcast address (Smurf attack protection)

net.ipv4.icmp_ignore_bogus_error_responses = 1
# Abaikan bogus ICMP error responses

net.ipv4.tcp_syncookies = 1
# Aktifkan SYN cookies untuk mencegah SYN flood attacks

# Filesystem Security - Melindungi filesystem
fs.protected_regular = 1
fs.protected_fifos = 1
# Lindungi file dan FIFO dari race condition attacks di world-writable directories

fs.suid_dumpable = 0
# Nonaktifkan core dump untuk SUID programs (security risk)

# Kernel Security - Meningkatkan keamanan kernel
kernel.randomize_va_space = 2
# Aktifkan Address Space Layout Randomization (ASLR) - membuat exploit lebih sulit
# 0 = disabled, 1 = conservative, 2 = full randomization

kernel.kptr_restrict = 2
# Restriksi akses ke kernel pointers melalui /proc
# 2 = hanya bisa diakses oleh kernel processes

kernel.dmesg_restrict = 1
# Restriksi akses ke dmesg (kernel ring buffer) untuk non-root users
EOF

# Apply sysctl settings
sysctl -p
# Reload semua kernel parameters dari /etc/sysctl.conf
# -p: Load dari file default (/etc/sysctl.conf)

# 5. Disable unnecessary services
log "Step 5: Disabling unnecessary services"
# Tujuan: Mengurangi attack surface dengan menonaktifkan services yang tidak diperlukan

systemctl disable bluetooth 2>/dev/null || true
# Nonaktifkan Bluetooth service (biasanya tidak diperlukan di server)
# 2>/dev/null: Redirect stderr ke /dev/null (suppress error messages)
# || true: Jalankan `true` jika command gagal, agar script tidak berhenti

systemctl disable cups 2>/dev/null || true
# Nonaktifkan CUPS (Common UNIX Printing System) printing service

systemctl disable avahi-daemon 2>/dev/null || true
# Nonaktifkan Avahi daemon (mDNS/DNS-SD service)
# Berbahaya karena bisa expose informasi jaringan

systemctl disable rpcbind 2>/dev/null || true
# Nonaktifkan RPCbind (portmapper) untuk NFS/NIS services
# Cukup berbahaya dan sering digunakan dalam serangan

# 6. Configure Fail2ban
log "Step 6: Configuring Fail2ban"
# Tujuan: Mem-block IP address yang mencoba brute force attacks

FAIL2BAN_LOCAL="/etc/fail2ban/jail.local"
backup_file "$FAIL2BAN_LOCAL"
# Backup konfigurasi fail2ban yang ada

cat > "$FAIL2BAN_LOCAL" << EOF
# Buat konfigurasi fail2ban baru
[DEFAULT]
bantime = 3600
# Durasi ban dalam detik (3600 = 1 jam)

findtime = 600
# Window waktu untuk mendeteksi percobaan (600 detik = 10 menit)

maxretry = 3
# Jumlah maksimal percobaan sebelum diblokir

backend = systemd
# Gunakan systemd backend untuk monitoring logs

[sshd]
enabled = true
port = $SSH_PORT
# Gunakan port SSH yang baru (random) untuk monitoring

filter = sshd
logpath = /var/log/auth.log
# Path file log untuk authentication attempts

maxretry = 3
# 3 kali failed login = ban

bantime = 86400
# Ban selama 24 jam untuk SSH attacks (lebih lama dari default)

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
# Monitor nginx error log untuk authentication failures

maxretry = 3
bantime = 3600
# 1 jam ban untuk nginx auth failures
EOF

systemctl enable fail2ban
# Enable fail2ban service untuk auto-start saat boot

systemctl restart fail2ban
# Restart fail2ban untuk menerapkan konfigurasi baru

# 7. Configure AIDE (Advanced Intrusion Detection Environment)
log "Step 7: Configuring AIDE"
# Tujuan: Membuat database integrity file system untuk deteksi perubahan tidak sah

aide --init
# Inisialisasi AIDE dan buat database integrity files
# Proses ini memakan waktu cukup lama karena scan seluruh filesystem

mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# Pindahkan database baru ke lokasi database aktif
# aide.db.new adalah default output dari init command
# Database ini menjadi baseline untuk perbandingan di kemudian hari

# 8. Configure rkhunter (Rootkit Hunter)
log "Step 8: Configuring rkhunter"
# Tujuan: Mendeteksi rootkits, backdoors, dan local exploits

RKHUNTER_CONF="/etc/rkhunter.conf"
backup_file "$RKHUNTER_CONF"
# Backup konfigurasi rkhunter

# Update rkhunter
rkhunter --update --sk
# --update: Update database rkhunter dengan signatures terbaru
# --sk atau --skip-keypress: Skip keypress prompts (non-interactive)
# Download white list database dan version info

# 9. File permissions
log "Step 9: Setting secure file permissions"
# Tujuan: Mengamankan permission file kritikal dari unauthorized access

chmod 644 /etc/passwd
# -rw-r--r--: Owner read/write, group read, others read
# File ini berisi user accounts, boleh dibaca semua orang

chmod 640 /etc/shadow
# -rw-r-----: Owner read/write, group read, others none
# File berisi hashed passwords, harus terproteksi ketat
# Group biasanya 'shadow' untuk program yang butuh akses

chmod 644 /etc/group
# -rw-r--r--: Owner read/write, group read, others read
# File berisi group information, boleh dibaca umum

chmod 600 /etc/ssh/sshd_config
# -rw-------: Hanya root yang bisa read/write
# Konfigurasi SSH sangat sensitif, hanya root yang boleh akses

chmod 640 /etc/sudoers
# -rw-r-----: Owner read/write, group read, others none
# File konfigurasi sudo, group biasanya 'sudo' atau 'wheel'

# 10. Create security monitoring script
log "Step 10: Creating security monitoring script"
# Tujuan: Automated monitoring setiap 5 menit untuk mendeteksi anomali keamanan

cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash
# 'EOF' dengan single quote: Prevent variable expansion

LOG_FILE="/var/log/security-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

log_event() {
    echo "[$DATE] $1" >> $LOG_FILE
}

# Check failed logins
FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log | wc -l)
# Cari semua failed password attempts dan hitung jumlahnya
# wc -l: word count - line count

if [ $FAILED_LOGINS -gt 10 ]; then
    log_event "WARNING: High number of failed login attempts: $FAILED_LOGINS"
fi
# Alert jika ada >10 failed login attempts

# Check for new user accounts
NEW_USERS=$(grep "new user" /var/log/auth.log | tail -5)
# Cari 5 user creation terakhir
# tail -5: Ambil 5 baris terakhir

if [ ! -z "$NEW_USERS" ]; then
    log_event "INFO: New user accounts created: $NEW_USERS"
fi
# Log jika ada user baru yang dibuat

# Check disk usage
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
# df -h: Disk free - human readable format
# awk 'NR==2 {print $5}': Ambil baris ke-2, kolom ke-5 (persentase)
# sed 's/%//': Remove % character

if [ $DISK_USAGE -gt 90 ]; then
    log_event "WARNING: High disk usage: ${DISK_USAGE}%"
fi
# Alert jika disk usage >90%

# Check running processes
SUSPICIOUS_PROCS=$(ps aux | grep -E '(nc|netcat|python.*socket|bash.*tcp)' | grep -v grep)
# Cari proses yang mencurigakan:
# nc/netcat: Network utility yang sering digunakan untuk backdoor
# python.*socket: Python script dengan socket programming
# bash.*tcp: Bash script dengan koneksi TCP
# grep -v grep: Exclude grep process dari hasil

if [ ! -z "$SUSPICIOUS_PROCS" ]; then
    log_event "WARNING: Suspicious processes detected: $SUSPICIOUS_PROCS"
fi
# Alert jika ada proses mencurigakan yang berjalan
EOF

chmod +x /usr/local/bin/security-monitor.sh
# Tambahkan execute permission agar bisa dijalankan langsung

# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/security-monitor.sh") | crontab -
# crontab -l: List existing crontab entries
# 2>/dev/null: Suppress error jika crontab kosong
# */5 * * * *: Setiap 5 menit (cron format: minute hour day month weekday)
# | crontab -: Install new crontab from stdin

# 11. Install logrotate configuration
log "Step 11: Configuring log rotation"
# Tujuan: Mengelola file log agar tidak memenuhi disk space

cat > /etc/logrotate.d/security << 'EOF'
/var/log/security-monitor.log {
    daily
    # Rotasi log setiap hari

    missingok
    # Tidak error jika file log tidak ada

    rotate 30
    # Simpan 30 file log terakhir

    compress
    # Kompres log lama dengan gzip (.gz)

    delaycompress
    # Tunda kompres untuk rotasi berikutnya
    # File log terakhir tidak dikompres untuk debugging

    copytruncate
    # Copy file lama, lalu truncate original
    # Memungkinkan continuous logging tanpa restart service
}
EOF

# 12. Clean up
log "Step 12: Cleaning up"
# Tujuan: Membersihkan sistem dari paket yang tidak diperlukan

apt-get autoremove -y
# Hapus paket yang terinstall otomatis tapi tidak lagi diperlukan
# -y: Jawab yes untuk semua pertanyaan

apt-get autoclean
# Hapus package files (.deb) dari cache APT
# Membersihkan /var/cache/apt/archives/

# 13. Generate summary report
log "Step 13: Generating security report"
# Tujuan: Membuat dokumentasi lengkap semua perubahan yang telah dilakukan

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
# Menampilkan summary kepada user tentang apa yang telah berubah
# dan langkah-langkah yang harus dilakukan selanjutnya
# Warna hijau untuk success, kuning untuk peringatan penting