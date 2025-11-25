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
tar -xzf security-files.tar.gz
cd /var/www

# Buat file executable
chmod +x *.sh
```

### Langkah 2: Server Hardening

```bash
# Jalankan script hardening
sudo bash server-hardening-checklist.md
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
# Setup firewall dengan UFW
sudo bash firewall-config.sh ufw

# Atau dengan IPTABLES
sudo bash firewall-config.sh iptables
```

### Langkah 4: Install Security Monitoring

```bash
# Install monitoring suite
sudo bash security-monitoring-suite.sh --install

# Start service
sudo systemctl start security-monitor
sudo systemctl enable security-monitor
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

# Block IP
sudo /usr/local/bin/block-ip.sh 1.2.3.4 "Suspicious activity"

# Cek status firewall
sudo ufw status
# atau
sudo iptables -L -n
```

### Monitoring Commands

```bash
# Cek status monitoring
sudo systemctl status security-monitor

# View real-time logs
sudo tail -f /var/log/security-monitor/monitor.log

# Generate test report
sudo /usr/local/bin/security-monitoring-suite --test

# View daily report
ls -la /var/log/security-monitor/daily-report-*.html
```

### Security Checks

```bash
# Manual file integrity check
sudo aide --check

# Scan malware dengan ClamAV
sudo clamscan -r /var/www

# Rootkit check
sudo rkhunter --check --sk
```

## 🔧 Troubleshooting

### SSH Tidak Bisa Connect

```bash
# 1. Cek jika SSH running
sudo systemctl status sshd

# 2. Cek port SSH
sudo netstat -tlnp | grep sshd

# 3. Cek firewall rules
sudo ufw status
sudo iptables -L -n | grep 22

# 4. Coba connect dari server sendiri
ssh -p <PORT> localhost
```

### Monitoring Service Tidak Running

```bash
# 1. Cek error log
sudo journalctl -u security-monitor -f

# 2. Check config syntax
sudo /usr/local/bin/security-monitoring-suite --test

# 3. Restart service
sudo systemctl restart security-monitor
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

# Disable password authentication setelah key setup
PasswordAuthentication no

# Gunakan 2FA untuk admin access
apt install libpam-google-authenticator
```

### 2. Password Policy

```bash
# Setup strong password policy
apt install libpam-pwquality

# Edit /etc/security/pwquality.conf
minlen = 16
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
```

### 3. Regular Updates

```bash
# Auto security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Manual update
sudo apt update && sudo apt upgrade
```

### 4. Backup Strategy

```bash
# Daily backup script
#!/bin/bash
rsync -avz --delete /etc /home /var/www backup@remote:/backups/
mysqldump --all-databases | gzip > backup.sql.gz
```

### 5. Log Management

```bash
# Configure log rotation
sudo nano /etc/logrotate.d/security

# Send logs to remote server
sudo nano /etc/rsyslog.d/remote.conf
*.* @@logserver.example.com:514
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
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install grafana

# Install Prometheus for metrics collection
sudo apt install prometheus

# Configure alerts in Grafana
# - CPU/Memory alerts
# - Failed login alerts
# - Disk space alerts
# - Network anomaly alerts
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