#!/bin/bash

# Comprehensive Security Monitoring Suite
# Features: Real-time monitoring, threat detection, automated responses
# Usage: sudo bash security-monitoring-suite.sh [--install|--start|--stop|--status|--test]

set -euo pipefail

# Configuration
SCRIPT_DIR="/usr/local/bin"
CONFIG_DIR="/etc/security-monitor"
LOG_DIR="/var/log/security-monitor"
PID_DIR="/var/run/security-monitor"
ALERT_EMAIL="admin@yourdomain.com"
SLACK_WEBHOOK_URL=""  # Optional: Set your Slack webhook URL

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
VERBOSE=false
DAEMON_MODE=false
TEST_MODE=false

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --verbose) VERBOSE=true ;;
        --daemon) DAEMON_MODE=true ;;
        --test) TEST_MODE=true ;;
        --install) INSTALL=true ;;
        --start) START=true ;;
        --stop) STOP=true ;;
        --status) STATUS=true ;;
    esac
done

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_file="$LOG_DIR/monitor.log"

    # Create log entry
    local log_entry="[$timestamp] [$level] $message"

    # Output to console if verbose
    if [ "$VERBOSE" = true ]; then
        case $level in
            "CRITICAL") echo -e "${RED}$log_entry${NC}" ;;
            "WARNING") echo -e "${YELLOW}$log_entry${NC}" ;;
            "INFO") echo -e "${GREEN}$log_entry${NC}" ;;
            "DEBUG") echo -e "${BLUE}$log_entry${NC}" ;;
            *) echo -e "$log_entry" ;;
        esac
    fi

    # Write to log file
    echo "$log_entry" >> "$log_file"

    # Send alerts for critical issues
    if [ "$level" = "CRITICAL" ]; then
        send_alert "$message"
    fi
}

# Alert function
send_alert() {
    local message="$1"

    # Email alert
    if command -v mail &> /dev/null; then
        echo "Security Alert: $message" | mail -s "CRITICAL: Server Security Alert" "$ALERT_EMAIL"
    fi

    # Slack alert
    if [ ! -z "$SLACK_WEBHOOK_URL" ] && command -v curl &> /dev/null; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 SECURITY ALERT: $message\"}" \
            "$SLACK_WEBHOOK_URL" &>/dev/null
    fi
}

# Initialize monitoring suite
init_monitor() {
    log "INFO" "Initializing security monitoring suite..."

    # Create necessary directories
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$PID_DIR"

    # Set permissions
    chmod 750 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    chmod 755 "$PID_DIR"

    # Create config file
    cat > "$CONFIG_DIR/config.json" << EOF
{
    "monitoring": {
        "interval": 60,
        "log_retention_days": 30,
        "alert_threshold": {
            "failed_login_attempts": 10,
            "cpu_usage": 90,
            "memory_usage": 90,
            "disk_usage": 85,
            "network_connections": 1000
        }
    },
    "threat_detection": {
        "scan_interval": 300,
        "quarantine_directory": "/var/lib/security-monitor/quarantine",
        "backup_directory": "/var/lib/security-monitor/backups"
    },
    "reporting": {
        "daily_report": true,
        "weekly_report": true,
        "monthly_report": true,
        "report_email": "$ALERT_EMAIL"
    }
}
EOF

    # Install dependencies
    if [ ! -f "/usr/bin/jq" ]; then
        apt-get update && apt-get install -y jq nmap net-tools curl mailutils
    fi

    log "INFO" "Initialization complete"
}

# Check login attempts and suspicious activity
check_login_security() {
    local failed_logins=$(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    local root_attempts=$(grep "root.*Failed" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)
    local banned_ips=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | awk -F':' '{print $2}' | tr -d ' ' | tr ',' '\n' | wc -l)

    if [ "$failed_logins" -gt 10 ]; then
        log "WARNING" "High failed login attempts: $failed_logins"
    fi

    if [ "$root_attempts" -gt 0 ]; then
        log "CRITICAL" "Root login attempts detected: $root_attempts"
    fi

    # Check for new user accounts
    local new_users=$(grep "new user" /var/log/auth.log | grep "$(date '+%b %d')" | tail -5)
    if [ ! -z "$new_users" ]; then
        log "WARNING" "New user accounts created: $new_users"
    fi

    # Check for sudo usage
    local sudo_usage=$(grep "sudo" /var/log/auth.log | grep "$(date '+%b %d')" | grep "COMMAND" | tail -10)
    if [ ! -z "$sudo_usage" ]; then
        log "INFO" "Recent sudo usage: $sudo_usage"
    fi
}

# Monitor system resources
check_system_resources() {
    # CPU Usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    if [ "${cpu_usage%.*}" -gt 90 ]; then
        log "WARNING" "High CPU usage: ${cpu_usage}%"
    fi

    # Memory Usage
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt 90 ]; then
        log "WARNING" "High memory usage: ${mem_usage}%"
    fi

    # Disk Usage
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        log "WARNING" "High disk usage: ${disk_usage}%"
    fi

    # Network Connections
    local connections=$(netstat -an | grep ESTABLISHED | wc -l)
    if [ "$connections" -gt 1000 ]; then
        log "WARNING" "High number of network connections: $connections"
    fi

    # Load Average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    local load_num=${load_avg%.*}
    local cpu_cores=$(nproc)
    if [ "$load_num" -gt "$cpu_cores" ]; then
        log "WARNING" "High load average: $load_avg (CPU cores: $cpu_cores)"
    fi
}

# Check for suspicious processes
check_suspicious_processes() {
    # Check for processes with unusual names
    local suspicious_procs=$(ps aux | grep -E '\.\./|/dev/shm|/tmp/|nc\.|netcat|python.*socket|perl.*socket' | grep -v grep)
    if [ ! -z "$suspicious_procs" ]; then
        log "CRITICAL" "Suspicious processes detected: $suspicious_procs"
    fi

    # Check for processes running from /tmp
    local tmp_procs=$(ps aux | awk '$11 ~ /^\/tmp\//' | grep -v grep)
    if [ ! -z "$tmp_procs" ]; then
        log "CRITICAL" "Processes running from /tmp: $tmp_procs"
    fi

    # Check for hidden processes
    local hidden_procs=$(ps -ef | awk '{print $9}' | grep -E '^\[' | wc -l)
    if [ "$hidden_procs" -gt 20 ]; then
        log "WARNING" "Unusual number of kernel processes: $hidden_procs"
    fi
}

# Monitor network security
check_network_security() {
    # Check for open ports
    local open_ports=$(netstat -tuln | grep LISTEN | awk '{print $4}' | awk -F':' '{print $NF}' | sort -n | uniq)
    log "DEBUG" "Open ports: $open_ports"

    # Check for connections to known malicious IPs
    local malicious_ips_file="$CONFIG_DIR/malicious-ips.txt"
    if [ -f "$malicious_ips_file" ]; then
        while read -r ip; do
            local connections=$(netstat -an | grep ESTABLISHED | grep "$ip" | wc -l)
            if [ "$connections" -gt 0 ]; then
                log "CRITICAL" "Connections to malicious IP $ip: $connections"
            fi
        done < "$malicious_ips_file"
    fi

    # Check for unusual outbound connections
    local outbound_ports=$(netstat -an | grep ESTABLISHED | awk '$5 ~ /^[0-9]/' | awk -F':' '{print $NF}' | sort | uniq -c | sort -nr | head -5)
    log "DEBUG" "Top outbound ports: $outbound_ports"

    # DNS queries monitoring
    local dns_queries=$(grep "$(date '+%b %d')" /var/log/syslog | grep "query" | tail -10)
    if [ ! -z "$dns_queries" ]; then
        log "DEBUG" "Recent DNS queries: $dns_queries"
    fi
}

# File integrity monitoring
check_file_integrity() {
    # Use AIDE if available
    if command -v aide &> /dev/null; then
        local aide_output=$(aide --check 2>&1 || true)
        if echo "$aide_output" | grep -q "changed"; then
            log "CRITICAL" "File integrity check failed: $aide_output"
        fi
    fi

    # Check for SUID/SGID files in suspicious locations
    local suid_files=$(find /tmp /var/tmp -type f -perm +4000 2>/dev/null | wc -l)
    if [ "$suid_files" -gt 0 ]; then
        log "CRITICAL" "SUID files in /tmp: $suid_files"
    fi

    # Check for world-writable files in critical directories
    local www_files=$(find /etc /bin /sbin /usr/bin -type f -perm -002 2>/dev/null | wc -l)
    if [ "$www_files" -gt 0 ]; then
        log "WARNING" "World-writable files in system directories: $www_files"
    fi

    # Check for new cron jobs
    local cron_changes=$(find /etc/cron* -type f -newer /tmp/last-cron-check 2>/dev/null | wc -l)
    if [ "$cron_changes" -gt 0 ]; then
        log "WARNING" "New cron jobs detected"
    fi
    touch /tmp/last-cron-check
}

# Malware detection
check_malware() {
    # Use ClamAV if available
    if command -v clamscan &> /dev/null; then
        # Quick scan of critical directories
        local scan_results=$(clamscan --recursive --infected /etc /bin /sbin /usr/bin 2>/dev/null | grep "Infected files" || true)
        if [ ! -z "$scan_results" ]; then
            log "CRITICAL" "Malware detected: $scan_results"
        fi
    fi

    # Check for web shells
    local web_shell_patterns="(\bshell_exec\b|\bpassthru\b|\bsystem\b|\beval\b|\bexec\b|\bacunetix\b|\bwebshell\b)"
    local web_shells=$(grep -rE "$web_shell_patterns" /var/www/html 2>/dev/null | head -10 || true)
    if [ ! -z "$web_shells" ]; then
        log "CRITICAL" "Potential web shells found: $web_shells"
    fi

    # Check for suspicious PHP files
    local suspicious_php=$(find /var/www -name "*.php" -size +50k 2>/dev/null | head -5)
    if [ ! -z "$suspicious_php" ]; then
        log "WARNING" "Large PHP files found: $suspicious_php"
    fi
}

# Generate security report
generate_report() {
    local report_file="$LOG_DIR/daily-report-$(date +%Y%m%d).html"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .critical { color: #d32f2f; }
        .warning { color: #f57c00; }
        .info { color: #1976d2; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { width: 100%; height: 200px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Monitoring Report</h1>
        <p>Generated: $(date)</p>
        <p>Server: $(hostname)</p>
    </div>

    <div class="section">
        <h2>System Overview</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Uptime</td><td>$(uptime -p)</td></tr>
            <tr><td>Load Average</td><td>$(uptime | awk -F'load average:' '{print $2}')</td></tr>
            <tr><td>Memory Usage</td><td>$(free -h | grep Mem | awk '{print $3"/"$2}') ($(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')%)</td></tr>
            <tr><td>Disk Usage</td><td>$(df -h / | awk 'NR==2 {print $3"/"$2 " ("$5")"}')</td></tr>
            <tr><td>Network Connections</td><td>$(netstat -an | grep ESTABLISHED | wc -l)</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Security Events Today</h2>
        <table>
            <tr><th>Event Type</th><th>Count</th><th>Details</th></tr>
EOF

    # Count events from logs
    local failed_logins=$(grep "$(date '+%b %d')" /var/log/auth.log | grep "Failed password" | wc -l)
    local sudo_commands=$(grep "$(date '+%b %d')" /var/log/auth.log | grep "sudo.*COMMAND" | wc -l)
    local firewall_blocks=$(grep "$(date '+%b %d')" /var/log/kern.log | grep "iptables-drop" | wc -l)
    local fail2ban_bans=$(grep "$(date '+%b %d')" /var/log/fail2ban.log | grep "Ban " | wc -l)

    cat >> "$report_file" << EOF
            <tr><td>Failed Logins</td><td>$failed_logins</td><td>Unsuccessful authentication attempts</td></tr>
            <tr><td>Sudo Commands</td><td>$sudo_commands</td><td>Privileged commands executed</td></tr>
            <tr><td>Firewall Blocks</td><td>$firewall_blocks</td><td>Packets dropped by firewall</td></tr>
            <tr><td>Fail2Ban Bans</td><td>$fail2ban_bans</td><td>IPs banned by Fail2Ban</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Top Threat Sources</h2>
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th><th>Country</th></tr>
EOF

    # Get top failed login IPs
    grep "$(date '+%b %d')" /var/log/auth.log | grep "Failed password" | awk '{print $NF}' | sort | uniq -c | sort -nr | head -10 | while read count ip; do
        country=$(geoiplookup "$ip" 2>/dev/null | awk -F': ' '{print $2}' || echo "Unknown")
        echo "<tr><td>$ip</td><td>$count</td><td>$country</td></tr>" >> "$report_file"
    done

    cat >> "$report_file" << EOF
        </table>
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        <ul>
EOF

    # Generate recommendations based on findings
    if [ "$failed_logins" -gt 50 ]; then
        echo "<li class='warning'>Consider implementing IP whitelisting for SSH access due to high failed login attempts</li>" >> "$report_file"
    fi

    if [ "$firewall_blocks" -gt 100 ]; then
        echo "<li class='warning'>High number of firewall blocks detected. Review security logs for patterns.</li>" >> "$report_file"
    fi

    if [ "$fail2ban_bans" -gt 20 ]; then
        echo "<li class='info'>Fail2Ban is actively protecting against attacks. Consider increasing ban duration for repeat offenders.</li>" >> "$report_file"
    fi

    cat >> "$report_file" << EOF
            <li>Regular security audits are recommended</li>
            <li>Keep all system packages updated</li>
            <li>Review user permissions regularly</li>
        </ul>
    </div>
</body>
</html>
EOF

    log "INFO" "Security report generated: $report_file"

    # Email report if configured
    if command -v mail &> /dev/null; then
        (
            echo "To: $ALERT_EMAIL"
            echo "Subject: Daily Security Report - $(hostname) - $(date +%Y-%m-%d)"
            echo "Content-Type: text/html"
            echo ""
            cat "$report_file"
        ) | sendmail "$ALERT_EMAIL"
    fi
}

# Real-time monitoring daemon
monitor_daemon() {
    log "INFO" "Starting security monitoring daemon..."
    local daemon_pid="$PID_DIR/monitor.pid"
    echo $$ > "$daemon_pid"

    # Trap signals for graceful shutdown
    trap 'rm -f "$daemon_pid"; log "INFO" "Monitoring daemon stopped"; exit 0' SIGTERM SIGINT

    # Main monitoring loop
    while true; do
        # Run all monitoring checks
        check_login_security
        check_system_resources
        check_suspicious_processes
        check_network_security
        check_file_integrity
        check_malware

        # Sleep for configured interval
        sleep 60
    done
}

# Test monitoring functions
test_monitoring() {
    log "INFO" "Running security monitoring tests..."

    echo "Testing login security check..."
    check_login_security
    echo "✓ Login security check complete"

    echo "Testing system resources check..."
    check_system_resources
    echo "✓ System resources check complete"

    echo "Testing suspicious processes check..."
    check_suspicious_processes
    echo "✓ Suspicious processes check complete"

    echo "Testing network security check..."
    check_network_security
    echo "✓ Network security check complete"

    echo "Testing file integrity check..."
    check_file_integrity
    echo "✓ File integrity check complete"

    echo "Testing malware detection..."
    check_malware
    echo "✓ Malware detection complete"

    echo "Generating test report..."
    generate_report
    echo "✓ Test report generated"

    log "INFO" "All monitoring tests completed successfully"
}

# Install monitoring suite
install_suite() {
    log "INFO" "Installing security monitoring suite..."

    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi

    # Copy script to system directory
    cp "$0" "$SCRIPT_DIR/security-monitoring-suite"
    chmod +x "$SCRIPT_DIR/security-monitoring-suite"

    # Create systemd service
    cat > /etc/systemd/system/security-monitor.service << EOF
[Unit]
Description=Security Monitoring Suite
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_DIR/security-monitoring-suite --daemon
Restart=always
RestartSec=30
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable service
    systemctl enable security-monitor

    # Initialize monitoring
    init_monitor

    log "INFO" "Security monitoring suite installed successfully!"
    echo ""
    echo "Commands:"
    echo "  Start service: systemctl start security-monitor"
    echo "  Stop service: systemctl stop security-monitor"
    echo "  Check status: systemctl status security-monitor"
    echo "  View logs: tail -f $LOG_DIR/monitor.log"
    echo "  Run test: $SCRIPT_DIR/security-monitoring-suite --test"
}

# Main execution
main() {
    case "${1:-}" in
        --install)
            install_suite
            ;;
        --start)
            systemctl start security-monitor
            log "INFO" "Security monitoring service started"
            ;;
        --stop)
            systemctl stop security-monitor
            log "INFO" "Security monitoring service stopped"
            ;;
        --status)
            systemctl status security-monitor
            ;;
        --test)
            TEST_MODE=true
            init_monitor
            test_monitoring
            ;;
        --daemon)
            DAEMON_MODE=true
            init_monitor
            monitor_daemon
            ;;
        *)
            echo "Security Monitoring Suite"
            echo ""
            echo "Usage: $0 [COMMAND]"
            echo ""
            echo "Commands:"
            echo "  --install    Install the monitoring suite"
            echo "  --start      Start the monitoring service"
            echo "  --stop       Stop the monitoring service"
            echo "  --status     Check service status"
            echo "  --test       Run monitoring tests"
            echo "  --daemon     Run as daemon (for systemd)"
            echo "  --verbose    Enable verbose output"
            echo ""
            echo "Examples:"
            echo "  sudo $0 --install    # Install the suite"
            echo "  sudo $0 --test       # Run tests"
            echo ""
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"