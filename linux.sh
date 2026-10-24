#!/usr/bin/env bash
# ==============================================================================
# CyberPatriot Automated Linux Hardening & Auditing Script (Ubuntu/Debian)
# ==============================================================================

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "[-] ERROR: This script must be run as root (use sudo ./linux.sh)" 
   exit 1
fi

# Set up directories and logging
BACKUP_DIR="/root/cypat_backups_$(date +%F_%H-%M-%S)"
REPORT_FILE="/root/cypat_audit_report.txt"
mkdir -p "$BACKUP_DIR"
touch "$REPORT_FILE"

echo "[+] Starting CyberPatriot Hardening Script..."
echo "[+] Backups will be stored in: $BACKUP_DIR"
echo "[+] Audit report will be saved to: $REPORT_FILE"
echo "==============================================================================" > "$REPORT_FILE"
echo "                    CYBERPATRIOT SYSTEM AUDIT REPORT                          " >> "$REPORT_FILE"
echo "==============================================================================" >> "$REPORT_FILE"

# ------------------------------------------------------------------------------
# 1. BACKUP CRITICAL FILES
# ------------------------------------------------------------------------------
echo "[+] Backing up critical configuration files..."
cp -r /etc/pam.d "$BACKUP_DIR/"
cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers "$BACKUP_DIR/" 2>/dev/null
cp /etc/login.defs /etc/sysctl.conf /etc/hosts "$BACKUP_DIR/" 2>/dev/null
cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null

# ------------------------------------------------------------------------------
# 2. FIREWALL (UFW) & NETWORK SECURITY
# ------------------------------------------------------------------------------
echo "[+] Configuring Uncomplicated Firewall (UFW)..."
apt-get install -y ufw >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw logging on
ufw logging high
ufw --force enable

# Check /etc/hosts for suspicious redirections
echo -e "\n--- /etc/hosts Contents ---" >> "$REPORT_FILE"
cat /etc/hosts >> "$REPORT_FILE"

# ------------------------------------------------------------------------------
# 3. FILE PERMISSIONS & OWNERSHIP
# ------------------------------------------------------------------------------
echo "[+] Securing critical system file permissions..."
chown root:root /etc/passwd /etc/group /etc/sudoers /etc/sysctl.conf
chmod 644 /etc/passwd /etc/group /etc/sysctl.conf
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d

chown root:shadow /etc/shadow /etc/gshadow
chmod 640 /etc/shadow /etc/gshadow

# Secure cron directories
chown -R root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>/dev/null
chmod -R go-rwx /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>/dev/null

# Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf

# ------------------------------------------------------------------------------
# 4. KERNEL HARDENING (/etc/sysctl.conf)
# ------------------------------------------------------------------------------
echo "[+] Applying kernel hardening parameters (sysctl)..."
cat << 'EOF' >> /etc/sysctl.conf

# --- CyberPatriot Kernel Hardening ---
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

sysctl -p >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 5. PASSWORD POLICIES & PAM HARDENING
# ------------------------------------------------------------------------------
echo "[+] Hardening /etc/login.defs..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB    yes/' /etc/login.defs
sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB yes/' /etc/login.defs
sed -i 's/^SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB  yes/' /etc/login.defs

# Apply login.defs aging rules to all existing human users
echo "[+] Applying password aging to existing users..."
for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    chage -M 90 -m 10 -W 7 "$user"
done

echo "[+] Configuring PAM password complexity and history..."
# Install libpam-pwquality (Ubuntu 22.04+) or libpam-cracklib (older Ubuntu)
apt-get update >/dev/null 2>&1
apt-get install -y libpam-pwquality >/dev/null 2>&1 || apt-get install -y libpam-cracklib >/dev/null 2>&1

# Disallow null passwords
sed -i 's/nullok//g' /etc/pam.d/common-auth
sed -i 's/nullok_secure//g' /etc/pam.d/common-auth

# Enforce password history and strong hashing in common-password
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    if ! grep -q "remember=" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/s/$/ remember=5 minlen=10/' /etc/pam.d/common-password
    fi
fi

# Enforce complexity if pam_pwquality or pam_cracklib is present
if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password
elif grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
    sed -i 's/pam_cracklib.so.*/pam_cracklib.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password
fi

# Safely configure Account Lockout depending on PAM version (prevents bricking sudo)
if find /lib /usr/lib -name "pam_tally2.so" 2>/dev/null | grep -q "pam_tally2.so"; then
    if ! grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth
    fi
elif find /lib /usr/lib -name "pam_faillock.so" 2>/dev/null | grep -q "pam_faillock.so"; then
    if [[ -f /etc/security/faillock.conf ]]; then
        sed -i 's/^# *deny =.*/deny = 5/' /etc/security/faillock.conf
        sed -i 's/^# *unlock_time =.*/unlock_time = 1800/' /etc/security/faillock.conf
    fi
fi

# ------------------------------------------------------------------------------
# 6. USER & ROOT SECURITY
# ------------------------------------------------------------------------------
echo "[+] Locking root account..."
passwd -l root

echo -e "\n--- Users with UID 0 (Should ONLY be root!) ---" >> "$REPORT_FILE"
awk -F: '$3 == 0 {print $1}' /etc/passwd >> "$REPORT_FILE"

echo -e "\n--- All Human Users (UID >= 1000) - COMPARE WITH README! ---" >> "$REPORT_FILE"
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd >> "$REPORT_FILE"

echo -e "\n--- System/Hidden Users with Valid Login Shells ---" >> "$REPORT_FILE"
awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(false|nologin|sync|shutdown|halt)/) {print $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd >> "$REPORT_FILE"

echo -e "\n--- Members of Sudo & Admin Groups ---" >> "$REPORT_FILE"
grep -E '^(sudo|admin|wheel|adm):' /etc/group >> "$REPORT_FILE"

echo -e "\n--- Sudoers File Anomalies (NOPASSWD or !authenticate) ---" >> "$REPORT_FILE"
grep -rnE '(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null >> "$REPORT_FILE"

# Interactive bulk password change option
read -p "[?] Do you want to change passwords for all standard users (excluding yours) right now? (y/n): " CHANGE_PASS
if [[ "$CHANGE_PASS" =~ ^[Yy]$ ]]; then
    read -p "Enter YOUR current username (so we don't lock you out): " CURRENT_USER
    read -s -p "Enter the new strong password to apply to all other users (e.g., CyberPatriot2026!): " NEW_PASS
    echo ""
    for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
        if [[ "$user" != "$CURRENT_USER" ]]; then
            echo "$user:$NEW_PASS" | chpasswd
            echo "[+] Changed password for $user"
        fi
    done
fi

# ------------------------------------------------------------------------------
# 7. SSH HARDENING
# ------------------------------------------------------------------------------
if [[ -f /etc/ssh/sshd_config ]]; then
    echo "[+] Hardening /etc/ssh/sshd_config..."
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
    sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
    sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    
    # Ensure directives exist even if they weren't commented in the file
    grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    grep -q "^Protocol" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
    
    systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1
    ufw limit ssh >/dev/null 2>&1
fi

# ------------------------------------------------------------------------------
# 8. DISABLE GUEST ACCOUNT & AUTO-LOGIN (LightDM / GDM3)
# ------------------------------------------------------------------------------
echo "[+] Disabling guest accounts and auto-login..."
if [[ -d /etc/lightdm ]]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat << 'EOF' > /etc/lightdm/lightdm.conf.d/50-cypat-hardening.conf
[SeatDefaults]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
EOF
    sed -i 's/^autologin-user=.*/#autologin-user=/' /etc/lightdm/lightdm.conf 2>/dev/null
fi

if [[ -f /etc/gdm3/custom.conf ]]; then
    sed -i 's/^AutomaticLoginEnable.*/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
    sed -i 's/^TimedLoginEnable.*/TimedLoginEnable=false/' /etc/gdm3/custom.conf
fi

# ------------------------------------------------------------------------------
# 9. REMOVE PROHIBITED SOFTWARE, HACKING TOOLS & GAMES
# ------------------------------------------------------------------------------
echo "[+] Purging known hacking tools, insecure legacy daemons, and games..."
BAD_PACKAGES=(
    # Hacking & Cracking Tools
    john john-data hydra hydra-gtk aircrack-ng fcrackzip lcrack ophcrack ophcrack-cli
    pdfcrack pyrit rarcrack sipcrack irpas medusa nikto nmap zenmap wireshark
    tshark tcpdump ettercap-common ettercap-graphical dsniff kismet netcat
    netcat-traditional netcat-openbsd ncat cryptcat socat nemesis
    sqlmap metasploit-framework burpsuite
    # Insecure Legacy Services (Almost never allowed)
    telnetd inetutils-telnetd telnet rsh-server rsh-client talk talkd
    nis tftpd tftp-hpa tftpd-hpa xinetd openbsd-inetd
    # P2P / Torrents
    transmission-gtk transmission-common transmission-cli transmission-daemon
    deluge deluged vuze frostwire qbittorrent
    # Common Games
    aisleriot gnome-mines gnome-sudoku gnome-mahjongg ace-of-penguins
    freeciv-client-gtk freeciv-server minetest Endless-Sky
)

for pkg in "${BAD_PACKAGES[@]}"; do
    if dpkg -l | grep -qw "$pkg"; then
        echo "[-] Removing prohibited package: $pkg"
        apt-get purge -y "$pkg" >/dev/null 2>&1
    fi
done
apt-get autoremove -y >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 10. INTERACTIVE SERVICE AUDITING (Avoid Breaking Required Services!)
# ------------------------------------------------------------------------------
echo "[+] Checking common server services against README requirements..."
SERVICES=(
    "ssh:OpenSSH Server"
    "apache2:Apache Web Server"
    "nginx:Nginx Web Server"
    "vsftpd:Very Secure FTP Daemon"
    "pure-ftpd:Pure-FTPd Server"
    "proftpd:ProFTPD Server"
    "smbd:Samba File Sharing"
    "mysql:MySQL Database"
    "mariadb:MariaDB Database"
    "postgresql:PostgreSQL Database"
    "bind9:ISC BIND DNS Server"
    "isc-dhcp-server:ISC DHCP Server"
    "dovecot:Dovecot Mail Server"
    "postfix:Postfix Mail Server"
    "snmpd:SNMP Daemon"
    "cups:CUPS Printing Service"
    "avahi-daemon:Avahi ZeroConf Daemon"
)

for entry in "${SERVICES[@]}"; do
    svc="${entry%%:*}"
    desc="${entry#*:}"
    if systemctl is-active --quiet "$svc" 2>/dev/null || dpkg -l | grep -qw "$svc"; then
        read -p "[?] Service '$svc' ($desc) is installed/active. Is it REQUIRED by the README? (y/n): " KEEP_SVC
        if [[ "$KEEP_SVC" =~ ^[Nn]$ ]]; then
            echo "[-] Stopping and disabling $svc..."
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            apt-get purge -y "$svc" >/dev/null 2>&1
        else
            echo "[+] Keeping $svc active."
        fi
    fi
done

# ------------------------------------------------------------------------------
# 11. AUTOMATIC UPDATES CONFIGURATION
# ------------------------------------------------------------------------------
echo "[+] Configuring daily automatic updates..."
apt-get install -y unattended-upgrades >/dev/null 2>&1
cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat << 'EOF' > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# ------------------------------------------------------------------------------
# 12. DEEP FORENSIC SCAN & REPORT GENERATION
# ------------------------------------------------------------------------------
echo "[+] Generating deep audit report in $REPORT_FILE..."

echo -e "\n--- Active Listening Network Ports (Check PIDs & Binaries!) ---" >> "$REPORT_FILE"
ss -tulnp >> "$REPORT_FILE"

echo -e "\n--- Scheduled Cron Jobs & User Crontabs ---" >> "$REPORT_FILE"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab_out=$(crontab -u "$user" -l 2>/dev/null)
    if [[ -n "$crontab_out" ]]; then
        echo "Crontab for $user:" >> "$REPORT_FILE"
        echo "$crontab_out" >> "$REPORT_FILE"
        echo "-----------------------------------" >> "$REPORT_FILE"
    fi
done
ls -la /etc/cron* /var/spool/cron/crontabs >> "$REPORT_FILE" 2>/dev/null

echo -e "\n--- Media & Prohibited Files in /home ---" >> "$REPORT_FILE"
find /home -type f \( -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.flac" -o -iname "*.ogg" -o -iname "*.avi" -o -iname "*.mov" -o -iname "*.mkv" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.pcap" -o -iname "*.tar.gz" -o -iname "*.zip" \) 2>/dev/null >> "$REPORT_FILE"

echo -e "\n--- SUID / SGID Binaries (Look for GTFOBins like find, vim, bash, python, nmap) ---" >> "$REPORT_FILE"
find / -perm /6000 -type f 2>/dev/null | grep -v -E "^(/snap|/proc|/sys)" >> "$REPORT_FILE"

echo -e "\n--- World-Writable Files in /etc and /home ---" >> "$REPORT_FILE"
find /etc /home -type f -perm -0002 2>/dev/null >> "$REPORT_FILE"

echo -e "\n--- Hidden Scripts or SSH Keys in /home ---" >> "$REPORT_FILE"
find /home -name "authorized_keys" -o -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null >> "$REPORT_FILE"

# ------------------------------------------------------------------------------
# 13. INSTALL SECURITY TOOLS & RUN SYSTEM UPDATES
# ------------------------------------------------------------------------------
echo "[+] Installing auditd and rootkit scanners..."
apt-get install -y auditd audispd-plugins rkhunter chkrootkit debsums >/dev/null 2>&1
systemctl enable --now auditd >/dev/null 2>&1
auditctl -e 1 >/dev/null 2>&1

echo "[+] Running full system package upgrades (this may take a few minutes)..."
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
apt-get autoremove -y && apt-get autoclean -y

echo "=============================================================================="
echo "[+] HARDENING COMPLETE!"
echo "[!] NEXT STEP: Open $REPORT_FILE to finish manual user, cron, and media checks."
echo "=============================================================================="
