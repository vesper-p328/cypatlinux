#!/usr/bin/env bash
# ==============================================================================
# CyberPatriot Automated Linux Hardening & Auditing Script (Ubuntu/Debian)
# File: linux.sh
# ==============================================================================

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "[-] ERROR: This script must be run as root (use sudo ./linux.sh)" 
   exit 1
fi

# Set up directories and logging
BACKUP_DIR="/root/cypat_backups_$(date +%F_%H-%M-%S)"
REPORT_FILE="/root/cypat_audit_report.txt"
PROHIBITED_FILE="/root/cypat_prohibited_files.txt"
mkdir -p "$BACKUP_DIR"
touch "$REPORT_FILE" "$PROHIBITED_FILE"

echo "[+] Starting CyberPatriot Hardening Script (linux.sh)..."
echo "[+] Backups will be stored in: $BACKUP_DIR"
echo "[+] Audit report will be saved to: $REPORT_FILE"
echo "[+] Prohibited files list will be saved to: $PROHIBITED_FILE"

echo "==============================================================================" > "$REPORT_FILE"
echo "                    CYBERPATRIOT SYSTEM AUDIT REPORT                          " >> "$REPORT_FILE"
echo "==============================================================================" >> "$REPORT_FILE"

echo "==============================================================================" > "$PROHIBITED_FILE"
echo "                 CYBERPATRIOT PROHIBITED FILES SCANNER                        " >> "$PROHIBITED_FILE"
echo "==============================================================================" >> "$PROHIBITED_FILE"

# ------------------------------------------------------------------------------
# 1. BACKUP CRITICAL FILES
# ------------------------------------------------------------------------------
echo "[+] Backing up critical configuration files..."
cp -r /etc/pam.d "$BACKUP_DIR/" 2>/dev/null
cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers "$BACKUP_DIR/" 2>/dev/null
cp /etc/login.defs /etc/default/useradd /etc/sysctl.conf /etc/hosts "$BACKUP_DIR/" 2>/dev/null
cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null
cp -r /etc/apt "$BACKUP_DIR/" 2>/dev/null

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
grep -q "^\* hard core 0" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf

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
# 5. PASSWORD EXPIRY PROCESSES & PAM HARDENING
# ------------------------------------------------------------------------------
echo "[+] Configuring password expiry policies in /etc/login.defs..."

# Ensure PASS_MAX_DAYS, PASS_MIN_DAYS, and PASS_WARN_AGE are set even if commented out or missing
if grep -qE "^#?PASS_MAX_DAYS" /etc/login.defs; then
    sed -i 's/^#*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
else
    echo -e "PASS_MAX_DAYS\t90" >> /etc/login.defs
fi

if grep -qE "^#?PASS_MIN_DAYS" /etc/login.defs; then
    sed -i 's/^#*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t10/' /etc/login.defs
else
    echo -e "PASS_MIN_DAYS\t10" >> /etc/login.defs
fi

if grep -qE "^#?PASS_WARN_AGE" /etc/login.defs; then
    sed -i 's/^#*PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
else
    echo -e "PASS_WARN_AGE\t7" >> /etc/login.defs
fi

sed -i 's/^#*FAILLOG_ENAB.*/FAILLOG_ENAB\tyes/' /etc/login.defs
sed -i 's/^#*LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\tyes/' /etc/login.defs
sed -i 's/^#*SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\tyes/' /etc/login.defs

# Lock inactive accounts 30 days after password expiration by default
useradd -D -f 30

# Apply password expiry processes to root and all existing human users (UID >= 1000)
echo "[+] Enforcing password expiration rules (chage) on existing users..."
chage -M 90 -m 10 -W 7 root 2>/dev/null
for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    chage -M 90 -m 10 -W 7 -I 30 "$user"
    echo "    -> Applied expiry rules (Max: 90, Min: 10, Warn: 7, Inactive: 30) to $user"
done

echo "[+] Configuring PAM password complexity and history..."
apt-get update >/dev/null 2>&1
apt-get install -y libpam-pwquality >/dev/null 2>&1 || apt-get install -y libpam-cracklib >/dev/null 2>&1

# Disallow null passwords
sed -i 's/nullok//g' /etc/pam.d/common-auth
sed -i 's/nullok_secure//g' /etc/pam.d/common-auth

# Enforce password history and minimum length in common-password
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    if ! grep -q "remember=" /etc/pam.d/common-password; then
        sed -i '/pam_unix.so/s/$/ remember=5 minlen=10/' /etc/pam.d/common-password
    fi
fi

# Enforce complexity via pam_pwquality or pam_cracklib
if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password
elif grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
    sed -i 's/pam_cracklib.so.*/pam_cracklib.so retry=3 minlen=10 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password
fi

# Configure Account Lockout safely
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

echo -e "\n--- All Human Users (UID >= 1000) & Expiry Status ---" >> "$REPORT_FILE"
for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    echo "User: $user" >> "$REPORT_FILE"
    chage -l "$user" | grep -E "Maximum|Minimum|Warning|Inactive" >> "$REPORT_FILE"
    echo "-----------------------------------" >> "$REPORT_FILE"
done

echo -e "\n--- System/Hidden Users with Valid Login Shells ---" >> "$REPORT_FILE"
awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(false|nologin|sync|shutdown|halt)/) {print $1 " (UID: " $3 ", Shell: " $7 ")"}' /etc/passwd >> "$REPORT_FILE"

echo -e "\n--- Members of Sudo & Admin Groups ---" >> "$REPORT_FILE"
grep -E '^(sudo|admin|wheel|adm):' /etc/group >> "$REPORT_FILE"

echo -e "\n--- Sudoers File Anomalies (NOPASSWD or !authenticate) ---" >> "$REPORT_FILE"
grep -rnE '(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null >> "$REPORT_FILE"

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
# 7. DISABLE SSH ROOT LOGIN & HARDEN SSH
# ------------------------------------------------------------------------------
echo "[+] Disabling SSH root login and hardening SSH configuration..."
if [[ -d /etc/ssh ]]; then
    # 1. Override any hidden drop-in configs in /etc/ssh/sshd_config.d/
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        for conf in /etc/ssh/sshd_config.d/*.conf; do
            [[ -e "$conf" ]] || continue
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/gI' "$conf"
            sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/gI' "$conf"
        done
    fi

    # 2. Harden main /etc/ssh/sshd_config
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/gI' /etc/ssh/sshd_config
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/gI' /etc/ssh/sshd_config
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/gI' /etc/ssh/sshd_config
        sed -i 's/^#*X11Forwarding.*/X11Forwarding no/gI' /etc/ssh/sshd_config
        sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/gI' /etc/ssh/sshd_config
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/gI' /etc/ssh/sshd_config
        sed -i 's/^#*IgnoreRhosts.*/IgnoreRhosts yes/gI' /etc/ssh/sshd_config
        sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/gI' /etc/ssh/sshd_config
        sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/gI' /etc/ssh/sshd_config
        sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/gI' /etc/ssh/sshd_config
        sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/gI' /etc/ssh/sshd_config

        # Explicitly append if missing from the file
        grep -qi "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        grep -qi "^PermitEmptyPasswords" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
        grep -qi "^Protocol" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config

        systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1
        ufw limit ssh >/dev/null 2>&1
        echo "    -> PermitRootLogin set to 'no' and SSH service restarted."
    fi
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
    # Insecure Legacy Services
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
# 10. INTERACTIVE SERVICE AUDITING
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
# 11. SEARCH FOR PROHIBITED FILES (MEDIA, ARCHIVES, SCRIPTS, PCAPS)
# ------------------------------------------------------------------------------
echo "[+] Searching filesystem for prohibited files (saving to $PROHIBITED_FILE)..."

SEARCH_DIRS="/home /root /tmp /var/tmp /dev/shm /opt /srv /var/www"

echo -e "\n--- 1. Audio & Video Files ---" >> "$PROHIBITED_FILE"
find $SEARCH_DIRS -type f \( \
    -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.flac" \
    -o -iname "*.ogg" -o -iname "*.aac" -o -iname "*.wma" -o -iname "*.m4a" \
    -o -iname "*.avi" -o -iname "*.mov" -o -iname "*.mkv" -o -iname "*.flv" \
    -o -iname "*.wmv" -o -iname "*.webm" \
\) 2>/dev/null | grep -vE "/\.(cache|local|config|mozilla|thunderbird)/" >> "$PROHIBITED_FILE"

echo -e "\n--- 2. Images in User/Temp Directories (Excluding App Cache) ---" >> "$PROHIBITED_FILE"
find /home /root /tmp /var/tmp /dev/shm -type f \( \
    -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" \
    -o -iname "*.bmp" -o -iname "*.tiff" -o -iname "*.webp" \
\) 2>/dev/null | grep -vE "/\.(cache|local|config|mozilla|thunderbird|icons|themes)/" >> "$PROHIBITED_FILE"

echo -e "\n--- 3. Archives, Packet Captures, & Key/Password Files ---" >> "$PROHIBITED_FILE"
find $SEARCH_DIRS -type f \( \
    -iname "*.pcap" -o -iname "*.pcapng" -o -iname "*.cap" -o -iname "*.zip" \
    -o -iname "*.tar" -o -iname "*.tar.gz" -o -iname "*.tgz" -o -iname "*.rar" \
    -o -iname "*.7z" -o -iname "*.kdbx" -o -iname "*.ovpn" -o -iname "*password*" \
    -o -iname "*backdoor*" -o -iname "*exploit*" -o -iname "*hack*" \
\) 2>/dev/null | grep -vE "/\.(cache|local|config|mozilla)/" >> "$PROHIBITED_FILE"

echo -e "\n--- 4. Suspicious Scripts & Executables in User/Temp Directories ---" >> "$PROHIBITED_FILE"
find /home /root /tmp /var/tmp /dev/shm -type f \( \
    -iname "*.sh" -o -iname "*.py" -o -iname "*.pl" -o -iname "*.rb" \
    -o -iname "*.php" -o -iname "*.elf" -o -iname "*.exe" -o -iname "*.bat" \
\) 2>/dev/null | grep -vE "/\.(cache|local|config|mozilla|vscode)/" >> "$PROHIBITED_FILE"

echo -e "\n--- 5. Hidden Dot-Files in /home and /tmp (Excluding Standard Profiles) ---" >> "$PROHIBITED_FILE"
find /home /tmp /var/tmp /dev/shm -maxdepth 3 -type f -name ".*" 2>/dev/null | \
    grep -vE "(\.bashrc|\.bash_logout|\.profile|\.bash_history|\.sudo_as_admin_successful|\.pam_environment|\.Xauthority|\.ICEauthority|\.xsession-errors|\.viminfo|\.wget-hsts)" >> "$PROHIBITED_FILE"

echo "    -> Found $(grep -c '^/' "$PROHIBITED_FILE") potentially prohibited files! Review $PROHIBITED_FILE."

# ------------------------------------------------------------------------------
# 12. DEEP FORENSIC SCAN & AUDIT REPORT
# ------------------------------------------------------------------------------
echo "[+] Generating system audit report in $REPORT_FILE..."

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

echo -e "\n--- SUID / SGID Binaries (Look for GTFOBins like find, vim, bash, python, nmap) ---" >> "$REPORT_FILE"
find / -perm /6000 -type f 2>/dev/null | grep -v -E "^(/snap|/proc|/sys)" >> "$REPORT_FILE"

echo -e "\n--- World-Writable Files in /etc and /home ---" >> "$REPORT_FILE"
find /etc /home -type f -perm -0002 2>/dev/null >> "$REPORT_FILE"

echo -e "\n--- Unowned Files (No User or No Group) ---" >> "$REPORT_FILE"
find / -nouser -o -nogroup 2>/dev/null | grep -v -E "^(/proc|/sys|/dev)" >> "$REPORT_FILE"

# ------------------------------------------------------------------------------
# 13. CONFIGURE UPDATES & RUN FULL SYSTEM UPGRADE
# ------------------------------------------------------------------------------
echo "[+] Configuring APT repositories and daily automatic updates..."

# Ensure Ubuntu codename security and updates repos are present if using standard sources.list
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" == "ubuntu" && -n "$VERSION_CODENAME" && -f /etc/apt/sources.list ]]; then
        # Uncomment any commented-out security or updates lines
        sed -i 's/^# *deb \(.*-security.*\)/deb \1/' /etc/apt/sources.list
        sed -i 's/^# *deb \(.*-updates.*\)/deb \1/' /etc/apt/sources.list
        
        # Ensure security and updates pockets exist
        if ! grep -q "${VERSION_CODENAME}-security" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            echo "deb http://security.ubuntu.com/ubuntu ${VERSION_CODENAME}-security main restricted universe multiverse" >> /etc/apt/sources.list
        fi
        if ! grep -q "${VERSION_CODENAME}-updates" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            echo "deb http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME}-updates main restricted universe multiverse" >> /etc/apt/sources.list
        fi
    fi
fi

# Install and enable unattended-upgrades
apt-get update >/dev/null 2>&1
apt-get install -y unattended-upgrades apt-listchanges >/dev/null 2>&1

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

systemctl enable --now unattended-upgrades >/dev/null 2>&1

echo "[+] Installing auditd and rootkit scanners..."
apt-get install -y auditd audispd-plugins rkhunter chkrootkit debsums >/dev/null 2>&1
systemctl enable --now auditd >/dev/null 2>&1
auditctl -e 1 >/dev/null 2>&1

echo "[+] Running full system package upgrades (this may take a few minutes)..."
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
DEBIAN_FRONTEND=noninteractive apt-get autoclean -y

echo "=============================================================================="
echo "[+] HARDENING COMPLETE!"
echo "[!] 1. Review Prohibited Files: less $PROHIBITED_FILE"
echo "[!] 2. Review System Audit:     less $REPORT_FILE"
echo "=============================================================================="
