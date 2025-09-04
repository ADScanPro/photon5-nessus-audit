# Photon OS 5 Nessus Unix Compliance Audit

This repository contains a custom Tenable Nessus Unix Compliance audit for VMware Photon OS 5: `photon_5_nessus_unix.audit`.

The audit was built by converting Photon 5 STIG-like Ruby controls (PHTN-50-*.rb) to Unix `custom_item`s. Each `custom_item` in the `.audit` file includes a "Source: PHTN-50-xxxxx.rb" comment for traceability.

## Usage
- Import `photon_5_nessus_unix.audit` into a Nessus (or Tenable.sc/Manager) compliance policy.
- Select Check Type: Unix.
- Run the scan with SSH credentials that allow reading config files and running `sshd -T` and `auditctl -l` (root recommended or equivalent sudo rights).
- This audit is intended for Photon OS 5. A platform guard checks `/etc/os-release`.

## Mapping (PHTN-50 control -> audit custom item)

### SSHD hardening
- PHTN-50-000200 -> SyslogFacility AUTHPRIV/AUTH (CMD_EXEC)
- PHTN-50-000201 -> LogLevel INFO (CMD_EXEC)
- PHTN-50-000069 -> ClientAliveInterval 900 (CMD_EXEC)
- PHTN-50-000203 -> ClientAliveCountMax 0 (CMD_EXEC)
- PHTN-50-000221 -> LoginGraceTime 30 (CMD_EXEC)
- PHTN-50-000207 -> PermitEmptyPasswords no (CMD_EXEC)
- PHTN-50-000208 -> PermitUserEnvironment no (CMD_EXEC)
- PHTN-50-000211 -> GSSAPIAuthentication no (CMD_EXEC)
- PHTN-50-000214 -> KerberosAuthentication no (CMD_EXEC)
- PHTN-50-000216 -> PrintLastLog yes (CMD_EXEC)
- PHTN-50-000215 -> Compression no (CMD_EXEC)
- PHTN-50-000212 -> X11Forwarding no (CMD_EXEC)
- PHTN-50-000217 -> IgnoreRhosts yes (CMD_EXEC)
- PHTN-50-000218 -> IgnoreUserKnownHosts yes (CMD_EXEC)
- PHTN-50-000219 -> MaxAuthTries 6 (CMD_EXEC)
- PHTN-50-000213 -> StrictModes yes (CMD_EXEC)
- PHTN-50-000220 -> AllowTcpForwarding no (CMD_EXEC)
- PHTN-50-000005 -> Banner /etc/issue (CMD_EXEC)
- PHTN-50-000079 -> Ciphers approved set (CMD_EXEC)
- PHTN-50-000239 -> MACs approved set (CMD_EXEC)
- PHTN-50-000188 -> HostbasedAuthentication no (CMD_EXEC)
- PHTN-50-000233 -> SSH public host keys 0644 root:root (CMD_EXEC)
- PHTN-50-000234 -> SSH private host keys 0600 root:root (CMD_EXEC)

### PAM and password policy
- PHTN-50-000059 -> pam_unix.so uses sha512 (FILE_CONTENT_CHECK)
- PHTN-50-000247 -> no nullok in system-password/system-auth (FILE_CONTENT_CHECK)
- PHTN-50-000197 -> pam_pwquality on password line (FILE_CONTENT_CHECK)
- PHTN-50-000044 -> minlen >= 15 (FILE_CONTENT_CHECK)
- PHTN-50-000035 -> ucredit = -1 (FILE_CONTENT_CHECK)
- PHTN-50-000037 -> dcredit = -1 (FILE_CONTENT_CHECK)
- PHTN-50-000036 -> lcredit = -1 (FILE_CONTENT_CHECK)
- PHTN-50-000086 -> ocredit = -1 (FILE_CONTENT_CHECK)
- PHTN-50-000038 -> difok >= 8 (FILE_CONTENT_CHECK)
- PHTN-50-000184 -> dictcheck = 1 (FILE_CONTENT_CHECK)
- PHTN-50-000235 -> enforce_for_root present (FILE_CONTENT_CHECK)
- PHTN-50-000043 -> pwhistory remember >= 5 (FILE_CONTENT_CHECK)
- PHTN-50-000243 -> pwhistory use_authtok present (FILE_CONTENT_CHECK)
- PHTN-50-000206 -> pam_faildelay delay=4000000 in system-auth (FILE_CONTENT_CHECK)
- PHTN-50-000192 -> pam_faillock preauth before pam_unix, authfail after (FILE_CONTENT_CHECK)
- PHTN-50-000108 -> faillock unlock_time = 0 (FILE_CONTENT_CHECK)
- PHTN-50-000004 -> faillock deny <= 3 and fail_interval >= 900 (FILE_CONTENT_CHECK)
- PHTN-50-000193 -> faillock.conf silent (FILE_CONTENT_CHECK)
- PHTN-50-000194 -> faillock.conf audit (FILE_CONTENT_CHECK)
- PHTN-50-000195 -> faillock.conf even_deny_root (FILE_CONTENT_CHECK)
- PHTN-50-000196 -> faillock.conf dir = /var/log/faillock (FILE_CONTENT_CHECK)

### login.defs
- PHTN-50-000039 -> ENCRYPT_METHOD SHA512 (FILE_CONTENT_CHECK)
- PHTN-50-000041 -> PASS_MIN_DAYS 1 (FILE_CONTENT_CHECK)
- PHTN-50-000042 -> PASS_MAX_DAYS <= 90 (FILE_CONTENT_CHECK)
- PHTN-50-000185 -> FAIL_DELAY >= 4 (FILE_CONTENT_CHECK)
- PHTN-50-000187 -> UMASK 077 (FILE_CONTENT_CHECK)
- PHTN-50-000209 -> CREATE_HOME yes (FILE_CONTENT_CHECK)

### auditd (auditctl -l)
- PHTN-50-000003 -> watch useradd/groupadd (CMD_EXEC)
- PHTN-50-000076 -> watch usermod/groupmod (CMD_EXEC)
- PHTN-50-000078 -> watch userdel/groupdel (CMD_EXEC)
- PHTN-50-000204 -> watch passwd/shadow/group/gshadow (CMD_EXEC)
- PHTN-50-000173 -> watch faillog/lastlog/tallylog (CMD_EXEC)
- PHTN-50-000238 -> watch /etc/security/opasswd (CMD_EXEC)
- PHTN-50-000019 -> execpriv execve rules (b32/b64) (CMD_EXEC)
- PHTN-50-000031 -> DAC permission modification syscalls (b32/b64) (CMD_EXEC)
- PHTN-50-000175 -> init_module rules (b32/b64) (CMD_EXEC)

### Package manager (tdnf)
- PHTN-50-000130 -> gpgcheck enabled (FILE_CONTENT_CHECK)
- PHTN-50-000161 -> clean_requirements_on_remove enabled (FILE_CONTENT_CHECK)
- PHTN-50-000199 -> repos gpgcheck=1 (CMD_EXEC)

### Time synchronization
- PHTN-50-000121 -> timesyncd NTP configured (if used) (FILE_CONTENT_CHECK)
- PHTN-50-000121 -> ntpd servers/peer/multicastclient configured (if used) (FILE_CONTENT_CHECK)
- PHTN-50-000121 -> chrony server configured (if used) (FILE_CONTENT_CHECK)

### rsyslog
- PHTN-50-000074 -> $umask 0037 (FILE_CONTENT_CHECK)
- PHTN-50-000111 -> remote offload to syslog server (FILE_CONTENT_CHECK)
- PHTN-50-000242 -> rsyslog enabled and running (CMD_EXEC)
- PHTN-50-000241 -> rsyslog installed (CMD_EXEC)

### Accounts, packages and boot security
- PHTN-50-000007 -> limits.conf maxlogins 10 (FILE_CONTENT_CHECK)
- PHTN-50-000012 -> rsyslog logs auth.*,authpriv.*,daemon.* (FILE_CONTENT_CHECK)
- PHTN-50-000013 -> OpenSSL FIPS provider installed (CMD_EXEC)
- PHTN-50-000040 -> Telnet not installed (CMD_EXEC)
- PHTN-50-000046 -> GRUB superusers/password_pbkdf2 (FILE_CONTENT_CHECK)
- PHTN-50-000047 -> modprobe disables nonessential modules (FILE_CONTENT_CHECK)
- PHTN-50-000049 -> No duplicate UIDs (CMD_EXEC)
- PHTN-50-000066 -> SELinux enforcing (CMD_EXEC)
- PHTN-50-000073 -> /var/log owner/perms (CMD_EXEC)
- PHTN-50-000080 -> kernel cmdline audit=1 (CMD_EXEC)
- PHTN-50-000085 -> /usr/lib ownership and perms (CMD_EXEC)
- PHTN-50-000127 -> AIDE installed (CMD_EXEC)
- PHTN-50-000133 -> sudo NOPASSWD re-auth enforcement (CMD_EXEC)
- PHTN-50-000222 -> ctrl-alt-del.target masked/inactive (CMD_EXEC)

### Kernel/sysctl
- PHTN-50-000231 -> net.ipv4.ip_forward = 0 (CMD_EXEC; may be N/A on container hosts)
- PHTN-50-000223 -> accept_source_route = 0 for v4/v6 (CMD_EXEC)
- PHTN-50-000224 -> net.ipv4.icmp_echo_ignore_broadcasts = 1 (CMD_EXEC)
- PHTN-50-000225 -> accept_redirects = 0 (CMD_EXEC)
- PHTN-50-000226 -> secure_redirects = 0 (CMD_EXEC)
- PHTN-50-000227 -> send_redirects = 0 (CMD_EXEC)
- PHTN-50-000228 -> log_martians = 1 (CMD_EXEC)
- PHTN-50-000229 -> rp_filter = 1 (CMD_EXEC)
- PHTN-50-000232 -> net.ipv4.tcp_timestamps = 1 (CMD_EXEC)
- PHTN-50-000068 -> net.ipv4.tcp_syncookies = 1 (CMD_EXEC)
- PHTN-50-000067 -> kernel.dmesg_restrict = 1 (CMD_EXEC)
- PHTN-50-000160 -> kernel.randomize_va_space = 2 (CMD_EXEC)
- PHTN-50-000105 -> fs.protected_symlinks = 1 (CMD_EXEC)
- PHTN-50-000244 -> fs.protected_hardlinks = 1 (CMD_EXEC)
- PHTN-50-000246 -> fs.suid_dumpable = 0 (CMD_EXEC)
- PHTN-50-000236 -> systemd fallback DNS disabled (CMD_EXEC)

### FIPS
- PHTN-50-000182 -> /proc/sys/crypto/fips_enabled = 1 (FILE_CONTENT_CHECK)

## Notes
- Some checks are environment-dependent (e.g., only one time service is typically in use, and container hosts may differ). This audit file does not use the non-standard 'optional' attribute for broader parser compatibility. If a check does not apply to your environment, adjust or comment it out accordingly.
- The SSHD crypto checks (Ciphers/MACs) enforce that only approved algorithms are present. The command outputs are matched against an allow-list regex.
- If you need to adapt values (e.g., different grace times or cipher suites), modify the corresponding `expect` lines in the `.audit` file.

## Testing
- Validate locally on a Photon OS 5 host:
  - `sshd -T | grep -i <param>`
  - `grep <key> /etc/pam.d/system-password`
  - `grep <key> /etc/security/pwquality.conf`
  - `grep ENCRYPT_METHOD /etc/login.defs`
  - `/sbin/auditctl -l`
  - `grep -E '^(NTP|server)' /etc/systemd/timesyncd.conf /etc/ntp.conf /etc/chrony/chrony.conf 2>/dev/null`

## License
MIT — see `LICENSE` for details.

## Disclaimer
This audit is provided as a best-effort conversion for Photon OS 5 and may require tuning for your environment and Nessus version. 
Always test in a non-production environment first.

## Contributing
See `CONTRIBUTING.md`. PRs and issues are welcome.
