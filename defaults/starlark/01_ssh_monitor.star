# Monitor SSH Configuration
# Check if SSH password authentication is enabled
ssh_config_check = run_command("defaults_read", ["com.apple.sshd"])
if "PasswordAuthentication" in ssh_config_check and "1" in ssh_config_check:
    report_finding(
        category="Network Security",
        name="SSH Password Auth Enabled",
        desc="SSH password authentication is enabled, making brute-force attacks possible",
        severity="medium",
        current_val="enabled",
        expected_val="disabled",
        passed=False,
        remediation_script="sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null || true"
    )
else:
    report_finding(
        category="Network Security",
        name="SSH Configuration",
        desc="SSH password authentication check completed",
        severity="info",
        current_val="checked",
        expected_val="disabled",
        passed=True
    )
