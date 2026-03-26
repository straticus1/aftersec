# Demo: Monitor /etc/shadow
def on_file_access(ctx):
    if ctx.file.path == "/etc/shadow":
        emit_alert("Sensitive file access: /etc/shadow", severity="high")
    return ACTION_ALLOW
