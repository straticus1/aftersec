# Demo: Monitor SSH Connections
def on_network_connect(ctx):
    if ctx.network.port == 22:
        emit_alert("SSH Connection Detected", severity="low")
    return ACTION_ALLOW
