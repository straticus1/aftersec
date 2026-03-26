# Demo: Prevent Crypto Miners
def on_process_start(ctx):
    miners = ["minerd", "xmrig", "ccminer"]
    if ctx.process.name in miners:
        emit_alert("Crypto miner blocked", severity="critical")
        return ACTION_BLOCK
    return ACTION_ALLOW
