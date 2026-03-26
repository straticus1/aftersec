# Demo: Detect curl | bash
def on_process_start(ctx):
    if ctx.process.name == "curl":
        if ctx.process.parent.name in ["bash", "sh", "zsh"]:
            emit_alert("Suspicious curl piped to shell", severity="high")
            return ACTION_BLOCK
    return ACTION_ALLOW
