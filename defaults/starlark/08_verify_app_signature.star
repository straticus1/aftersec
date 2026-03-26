# Demo: Ensure critical apps are signed by Apple
def on_process_start(ctx):
    if ctx.process.name == "Terminal":
        sig = verify_signature(ctx.process.path)
        if not sig["valid"] or "Apple" not in sig["authority"]:
            emit_alert("Unsigned or modified Terminal binary detected!", severity="critical")
            return ACTION_BLOCK
    return ACTION_ALLOW
