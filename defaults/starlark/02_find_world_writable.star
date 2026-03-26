# Demo: Find World Writable Files
def on_scan(ctx):
    files = fs.find("/", mode="0777")
    for f in files:
        emit_alert("World-writable file found: " + f.path, severity="medium")
