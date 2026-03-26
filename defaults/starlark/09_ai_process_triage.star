# Demo: Periodic AI triage of raw process memory maps
def on_schedule_tick(ctx):
    procs = scan_processes()
    for p in procs:
        if p["score"] > 70:
            analysis = ai_analyze_threat("High-risk process detected: " + p["command"])
            emit_alert("AI Verdict on " + p["user"] + ": " + analysis, severity="high")
