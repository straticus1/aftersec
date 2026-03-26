# Demo: Drop an AI Genkit-generated honeypot
def on_startup(ctx):
    # Deploys an irresistible decoy credential file using AI
    deploy_honeypot("aws_credentials", "/tmp/.aws/credentials")
    emit_alert("Dynamic Honeypot deployed to /tmp/.aws", severity="info")
