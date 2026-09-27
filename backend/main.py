"""
PS26145 AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Backend Service Entrypoint
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="PS26145 Cyber Threat Detection API",
    description="Passively ingested unidirectional traffic threat detection pipeline for NTRO",
    version="0.1.0",
)

# CORS configuration
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "service": "ps26145-backend",
        "version": "0.1.0",
        "architecture": "unidirectional-passive-monitoring",
        "threat_classes": [
            "ddos",
            "c2_beaconing",
            "dga_domains",
            "dns_tunnelling",
            "encrypted_malware",
            "reconnaissance",
            "data_exfiltration"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", 8000))
    uvicorn.run("backend.main:app", host=host, port=port, reload=True)
