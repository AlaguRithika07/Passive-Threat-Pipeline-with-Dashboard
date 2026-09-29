import asyncio
import random
import uuid
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from pipeline import PassiveStreamingPipeline

app = FastAPI(title="Passive Network Security Enclave")
templates = Jinja2Templates(directory="dashboard/templates")

connected_websockets = []

async def broadcast_alert(alert_data: dict):
    for ws in list(connected_websockets):
        try:
            await ws.send_json(alert_data)
        except Exception:
            if ws in connected_websockets:
                connected_websockets.remove(ws)

pipeline = PassiveStreamingPipeline(alert_callback=broadcast_alert)

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

async def simulate_passive_ingest():
    """Simulates passive traffic mirroring (synthetic stream generator)."""
    await asyncio.sleep(2)
    while True:
        try:
            # 1. Normal background packets
            for _ in range(30):
                pkt = IP(src="192.168.1.50", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="A")
                pipeline.process_packet(pkt)

            # 2. Inject simulated threat traffic periodically
            threat_type = random.choice(["ddos", "dns_tunnel", "scan", "exfil"])
            
            if threat_type == "ddos":
                for _ in range(120):
                    pkt = IP(src="10.66.66.1", dst=f"10.0.0.{random.randint(1, 255)}")/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
                    pipeline.process_packet(pkt)
            elif threat_type == "dns_tunnel":
                for _ in range(15):
                    long_subdomain = f"v1-exfil-{uuid.uuid4().hex}{uuid.uuid4().hex}.malicious-domain.com"
                    pkt = IP(src="192.168.1.105", dst="8.8.8.8")/UDP(sport=5353, dport=53)/DNS(qd=DNSQR(qname=long_subdomain))
                    pipeline.process_packet(pkt)
            elif threat_type == "scan":
                for port in range(20, 80):
                    pkt = IP(src="172.16.0.4", dst="10.0.0.5")/TCP(sport=44444, dport=port, flags="S")
                    pipeline.process_packet(pkt)
            elif threat_type == "exfil":
                for _ in range(30):
                    pkt = IP(src="192.168.1.200", dst="45.33.32.156")/TCP(sport=51112, dport=443)/(b"X" * 1400)
                    pipeline.process_packet(pkt)

            await pipeline.run_window_cycle()
        except Exception as e:
            print(f"Error in simulation loop: {e}")

        await asyncio.sleep(3)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(simulate_passive_ingest())