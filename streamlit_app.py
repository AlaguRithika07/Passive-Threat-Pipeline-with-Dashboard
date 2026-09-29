import asyncio
import random
import uuid
import pandas as pd
import streamlit as st
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from pipeline import PassiveStreamingPipeline

st.set_page_config(
    page_title="Passive Network Threat Enclave",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Passive Network Security Enclave")
st.caption("Real-time threat monitoring and anomaly detection engine.")

# 1. Initialize session state for holding alerts (Corrected)
if "alerts" not in st.session_state:
    st.session_state.alerts = []

# Callback function to handle incoming alerts from the pipeline
async def handle_alert(alert_data: dict):
    st.session_state.alerts.insert(0, alert_data)
    # Keep only the latest 50 alerts in memory
    if len(st.session_state.alerts) > 50:
        st.session_state.alerts.pop()

# 2. Instantiate pipeline in Streamlit memory
@st.cache_resource
def get_pipeline():
    return PassiveStreamingPipeline(alert_callback=handle_alert)

pipeline = get_pipeline()

# Layout setup
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Control Center")
    run_sim = st.button("🚀 Run Threat Simulation Cycle", use_container_width=True)
    if st.button("🧹 Clear Alerts", use_container_width=True):
        st.session_state.alerts = []
        st.rerun()

    st.metric("Total Alerts Caught", len(st.session_state.alerts))

with col2:
    st.subheader("🚨 Real-Time Security Alerts")
    
    if run_sim:
        with st.spinner("Processing network packets & detecting threats..."):
            # Background normal traffic
            for _ in range(20):
                pkt = IP(src="192.168.1.50", dst="10.0.0.1")/TCP(sport=12345, dport=80, flags="A")
                pipeline.process_packet(pkt)

            # Inject simulated threat traffic
            threat_type = random.choice(["ddos", "dns_tunnel", "scan", "exfil"])
            
            if threat_type == "ddos":
                for _ in range(120):
                    pkt = IP(src="10.66.66.1", dst=f"10.0.0.{random.randint(1, 255)}")/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
                    pipeline.process_packet(pkt)
            elif threat_type == "dns_tunnel":
                for _ in range(15):
                    sub = f"v1-exfil-{uuid.uuid4().hex[:8]}.malicious.com"
                    pkt = IP(src="192.168.1.105", dst="8.8.8.8")/UDP(sport=5353, dport=53)/DNS(qd=DNSQR(qname=sub))
                    pipeline.process_packet(pkt)
            elif threat_type == "scan":
                for port in range(20, 60):
                    pkt = IP(src="172.16.0.4", dst="10.0.0.5")/TCP(sport=44444, dport=port, flags="S")
                    pipeline.process_packet(pkt)
            elif threat_type == "exfil":
                for _ in range(25):
                    pkt = IP(src="192.168.1.200", dst="45.33.32.156")/TCP(sport=51112, dport=443)/(b"X" * 1400)
                    pipeline.process_packet(pkt)

            # Trigger pipeline window analysis
            asyncio.run(pipeline.run_window_cycle())

    # Render alerts table/cards
    if st.session_state.alerts:
        df = pd.DataFrame(st.session_state.alerts)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No active threats detected yet. Click 'Run Threat Simulation Cycle' to test.")