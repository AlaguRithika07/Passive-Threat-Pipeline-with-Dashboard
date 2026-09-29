import time
import uuid
import asyncio
from typing import Callable, Awaitable
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from config import ALERT_CONFIDENCE_THRESHOLD
from schema import AlertSchema, FlowIdentifier
from features.extractor import FeatureExtractor
from models.threat_classifier import ThreatClassifier

class PassiveStreamingPipeline:
    def __init__(self, alert_callback: Callable[[dict], Awaitable[None]]):
        self.extractor = FeatureExtractor()
        self.classifier = ThreatClassifier()
        self.alert_callback = alert_callback
        self.packet_buffer = []

    def process_packet(self, raw_pkt):
        """Converts raw packet into metadata dict cleanly without writing back."""
        if not raw_pkt.haslayer(IP):
            return

        pkt_data = {
            "src_ip": raw_pkt[IP].src,
            "dst_ip": raw_pkt[IP].dst,
            "length": len(raw_pkt),
            "timestamp": time.time(),
            "protocol": "OTHER",
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": None,
            "dns_query": None,
            "ja3": "N/A"
        }

        if raw_pkt.haslayer(TCP):
            pkt_data["protocol"] = "TCP"
            pkt_data["src_port"] = raw_pkt[TCP].sport
            pkt_data["dst_port"] = raw_pkt[TCP].dport
            pkt_data["tcp_flags"] = str(raw_pkt[TCP].flags)
        elif raw_pkt.haslayer(UDP):
            pkt_data["protocol"] = "UDP"
            pkt_data["src_port"] = raw_pkt[UDP].sport
            pkt_data["dst_port"] = raw_pkt[UDP].dport

        if raw_pkt.haslayer(DNS) and raw_pkt.haslayer(DNSQR):
            try:
                pkt_data["dns_query"] = raw_pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            except Exception:
                pkt_data["dns_query"] = None

        self.packet_buffer.append(pkt_data)

    async def run_window_cycle(self):
        """Evaluates buffers periodically according to streaming window intervals."""
        if not self.packet_buffer:
            return

        current_buffer = list(self.packet_buffer)
        self.packet_buffer.clear()

        # Extract features from packet window
        features = self.extractor.process_window(current_buffer)

        for feat in features:
            threat_label, confidence, evidence = self.classifier.classify_and_score(feat)

            if threat_label != "Normal" and confidence >= ALERT_CONFIDENCE_THRESHOLD:
                # Severity Calculator
                severity = "CRITICAL" if confidence >= 0.90 else "HIGH" if confidence >= 0.80 else "MEDIUM"
                
                # Build Standardized Alert
                alert = AlertSchema(
                    alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    flow_id=FlowIdentifier(
                        src_ip=feat["src_ip"],
                        dst_ip=feat["dst_ip"],
                        src_port=feat.get("src_port", 0),
                        dst_port=feat.get("dst_port", 0),
                        protocol=feat["protocol"]
                    ),
                    threat_class=threat_label,
                    confidence_score=round(confidence, 3),
                    severity=severity,
                    evidence=evidence
                )

                # Dump Pydantic schema safely across Pydantic v1 / v2
                try:
                    alert_dict = alert.model_dump()
                except AttributeError:
                    alert_dict = alert.dict()

                # Trigger alert callback to Dashboard WebSocket
                await self.alert_callback(alert_dict)