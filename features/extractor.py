import math
import hashlib
from collections import defaultdict
import numpy as np

class FeatureExtractor:
    @staticmethod
    def calculate_entropy(data_str: str) -> float:
        """Calculates Shannon Entropy for DGA/DNS tunneling detection."""
        if not data_str:
            return 0.0
        prob = [float(data_str.count(c)) / len(data_str) for c in set(data_str)]
        return -sum([p * math.log2(p) for p in prob])

    def process_window(self, packet_buffer: list) -> list:
        """Extracts engineered ML features from passive packet window."""
        features_list = []
        if not packet_buffer:
            return features_list

        # Group packets by Source IP to capture host behavior
        aggregated = defaultdict(list)
        for pkt in packet_buffer:
            aggregated[pkt['src_ip']].append(pkt)

        for src_ip, pkts in aggregated.items():
            total_pkts = len(pkts)
            total_bytes = sum(p['length'] for p in pkts)
            
            # Extract destination IPs and Ports safely
            dst_ips = [p['dst_ip'] for p in pkts]
            dst_ports = [p.get('dst_port', 0) for p in pkts]
            src_ports = [p.get('src_port', 0) for p in pkts]

            # 1. DDoS Features: Source IP & Port Entropy
            ip_entropy = self.calculate_entropy("".join(dst_ips))
            syn_count = sum(1 for p in pkts if p.get('tcp_flags') and 'S' in str(p.get('tcp_flags')))
            syn_ratio = syn_count / max(1, total_pkts)

            # 2. Beaconing: Inter-arrival time std-dev
            timestamps = sorted([p['timestamp'] for p in pkts])
            iats = np.diff(timestamps) if len(timestamps) > 1 else [0.0]
            iat_std = float(np.std(iats)) if len(iats) > 0 else 0.0

            # 3. DNS Anomalies: Query Length & Entropy
            dns_queries = [p['dns_query'] for p in pkts if p.get('dns_query')]
            dns_entropy = float(np.mean([self.calculate_entropy(q) for q in dns_queries])) if dns_queries else 0.0
            avg_dns_len = float(np.mean([len(q) for q in dns_queries])) if dns_queries else 0.0

            # 4. Reconnaissance: Fan-out ratio
            unique_dst_ports = len(set(dst_ports))
            fanout_ratio = unique_dst_ports / max(1, total_pkts)

            # 5. Data Exfiltration: Asymmetric ratio
            out_bytes = sum(p['length'] for p in pkts if p['src_ip'] == src_ip)
            in_bytes = sum(p['length'] for p in pkts if p['dst_ip'] == src_ip)
            asym_ratio = float(out_bytes / max(1, in_bytes))

            features_list.append({
                "src_ip": src_ip,
                "dst_ip": dst_ips[0] if dst_ips else "0.0.0.0",
                "src_port": src_ports[0] if src_ports else 0,
                "dst_port": dst_ports[0] if dst_ports else 0,
                "protocol": pkts[0].get('protocol', 'TCP'),
                "total_pkts": total_pkts,
                "total_bytes": total_bytes,
                "syn_ratio": syn_ratio,
                "ip_entropy": ip_entropy,
                "iat_std": iat_std,
                "dns_entropy": dns_entropy,
                "avg_dns_len": avg_dns_len,
                "fanout_ratio": fanout_ratio,
                "asym_ratio": asym_ratio,
                "ja3": pkts[0].get('ja3', 'N/A')
            })

        return features_list