import os
import time
import logging
from typing import Callable, Optional
from scapy.all import PcapReader, IP, TCP, UDP, DNS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PCAPStreamer")

class PCAPStreamer:
    """
    Passively streams packets from a PCAP file without sending any probes,
    responding to handshakes, or writing back to the network.
    """
    def __init__(self, pcap_path: str, packet_callback: Callable):
        self.pcap_path = pcap_path
        self.packet_callback = packet_callback

    def stream_pcap(self, max_packets: Optional[int] = None, delay_between_packets: float = 0.001):
        if not os.path.exists(self.pcap_path):
            logger.error(f"PCAP file not found: {self.pcap_path}")
            return

        logger.info(f"Starting passive streaming from: {self.pcap_path}")
        count = 0

        try:
            with PcapReader(self.pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    if pkt.haslayer(IP):
                        self.packet_callback(pkt)
                        count += 1
                        
                        if delay_between_packets > 0:
                            time.sleep(delay_between_packets)

                        if max_packets and count >= max_packets:
                            break
            logger.info(f"Finished streaming {count} packets from PCAP.")
        except Exception as e:
            logger.error(f"Error streaming PCAP: {str(e)}")