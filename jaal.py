"""
File: jaal.py
Description: Main driver file for our Jaal system that will invoke funtionality from
all three modules. At the moment, functionality simply reads test data from
MAWI group and performs packet summarization.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""
import random

from util import parse_pcap_packets, is_tcp_ip_packet, IP, TCP
from summarize import summarize_packet_data
from assignment import assign_flow_to_monitor

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether

from monitor import Monitor
from inference import inference_module

# PCAP file can be downloaded from this URL:
# http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html
PCAP_FILE = '201601011400.pcap'

MAX_MONITORS = 10

class JaalModule(object):
    def __init__(self):
         self.monitors = []
         self.flow_map = {}
    
    def call_inference_mod(self):
        summaries = []
        for monitor in self.monitors:
            summary = monitor.get_batch_summary()
            if summary is not None:
                summaries.append(summary)
        inference_module(summaries)
    
    def start(self, test_file=PCAP_FILE):
        for id in range(0, MAX_MONITORS):
            monitor_thread = Monitor(id, self)
            monitor_thread.start()
            self.monitors.append(monitor_thread)

        # Main method of execution, will just keep reading in packets
        # until we want it to stop
        num_pkts = 0
        atk_pkts = 0
        try:
            for pkt in PcapReader(test_file):

                if not is_tcp_ip_packet(pkt):
                    continue

                pkts_to_add = [pkt]

                # Randomly injecting traffic
                should_attack = random.randint(0, 100)
                if should_attack < 10 and (atk_pkts / num_pkts) < 0.1:

                    attack_type = random.randint(0, 5)

                    for loop in range(5, random.randint(10, 50)):
                        if (atk_pkts / num_pkts) >= 0.1:
                            break

                        # PORT_SCAN_RULE  -- same IP dest, different port numbers
                        atk_pkt = pkt
                        atk_pkt[TCP].dport += loop

                        pkts_to_add.append(atk_pkt)
                        atk_pkts += 1
                    
                    print("ADDED PORT ATTACK WITH {} PACKETS!".format(len(pkts_to_add) - 1))

                num_pkts += 1
                for new_pkt in pkts_to_add:
                    flow_assignment = assign_flow_to_monitor(pkt, self.monitors, self.flow_map)
                    self.monitors[flow_assignment].add_to_batch(pkt)

        except KeyboardInterrupt:
            for monitor_thread in self.monitors:
                monitor_thread.kill() 

        for monitor_thread in self.monitors:
            monitor_thread.join()

if __name__ == '__main__':
    module = JaalModule()
    module.start()
