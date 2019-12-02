"""
File: jaal.py
Description: Main driver file for our Jaal system that will invoke funtionality from
all three modules. At the moment, functionality simply reads test data from
MAWI group and performs packet summarization.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""

from util import parse_pcap_packets
from summarize import summarize_packet_data
from assignment import assign_flow_to_monitor

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether

from monitor import Monitor

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
    
    def start(self, test_file=PCAP_FILE):
        for id in range(0, MAX_MONITORS):
            monitor_thread = Monitor(id, self)
            monitor_thread.start()
            self.monitors.append(monitor_thread)

        # Main method of execution, will just keep reading in packets
        # until we want it to stop
        try:
            for pkt in PcapReader(test_file):

                #TODO: Randomly inject traffic, or create a transformed dataset that does that

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
