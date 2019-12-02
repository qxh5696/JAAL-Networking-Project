"""
    Thread class representing a monitor.
"""

import pandas as pd
import util

from threading import Thread

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether

from inference import inference_mod
from summarize import summarize_packet_data

MAX_BATCH = 250

class Monitor(Thread):
    def __init__(self, id, jaal_inst, batch_size=MAX_BATCH):
        Thread.__init__(self)

        # ID, useful for debugging
        self.id = id

        # To call events on the Jaal Module to trigger summary + inference
        self.jaal_inst = jaal_inst

        # Batch dataframe will hold all of the packets that are used for summarization
        self.batch = pd.DataFrame(columns=util.TCP_COLS)

        # Keeping track of the flows that this monitor has
        self.flows = {}
        self.num_flows = 0
        self.num_packets = 0

        # The maximum number of packets that this thread will hold until it sends them
        # to the summarization and inference module
        self.batch_size = batch_size

        # Determines when this thread should stop execution
        self.shouldStop = False
    
    def get_batch_summary(self):
        if self.num_packets < MAX_BATCH:
            return None

        summary = summarize_packet_data(self.batch[:MAX_BATCH])
        self.batch.drop(self.batch.index[:MAX_BATCH], inplace=True)
        return summary
    
    def add_to_batch(self, pkt):
        # Add the packet to the current dataframe
        is_success = util.add_pcap_packet_to_df(pkt, self.batch)

        if is_success:
            # Parse to see if this is a new flow
            src, dst = pkt[Ether].src, pkt[Ether].dst
            self.num_packets += 1

            if src not in self.flows:
                self.flows[src] = [dst]
                self.num_flows += 1
            elif src in self.flows and dst not in self.flows[src]:
                self.flows[src].append(dst)
                self.num_flows += 1
    
        return is_success

    def kill(self):
        self.shouldStop = True
    
    def run(self):
        while not self.shouldStop:
            if len(self.batch.index) >= self.batch_size:
                self.jaal_inst.call_inference_mod()