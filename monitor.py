"""
    Thread class representing a monitor.
"""

import pandas as pd
import util

from threading import Thread
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from summarize import summarize_packet_data
from constants import *

class Monitor(object):
    def __init__(self, id, batch_size=MAX_BATCH):

        # ID, useful for debugging
        self.id = id

        # Batch dataframe will hold all of the packets that are used for summarization
        self.batch = pd.DataFrame(columns=util.TCP_COLS)

        # Keeping track of the flows that this monitor has
        self.flows = {}
        self.num_flows = 0
        self.num_packets = 0

        # The maximum number of packets that this thread will hold until it sends them
        # to the summarization and inference module
        self.batch_size = batch_size
    
    def get_batch_summary(self):
        if self.num_packets < MAX_BATCH:
            return None

        summary = summarize_packet_data(self.batch[:MAX_BATCH])
        self.batch.drop(self.batch.index[:MAX_BATCH], inplace=True)
        self.num_packets -= MAX_BATCH

        return summary
    
    def add_to_batch(self, pkt):
        # Add the packet to the current dataframe
        is_success, self.batch = util.add_pcap_packet_to_df(pkt, self.batch)

        if is_success:
            print("Monitor {}: {} packets".format(self.id, self.num_packets))

            # Parse to see if this is a new flow
            src, dst = pkt[IP].src, pkt[IP].dst
            self.num_packets += 1

            if src not in self.flows:
                self.flows[src] = [dst]
                self.num_flows += 1
            elif src in self.flows and dst not in self.flows[src]:
                self.flows[src].append(dst)
                self.num_flows += 1
        
        return len(self.batch.index) >= self.batch_size