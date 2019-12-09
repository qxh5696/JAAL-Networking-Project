"""
File: monitor.py

Description: Monitor class for the flow assignment module.

Language: python3

Author: Theodora Bendlin
"""

import pandas as pd
import util

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

        # Keeping track of the flows and packets that this monitor has
        self.flows = {}
        self.num_flows = 0
        self.num_packets = 0

        # The maximum number of packets that this thread will hold until it sends them
        # to the summarization and inference module
        self.batch_size = batch_size
    
    def get_batch_summary(self):
        """
            Helper function that will retrieve the summary for the monitor's batch
            of packets, and then remove them from the current batch.

            :return: (numpy array) summarized version of the monitor's packets from 0 
                to the batch size
        """
        if self.num_packets < self.batch_size:
            return None

        summary = summarize_packet_data(self.batch[:self.batch_size])
        self.batch.drop(self.batch.index[:self.batch_size], inplace=True)
        self.num_packets -= self.batch_size

        return summary
    
    def add_to_batch(self, pkt):
        """
            Adds the packet to the monitors dataframe. Updates an internal flow table
            to keep track of the flows specific to the monitor, which is used in flow
            assignment module.

            :param pkt: (scapy Packet) packet to add to the monitor
            
            :return: (boolean) T/F if the maximum batch size of the monitor has been exceeded
        """
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
