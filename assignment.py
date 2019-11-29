"""
File: inference.py
Description: Flow assignment module, functionality to be implemented in future work.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran

Due to time constraints, we are implementing the "flow assignment" module with threads. There is a 
single stream that reads in incoming TCP packets, and the flow assignment module will handle thread
pool assignment based on similar functionality described in the paper, where each "monitor" is a
thread of execution.
"""
import pandas as pd
import util

from threading import Thread

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether

from inference import inference_mod
from summarize import summarize_packet_data

MAX_MONITORS = 10
MAX_BATCH = 250
PCAP_FILE = '201601011400.pcap'

"""

Flow assignment rules:

- A "flow" I assume is talking about a traffic flow, which is a sequence of packets sent from the 
same src to the same destination
- A flow can only be monitored by ONE monitor
- Want equal distribution between the monitors

Essential algorithm is to assign to the least loaded monitor

"""

class Monitor(Thread):
    def __init__(self, id, batch_size):
        Thread.__init__(self)

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

        # Determines when this thread should stop execution
        self.shouldStop = False
    
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
                summary = summarize_packet_data(self.batch[:MAX_BATCH])
                inference_mod(summary)
                self.batch.drop(self.batch.index[:MAX_BATCH], inplace=True)

def get_least_loaded_monitor(monitors):
    min_flows = monitors[0].num_flows
    min_flow_idx = 0

    for idx in range(len(monitors)):
        if monitors[idx].num_flows < min_flows or (monitors[idx].num_flows == min_flows and monitors[idx].num_packets < monitors[min_flow_idx].num_packets):
            min_flows = monitors[idx].num_flows
            min_flow_idx = idx
    
    return min_flow_idx

def start_jaal(test_file):
    flow_map = {}
    monitors = []

    for id in range(0, MAX_MONITORS):
        monitor_thread = Monitor(id, MAX_BATCH)
        monitor_thread.start()

        monitors.append(monitor_thread)

    # Main method of execution, will just keep reading in packets
    # until we want it to stop
    try:
        for pkt in PcapReader(test_file):

            #TODO: Randomly inject traffic, or create a transformed dataset that does that

            src, dst = pkt[Ether].src, pkt[Ether].dst
            if src not in flow_map or dst not in flow_map[src]:

                print("src={}, dst={} not in flow map, finding new assignment...".format(src, dst))
                print("Current flow state: ")
                for monitor in monitors:
                    print("Monitor {}: {} flows, {} packets.".format(monitor.id, monitor.num_flows, monitor.num_packets))
                print("\n\n")

                flow_assignment = get_least_loaded_monitor(monitors)

                print("Flow assignment: Monitor {}".format(flow_assignment))

                flow_map[src] = { dst : flow_assignment}
                monitors[flow_assignment].add_to_batch(pkt)
            else:
                flow_assignment = flow_map[src][dst]
                monitors[flow_assignment].add_to_batch(pkt)

    except KeyboardInterrupt:
        for monitor_thread in monitors:
            monitor_thread.kill() 

    for monitor_thread in monitors:
        monitor_thread.join()
    
if __name__ == '__main__':
    start_jaal(PCAP_FILE)