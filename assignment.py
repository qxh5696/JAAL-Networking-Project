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
from scapy.layers.l2 import Ether

MAX_MONITORS = 10
PCAP_FILE = '201601011400.pcap'

"""

Flow assignment rules:

- A "flow" I assume is talking about a traffic flow, which is a sequence of packets sent from the 
same src to the same destination
- A flow can only be monitored by ONE monitor
- Want equal distribution between the monitors

Essential algorithm is to assign to the least loaded monitor

"""
def get_least_loaded_monitor(monitors):
    min_flows = monitors[0].num_flows
    min_flow_idx = 0

    for idx in range(len(monitors)):
        if monitors[idx].num_flows < min_flows \
                or (monitors[idx].num_flows == min_flows
                    and monitors[idx].num_packets < monitors[min_flow_idx].num_packets):
            min_flows = monitors[idx].num_flows
            min_flow_idx = idx
    
    return min_flow_idx

def assign_flow_to_monitor(pkt, monitors, flow_map):
    src, dst = pkt[Ether].src, pkt[Ether].dst
    flow_assignment = 0
    if src not in flow_map or dst not in flow_map[src]:
        flow_assignment = get_least_loaded_monitor(monitors)
        flow_map[src] = {dst: flow_assignment}
    else:
        flow_assignment = flow_map[src][dst]
    return flow_assignment