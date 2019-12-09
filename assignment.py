"""
File: inference.py

Description: Due to time constraints, we are implementing the "flow assignment" 
module with a monitor object. There is a single stream that reads in incoming TCP packets, 
and the flow assignment module will handle thread pool assignment according to the following
rules set in the paper:

(1) A flow can only be monitored by a single monitor. A flow is defined as a sequence of packets
that are sent from the same source to the same destination
(2) There is an equal distribution of flows to monitors.

Language: python3

Authors: Theodora Bendlin
"""
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from constants import *


def get_least_loaded_monitor(monitors):
    """
        Simple greedy function that will assign a flow to the least loaded monitor.
        Iterates through a list of monitors and finds the one with the fewest flows,
        or fewest number of packets, if a tie occurs.

        :param: monitors (list) List of monitor objects used in Jaal
        
        :return: min_flow_idx (int) the index of the monitor that should be used for
        assignment
    """
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
    """
        Main function that will perform flow assignment using the get_least_loaded_monitor
        function. Uses a map depicting src --> dst --> monitor, the source to a series of common
        destinations, each with their monitor assignment.

        :param: pkt (spacy Packet) Packet that is to be assigned
        :param: monitors (list) List of monitor objects used in Jaal
        :param: flow_map (dict) Map specifying src, dst pairs to monitor assignments

        :return: flow_assignment (int) the monitor that the flow was assigned to
    """
    src, dst = pkt[IP].src, pkt[IP].dst
    flow_assignment = 0
    if src not in flow_map or dst not in flow_map[src]:
        flow_assignment = get_least_loaded_monitor(monitors)
        flow_map[src] = {dst: flow_assignment}
    else:
        flow_assignment = flow_map[src][dst]
    return flow_assignment
