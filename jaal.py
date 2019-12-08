"""
File: jaal.py

Description: Main driver file for our Jaal system that will invoke funtionality from
all three modules while reading in the MAWI trace.

Language: python3

Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""
import random

from util import is_tcp_ip_packet, IP, TCP
from summarize import summarize_packet_data
from assignment import assign_flow_to_monitor
from monitor import Monitor
from inference import inference_module
from constants import *

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether

from threading import Thread

def spinup_jaal(exp_sums, test_file=PCAP_FILE):
    """
        Main method of execution, will read in packets until 
        CTRL + C is pressed. Runs a basic experiement of accuracy
        where attack packets are randomly injected, and the expected
        and actual counts are counted.

        :param exp_sums: (dict) keeps track of the experimental results to be
            printed after execution stops
        :param test_tile: (string) file name of PCAP TCP dump
    """

    monitors = []
    flow_map = {}

    # Creating the list of monitors
    for id in range(0, MAX_MONITORS):
        monitors.append(Monitor(id))

    # Keep track of types of packets to ensure 10% of attack traffic isn't exceeded
    num_pkts = 0
    atk_pkts = 0

    atk_pkts_map = {
        0: 0,
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 0,
        6: 0
    }

    for pkt in PcapReader(test_file):

        # The paper only considers TCP/IP packets
        if not is_tcp_ip_packet(pkt):
            continue

        pkts_to_add = [pkt]

        # Randomly injecting traffic, probability = 0.03
        # As per the paper, we must ensure the attack traffic
        # is not larger than 10% of the total traffic
        should_attack = random.randint(1, 100)
        if num_pkts > 1000 and should_attack < 3 and (atk_pkts / (num_pkts + atk_pkts)) < 0.10:

            attack_type = random.randint(0, 6)

            for loop in range(5, random.randint(10, 20)):
                if (atk_pkts / (num_pkts + atk_pkts)) >= 0.10:
                    break

                # PORT_SCAN_RULE  -- same IP dest, different port numbers
                if attack_type == 0:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_HOME_IP
                    atk_pkt[TCP].dport += loop
                
                # NMAP TCP Scan -- same IP dest with port = 22
                elif attack_type == 1:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_HOME_IP
                    atk_pkt[TCP].dport = 22

                # SYM_FLOOD_DDOS_RULE
                elif attack_type == 2:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_IPS[random.randint(0, len(ATTACK_IPS) - 1)]
                    atk_pkt[TCP].dport = 80

                # DDOS RULES -  SRC is changed (13), sport (15)
                elif attack_type == 3:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_IPS[random.randint(0, len(ATTACK_IPS) - 1)]
                    atk_pkt[IP].dst = ATTACK_HOME_IP
                    atk_pkt[TCP].dport = 27665

                elif attack_type == 4:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_IPS[random.randint(0, len(ATTACK_IPS) - 1)]
                    atk_pkt[IP].dst = ATTACK_HOME_IP
                    atk_pkt[TCP].dport = 15104

                else:
                    atk_pkt = pkt
                    atk_pkt[IP].src = ATTACK_IPS[random.randint(0, len(ATTACK_IPS) - 1)]
                    atk_pkt[IP].dst = ATTACK_HOME_IP
                    atk_pkt[TCP].dport = 12754

                pkts_to_add.append(atk_pkt)
                atk_pkts += 1
                atk_pkts_map[attack_type] += 1

        num_pkts += 1
        for new_pkt in pkts_to_add:
            flow_assignment = assign_flow_to_monitor(pkt, monitors, flow_map)
            should_check = monitors[flow_assignment].add_to_batch(pkt)

            if should_check:
                print("Packet Attack Types:")
                for key in range(0, 6):
                    print("Type {}: {} packets".format(key, atk_pkts_map[key]))

                perform_error_detection(monitors, atk_pkts_map, exp_sums)

                atk_pkts_map = {
                    0: 0,
                    1: 0,
                    2: 0,
                    3: 0,
                    4: 0,
                    5: 0,
                    6: 0
                }

def perform_error_detection(monitors, expected_errors, exp_sums):
    """
    
        Helper function that will update the experiment results with the
        counts from the inference module.

        :param monitors: (list) List of all monitors used in Jaal
        :param expected_errors: (dict) dictionary of error type --> number of packets
        :param exp_sums: (dict) dictionary of experiment result summations
    
    """
    summaries = []
    for monitor in monitors:
        summary = monitor.get_batch_summary()
        if summary is not None:
            summaries.append(summary)

    correct, false_positives, false_negatives = inference_module(summaries, expected_errors)

    exp_sums["total"] += 6
    exp_sums["correct"] += correct
    exp_sums["false_positives"] += false_positives
    exp_sums["false_negatives"] += false_negatives

if __name__ == "__main__":
    exp_sums = {
        "total": 0,
        "correct": 0,
        "false_positives": 0,
        "false_negatives": 0
    }

    try:
        spinup_jaal(exp_sums)
    except KeyboardInterrupt as e:
        for key in exp_sums:
            print("{}: {}".format(key, exp_sums[key]))