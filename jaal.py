"""

    Main driver file for our Jaal system that will invoke funtionality from
    all three modules. At the moment, funcitonality simply reads test data from
    MAWI group and performs packet summarization.

"""

import numpy as np
import pandas as pd
from sklearn.cluster import k_means
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP, UDP

from util import parse_pcap_packets
from summarize import summarize_packet_data

# PCAP file can be downloaded from this URL:
# http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html
PCAP_FILE = '201601011400.pcap'

if __name__ == '__main__':
    tcp_df = parse_pcap_packets(PCAP_FILE)
    results = summarize_packet_data(tcp_df)
    
    print(results)