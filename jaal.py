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

# PCAP file can be downloaded from this URL:
# http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html
PCAP_FILE = '201601011400.pcap'

if __name__ == '__main__':
    print("Starting Jaal, parsing first 500 TCP/IP packets...")
    tcp_df = parse_pcap_packets(PCAP_FILE)

    print("Packets retrieved, creating summary...")
    results = summarize_packet_data(tcp_df)

    print("Final Summary Representation: ")
    print(results)
