"""
File: constants.py

Description: File containing the constants used throughout the Jaal project for easy access.

Language: python3

Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""
MAX_BATCH = 1000

# PCAP file can be downloaded from this URL:
# http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html
PCAP_FILE = '201601011400.pcap'

MAX_MONITORS = 10

ETHERNET_COLS = ['ETH_DST', 'ETH_SRC', 'ETH_TYPE']
IP_COLS = ['IP_VERSION', 'IHL', 'TOS', 'IP_LEN', 'IP_ID', 'IP_FLAGS',
           'IP_FRAG', 'IP_TTL', 'IP_PROTO', 'IP_CHKSUM', 'IP_SRC', 'IP_DST']
TCP_COLS = ['SPORT', 'DPORT', 'SEQ', 'ACK', 'DATAOFS', 'RESERVED', 'FLAGS', 'WINDOW', 'PROTOCOL_CHKSUM', 'URGPTR']

COLUMNS_TCP = [*ETHERNET_COLS, *IP_COLS, *TCP_COLS]

NUM_CLUSTERS = 10

ATTACK_HOME_IP = '127.0.0.1'
ATTACK_IPS = ['10.1.1.1', '11.2.2.2', '12.3.3.3']
