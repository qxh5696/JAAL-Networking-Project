"""
File: util.py
Description: File containing utility functions used in other modules.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""


import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

ETHERNET_COLS = ['ETH_DST', 'ETH_SRC', 'ETH_TYPE']
IP_COLS = ['IP_VERSION', 'IHL', 'TOS', 'IP_LEN', 'IP_ID', 'IP_FLAGS',
           'IP_FRAG', 'IP_TTL', 'IP_PROTO', 'IP_CHKSUM', 'IP_SRC', 'IP_DST']
TCP_COLS = ['SPORT', 'DPORT', 'SEQ', 'ACK', 'DATAOFS', 'RESERVED', 'FLAGS', 'WINDOW', 'PROTOCOL_CHKSUM', 'URGPTR']

COLUMNS_TCP = [*ETHERNET_COLS, *IP_COLS, *TCP_COLS]

NUM_CLUSTERS = 10


def parse_pcap_packets(file, limit=500):
    """
    Opens a PCAP file containing packet dump and creates a pandas dataframe
    of TCP packet data, where each row is a separate packet.

    This function will be replaced in the final implementation with flow assignment
    and processing packets in a stream.

    @parameter file (string) the filename of the PCAP dump file
    @returns tcp_df (Dataframe) Pandas dataframe of (100) TCP packet data
    :param file:
    :return:
    """

    tcp_df = pd.DataFrame([], columns=COLUMNS_TCP)

    for pkt in PcapReader(file):

        if len(tcp_df.index) >= limit:
            break

        try:
            df = pd.DataFrame({
                COLUMNS_TCP[0]: [hexstring_to_int(pkt[Ether].dst)],
                COLUMNS_TCP[1]: [hexstring_to_int(pkt[Ether].src)],
                COLUMNS_TCP[2]: [pkt[Ether].type],
                COLUMNS_TCP[3]: [pkt[IP].version],
                COLUMNS_TCP[4]: [pkt[IP].ihl],
                COLUMNS_TCP[5]: [pkt[IP].tos],
                COLUMNS_TCP[6]: [pkt[IP].len],
                COLUMNS_TCP[7]: [pkt[IP].id],
                COLUMNS_TCP[8]: [pkt[IP].flags.value],
                COLUMNS_TCP[9]: [pkt[IP].frag],
                COLUMNS_TCP[10]: [pkt[IP].ttl],
                COLUMNS_TCP[11]: [pkt[IP].proto],
                COLUMNS_TCP[12]: [pkt[IP].chksum],
                COLUMNS_TCP[13]: [ipstring_to_int(pkt[IP].src)],
                COLUMNS_TCP[14]: [ipstring_to_int(pkt[IP].dst)],
                COLUMNS_TCP[15]: [pkt[TCP].sport],
                COLUMNS_TCP[16]: [pkt[TCP].dport],
                COLUMNS_TCP[17]: [pkt[TCP].seq],
                COLUMNS_TCP[18]: [pkt[TCP].ack],
                COLUMNS_TCP[19]: [pkt[TCP].dataofs],
                COLUMNS_TCP[20]: [pkt[TCP].reserved],
                COLUMNS_TCP[21]: [pkt[TCP].flags.value],
                COLUMNS_TCP[22]: [pkt[TCP].window],
                COLUMNS_TCP[23]: [pkt[TCP].chksum],
                COLUMNS_TCP[24]: [pkt[TCP].urgptr],
            })

            # append is NOT  an inplace operation!
            tcp_df = tcp_df.append(df, ignore_index=True)
        except IndexError as e:
            pass

    tcp_df.drop_duplicates()
    return tcp_df

def add_pcap_packet_to_df(packet, packet_df):
    try:
        df = pd.DataFrame({
                COLUMNS_TCP[0]: [hexstring_to_int(packet[Ether].dst)],
                COLUMNS_TCP[1]: [hexstring_to_int(packet[Ether].src)],
                COLUMNS_TCP[2]: [packet[Ether].type],
                COLUMNS_TCP[3]: [packet[IP].version],
                COLUMNS_TCP[4]: [packet[IP].ihl],
                COLUMNS_TCP[5]: [packet[IP].tos],
                COLUMNS_TCP[6]: [packet[IP].len],
                COLUMNS_TCP[7]: [packet[IP].id],
                COLUMNS_TCP[8]: [packet[IP].flags.value],
                COLUMNS_TCP[9]: [packet[IP].frag],
                COLUMNS_TCP[10]: [packet[IP].ttl],
                COLUMNS_TCP[11]: [packet[IP].proto],
                COLUMNS_TCP[12]: [packet[IP].chksum],
                COLUMNS_TCP[13]: [ipstring_to_int(packet[IP].src)],
                COLUMNS_TCP[14]: [ipstring_to_int(packet[IP].dst)],
                COLUMNS_TCP[15]: [packet[TCP].sport],
                COLUMNS_TCP[16]: [packet[TCP].dport],
                COLUMNS_TCP[17]: [packet[TCP].seq],
                COLUMNS_TCP[18]: [packet[TCP].ack],
                COLUMNS_TCP[19]: [packet[TCP].dataofs],
                COLUMNS_TCP[20]: [packet[TCP].reserved],
                COLUMNS_TCP[21]: [packet[TCP].flags.value],
                COLUMNS_TCP[22]: [packet[TCP].window],
                COLUMNS_TCP[23]: [packet[TCP].chksum],
                COLUMNS_TCP[24]: [packet[TCP].urgptr],
            })

        # append is NOT  an inplace operation!
        packet_df = packet_df.append(df, ignore_index=True, sort=False)

    except IndexError as e:
        return False, packet_df
    
    return (True, packet_df)

def hexstring_to_int(hex_s):
    """
    Helper funtion that converts HW addresses into decimal form

    @param hex_s (str) HW address string
    @returns (int) integer representation of the HW address
    :param hex_s:
    :return:
    """

    hex_s = hex_s.replace(':', '')
    return int(hex_s, 16)


def ipstring_to_int(ip_s):
    """
    Helper funtion that converts string IP address into decimal form

    @param ip_s (str) IP address string
    @returns (int) integer representation of the IP address
    :param ip_s:
    :return:
    """
    ip_s = ip_s.replace('.', '')
    return int(ip_s)
