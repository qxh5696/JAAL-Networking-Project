"""
File: util.py
Description: File containing utility functions used in other modules.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin
"""


import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from constants import *

def add_pcap_packet_to_df(packet, packet_df):
    """
    Creates a TCP dataframe to add to the given input dataframe.

    If the operation could not be done (i.e. the packet is not a TCP/IP
    packet), then the packet is not added.

    :param file: (string) the filename of the PCAP dump file
    :return: (boolean) if the operation was successful, 
        (Dataframe) Pandas dataframe of TCP packet data
    """

    if not is_tcp_ip_packet(packet):
        return False, packet_df

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
    return True, packet_df

def hexstring_to_int(hex_s):
    """
    Helper funtion that converts HW addresses into decimal form

    :param hex_s: (str) HW address string
    :return: (int) integer representation of the HW address
    """

    hex_s = hex_s.replace(':', '')
    return int(hex_s, 16)


def ipstring_to_int(ip_s):
    """
    Helper funtion that converts string IP address into decimal form

    :param ip_s: (str) IP address string
    :return: (int) integer representation of the IP address
    """
    ip_s = ip_s.replace('.', '')
    return int(ip_s)

def is_tcp_ip_packet(pkt):
    """
        Helper function that will try to parse TCP/IP columns specifically
        to determine if the packet is a TCP/IP packet

        :return: (boolean) if the packet is a TCP/IP packet
    """
    try:
        pkt[TCP].sport
        pkt[IP].id
    except IndexError as e:
        return False

    return True