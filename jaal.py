import numpy as np
import pandas as pd
from sklearn.cluster import k_means
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP, UDP

# PCAP file can be downloaded from this URL:
# http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html
PCAP_FILE = '201601011400.pcap'

ETHERNET_COLS = ['ETH_DST', 'ETH_SRC', 'ETH_TYPE']
IP_COLS = ['IP_VERSION', 'IHL', 'TOS', 'IP_LEN', 'IP_ID', 'IP_FLAGS',
           'IP_FRAG', 'IP_TTL', 'IP_PROTO', 'IP_CHKSUM', 'IP_SRC', 'IP_DST']
TCP_COLS = ['SPORT', 'DPORT', 'SEQ', 'ACK', 'DATAOFS', 'RESERVED', 'FLAGS', 'WINDOW', 'PROTOCOL_CHKSUM', 'URGPTR',
            'PAYLOAD']
UDP_COLS = ['SPORT', 'DPORT', 'UDP_LEN', 'PROTOCOL_CHKSUM', 'PAYLOAD']
ICMP_COLS = ['ICMP_TYPE', 'CODE', 'PROTOCOL_CHKSUM', 'ICMP_ID', 'SEQ', 'PAYLOAD']

COLUMNS_TCP = [*ETHERNET_COLS, *IP_COLS, *TCP_COLS]
COLUMNS_UDP = [*ETHERNET_COLS, *IP_COLS, *UDP_COLS]
COLUMNS_ICMP = [*ETHERNET_COLS, *IP_COLS, *ICMP_COLS]

NON_NUMERIC_COLS = set(['ETH_DST','ETH_SRC', 'SPORT', 'DPORT', 'PROTO', 'ETH_TYPE', 'IP_SRC', 'IP_DST', 'IP_ID',
                        'ICMP_ID', 'IP_VERSION', 'FLAGS', 'IP_FLAGS', 'PAYLOAD']) # remove payload after conversion
NUM_CLUSTERS = 10


def summarize_packet_data(df):
    # normalize
    normalized_df = df.copy()
    print(normalized_df.head())
    for c in NON_NUMERIC_COLS:
        if c in set(normalized_df.columns):
            normalized_df.drop(c, axis=1, inplace=True)
    for c in normalized_df.columns:
        print(c)
        normalized_df[c].apply(lambda x: x/normalized_df[c].max() if normalized_df[c].max() != 0 else 0)
    # apply reduction
    reduced_df = np.linalg.svd(normalized_df.values)
    # kmeans
    clusters = k_means(reduced_df, NUM_CLUSTERS)
    return clusters


def open_packet_file(file):
    i = 0
    udp_df = pd.DataFrame([], columns=COLUMNS_UDP)
    tcp_df = pd.DataFrame([], columns=COLUMNS_TCP)
    icmp_df = pd.DataFrame([], columns=COLUMNS_ICMP)
    for pkt in PcapReader(file):
        print(pkt.show())
        if i == 100: # only first hundred for now, doing whole file takes forever
            break
        try:
            df = pd.DataFrame({
                COLUMNS_UDP[0]: pkt[Ether].dst,
                COLUMNS_UDP[1]: [pkt[Ether].src],
                COLUMNS_UDP[2]: [pkt[Ether].type],
                COLUMNS_UDP[3]: [pkt[IP].version],
                COLUMNS_UDP[4]: [pkt[IP].ihl],
                COLUMNS_UDP[5]: [pkt[IP].tos],
                COLUMNS_UDP[6]: [pkt[IP].len],
                COLUMNS_UDP[7]: [pkt[IP].id],
                COLUMNS_UDP[8]: [pkt[IP].flags],
                COLUMNS_UDP[9]: [pkt[IP].frag],
                COLUMNS_UDP[10]: [pkt[IP].ttl],
                COLUMNS_UDP[11]: [pkt[IP].proto],
                COLUMNS_UDP[12]: [pkt[IP].chksum],
                COLUMNS_UDP[13]: [pkt[IP].src],
                COLUMNS_UDP[14]: [pkt[IP].dst],
                COLUMNS_UDP[15]: [pkt[UDP].sport],
                COLUMNS_UDP[16]: [pkt[UDP].dport],
                COLUMNS_UDP[17]: [pkt[UDP].len],
                COLUMNS_UDP[18]: [pkt[UDP].chksum],
                COLUMNS_UDP[19]: [pkt.payload],
            })
            udp_df = udp_df.append(df, ignore_index=True)
        except IndexError as e:
            pass
        try:
            df = pd.DataFrame({
                COLUMNS_TCP[0]: pkt[Ether].dst,
                COLUMNS_TCP[1]: [pkt[Ether].src],
                COLUMNS_TCP[2]: [pkt[Ether].type],
                COLUMNS_TCP[3]: [pkt[IP].version],
                COLUMNS_TCP[4]: [pkt[IP].ihl],
                COLUMNS_TCP[5]: [pkt[IP].tos],
                COLUMNS_TCP[6]: [pkt[IP].len],
                COLUMNS_TCP[7]: [pkt[IP].id],
                COLUMNS_TCP[8]: [pkt[IP].flags],
                COLUMNS_TCP[9]: [pkt[IP].frag],
                COLUMNS_TCP[10]: [pkt[IP].ttl],
                COLUMNS_TCP[11]: [pkt[IP].proto],
                COLUMNS_TCP[12]: [pkt[IP].chksum],
                COLUMNS_TCP[13]: [pkt[IP].src],
                COLUMNS_TCP[14]: [pkt[IP].dst],
                COLUMNS_TCP[15]: [pkt[TCP].sport],
                COLUMNS_TCP[16]: [pkt[TCP].dport],
                COLUMNS_TCP[17]: [pkt[TCP].seq],
                COLUMNS_TCP[18]: [pkt[TCP].ack],
                COLUMNS_TCP[19]: [pkt[TCP].dataofs],
                COLUMNS_TCP[20]: [pkt[TCP].reserved],
                COLUMNS_TCP[21]: [pkt[TCP].flags],
                COLUMNS_TCP[22]: [pkt[TCP].window],
                COLUMNS_TCP[23]: [pkt[TCP].chksum],
                COLUMNS_TCP[24]: [pkt[TCP].urgptr],
                COLUMNS_TCP[25]: [bytes(pkt.payload)]
            })
            tcp_df = tcp_df.append(df, ignore_index=True) # append is NOT  an inplace operation!
        except IndexError as e:
            pass
        try:
            df = pd.DataFrame({
                COLUMNS_UDP[0]: pkt[Ether].dst,
                COLUMNS_UDP[1]: [pkt[Ether].src],
                COLUMNS_UDP[2]: [pkt[Ether].type],
                COLUMNS_UDP[3]: [pkt[IP].version],
                COLUMNS_UDP[4]: [pkt[IP].ihl],
                COLUMNS_UDP[5]: [pkt[IP].tos],
                COLUMNS_UDP[6]: [pkt[IP].len],
                COLUMNS_UDP[7]: [pkt[IP].id],
                COLUMNS_UDP[8]: [pkt[IP].flags],
                COLUMNS_UDP[9]: [pkt[IP].frag],
                COLUMNS_UDP[10]: [pkt[IP].ttl],
                COLUMNS_UDP[11]: [pkt[IP].proto],
                COLUMNS_UDP[12]: [pkt[IP].chksum],
                COLUMNS_UDP[13]: [pkt[IP].src],
                COLUMNS_UDP[14]: [pkt[IP].dst],
                COLUMNS_UDP[15]: [pkt[ICMP].type],
                COLUMNS_UDP[16]: [pkt[ICMP].code],
                COLUMNS_UDP[17]: [pkt[ICMP].chksum],
                COLUMNS_UDP[18]: [pkt[ICMP].id],
                COLUMNS_UDP[19]: [pkt[ICMP].seq],
                COLUMNS_UDP[20]: [pkt.payload],
            })
            icmp_df = icmp_df.append(df, ignore_index=True)
        except IndexError as e:
            pass
        i += 1
    print(summarize_packet_data(tcp_df))


if __name__ == '__main__':
    open_packet_file(PCAP_FILE)
