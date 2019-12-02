"""
File: inference.py
Description: Inference module, functionality to be implemented in future work.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""

import pandas as pd
import numpy as np

from util import parse_pcap_packets
from summarize import summarize_packet_data

def create_aggregate_summary(summaries):
    agg_summaries = []
    for summary_pair in summaries:
        if summary_pair[0] == 1:
            agg_summaries.append(summary_pair[1])
        else:
            clusters, SigrVr = summary_pair[1]['clusters'], summary_pair[1]['e']
            prod = np.dot(clusters, SigrVr)
            agg_summaries.append(np.hstack((prod, summary_pair[1]['c'])))
    
    return np.concatenate(agg_summaries, axis=0)

if __name__ == '__main__':
    tcp_df = parse_pcap_packets('201601011400.pcap', 750)

    resulta = summarize_packet_data(tcp_df[:250])
    resultb = summarize_packet_data(tcp_df[250:500])
    resultc = summarize_packet_data(tcp_df[500:])

    create_aggregate_summary([resulta, resultb, resultc])

# Example SNORT Rule:
# alert[0] tcp[1] $EXTERNAL_NET[2] any[3] -> $HOME_NET[4] 22[5] (msg: "INDICATORSCAN
# SSH brute force login attempt"[6]; flow: to_server[7], established[8]; content:
# "SSH-"[9]; depth: 4[10]; detection_filter: track by_src[11], count 5[12], seconds 60[13];
# metadata: service ssh[14]; classtype: misc-activity[15]; sid: 19559[16]; rev:5 [17];).
#
# The rule postulates that an alert must be generated if 5 packets
# destined for the home network were received within the last 60s,
# with port number 22.
#
# To translate this rule into a question vector, Jaal initializes a vector of size 18 with −1 set for every position
#
# Then, the position corresponding to the IP address is set to the normalized home network IP address and the position
# corresponding to port number is set to 22 (normalized version).
def translate(snort_rule):
    vector = [-1] * 18 # initialization vector
    

