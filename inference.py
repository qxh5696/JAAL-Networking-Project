"""
File: inference.py
Description: Inference module, functionality to be implemented in future work.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""

import pandas as pd
import numpy as np

import random

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