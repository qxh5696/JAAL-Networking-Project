"""
File: inference.py
Description: Inference module, functionality to be implemented in future work.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran

Example SNORT Rule:
alert[0] tcp[1] $EXTERNAL_NET[2] any[3] -> $HOME_NET[4] 22[5] (msg: "INDICATORSCAN
SSH brute force login attempt"[6]; flow: to_server[7], established[8]; content:
"SSH-"[9]; depth: 4[10]; detection_filter: track by_src[11], count 5[12], seconds 60[13];
metadata: service ssh[14]; classtype: misc-activity[15]; sid: 19559[16]; rev:5 [17];).

The rule postulates that an alert must be generated if 5 packets
destined for the home network were received within the last 60s,
with port number 22.

To translate this rule into a question vector, Jaal initializes a vector of size 18 with −1 set for every position

Then, the position corresponding to the IP address is set to the normalized home network IP address and the position
corresponding to port number is set to 22 (normalized version).

Question Vectors:
(i) SYN floods to represent DoS attacks,
(ii) distributed SYN floods to represent DDoS,
(iii) distributed port scans
"""

import numpy as np
import math
import util
from constants import *

# Remember to switch IP addresses out with the corresponding attack IP address and attack ports
# https://www.hackingarticles.in/detect-nmap-scan-using-snort/
PORT_SCAN_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# Identify NMAP TCP Scan (same link as above)
NMAP_TCP_SCAN_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 22, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# https://serverfault.com/questions/178437/snort-rules-for-syn-flood-ddos
SYM_FLOOD_DDOS_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 80, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# https://github.com/eldondev/Snort/blob/master/rules/ddos.rules
DDOS_RULE_1 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 27665, -1, -1, -1, -1, -1, -1, -1, -1]

DDOS_RULE_2 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 15104, -1, -1, -1, -1, -1, -1, -1, -1]

DDOS_RULE_3 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, -1, 12754, -1, -1, -1, -1, -1, -1, -1, -1]

QUESTION_VECTORS = [PORT_SCAN_RULE, NMAP_TCP_SCAN_RULE, SYM_FLOOD_DDOS_RULE, DDOS_RULE_1, DDOS_RULE_2, DDOS_RULE_3]

def create_aggregate_summary(summaries):
    if len(summaries) <= 0:
        return None

    agg_summaries = []
    for summary_pair in summaries:
        if summary_pair[0] == 1:
            agg_summaries.append(summary_pair[1])
        else:
            clusters, SigrVr = summary_pair[1]['clusters'], summary_pair[1]['e']
            prod = np.dot(clusters, SigrVr)
            agg_summaries.append(np.hstack((prod, summary_pair[1]['c'])))

    return np.concatenate(agg_summaries, axis=0)

def distance_measure(q, x):
    q_x_sum = 0.0
    q_sum = 0.0
    for j in range(len(q)):
        if q[j] != -1:
            q_sum += 1
            q_x_sum += math.fabs(q[j] - x[j])

    if q_sum == 0:
        return 1

    return q_x_sum / q_sum

def similarity_estimate(agg_sum, q, t_d, t_c):
    c_sum = 0
    Q = []

    for row in range(len(agg_sum)):
        xi = agg_sum[row][:-1]
        ci = agg_sum[row][-1]

        dist = distance_measure(q, xi)
        if dist <= t_d:
            c_sum += ci
            Q.append(xi)

    if c_sum >= t_c:
        print("Sum is greater than threshold: {}".format(c_sum))
        return True, Q
    else:
        print("Sum is NOT greater than threshold: {}".format(c_sum))
        return False, Q

def postprocess_header_index(Q, h_idx, t_v):
    z = []

    for row in range(len(Q)):
        xi = Q[row][:-1]
        ci = Q[row][-1]

        for _ in range(int(ci)):
            z.append(xi[h_idx])
    
        if z is None or len(z) <= 0:
            continue

        variance = np.var(np.concatenate(z, axis=0))
        if variance >= t_v:
            return True
    
    return False

def set_normalized_rule(agg_sum, val_pairs, q):
    maxes = agg_sum.max(1)
    mins = agg_sum.min(1)

    for pair in val_pairs:
        value = pair[0]
        idx = pair[1]
        val_min = pair[2]
        val_max = pair[3]
        should_scale_and_normalize = pair[4]

        if should_scale_and_normalize:
            value = (1 - 0)/(val_max - val_min)*(value - val_max) + 1

            min_v = mins[idx]
            max_v = maxes[idx]

            q[idx] = (value - min_v) / (max_v - min_v)
        else:
            q[idx] = value

    #print("Question vector: ", q)
    return q


def inference_module(batch_summaries, expected_errors):
    agg_summaries = create_aggregate_summary(batch_summaries)
    if agg_summaries is None:
        print("No summaries to perform inference on!")
        return

    column_means = agg_summaries.mean(axis=1)
    port_scan_rule = set_normalized_rule(agg_summaries, [(util.ipstring_to_int(ATTACK_HOME_IP), 13, 1, 255255255254, True)], PORT_SCAN_RULE)
    nmap_scan_rule = set_normalized_rule(agg_summaries, [(util.ipstring_to_int(ATTACK_HOME_IP), 13, 1, 255255255254, True), (22, 16, 1, 65535, True)], NMAP_TCP_SCAN_RULE)
    syn_floods_rule = set_normalized_rule(agg_summaries, [(column_means[13], 13, 0, 0, False), (80, 16, 1, 65535, True)], SYM_FLOOD_DDOS_RULE)
    ddos_rule_1 = set_normalized_rule(agg_summaries, [(column_means[13], 13, 0, 0, False), (27665, 16, 1, 65535, True)], DDOS_RULE_1)
    ddos_rule_2 = set_normalized_rule(agg_summaries, [(column_means[13], 13, 0, 0, False), (15104, 16, 1, 65535, True)], DDOS_RULE_2)
    ddos_rule_3 = set_normalized_rule(agg_summaries, [(column_means[13], 13, 0, 0, False), (12754, 16, 1, 65535, True)], DDOS_RULE_3)

    attacks = [False, False, False, False, False, False]

    did_find_error, Q = similarity_estimate(agg_summaries, port_scan_rule, 0.1, 10)
    attacks[0] = did_find_error or postprocess_header_index(Q, 16, 0.1)

    attacks[1] = similarity_estimate(agg_summaries, nmap_scan_rule, 0.1, 10)[0]
    
    did_find_error, Q = similarity_estimate(agg_summaries, syn_floods_rule, 0.1, 10)
    attacks[2] = did_find_error or postprocess_header_index(Q, 13, 0.1)

    did_find_error, Q = similarity_estimate(agg_summaries, ddos_rule_1, 0.1, 10)
    attacks[3] = did_find_error or postprocess_header_index(Q, 13, 0.1)
    
    did_find_error, Q = similarity_estimate(agg_summaries, ddos_rule_2, 0.1, 10)
    attacks[4] = did_find_error or postprocess_header_index(Q, 13, 0.1)
    
    did_find_error, Q = similarity_estimate(agg_summaries, ddos_rule_3, 0.1, 10)
    attacks[5] = did_find_error or postprocess_header_index(Q, 13, 0.1)

    false_positives = 0
    false_negatives = 0
    correct = 0

    for a_idx in range(len(attacks)):
        if (attacks[a_idx] and expected_errors[a_idx] >= 10) or (not attacks[a_idx] and expected_errors[a_idx] < 10):
            correct += 1
        elif not attacks[a_idx] and expected_errors[a_idx] >= 10:
            false_negatives += 1
        elif attacks[a_idx] and expected_errors[a_idx] < 10:
            false_positives += 1
    
    return correct, false_positives, false_negatives