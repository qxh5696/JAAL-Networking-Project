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

# Remember to switch IP addresses out with the corresponding attack IP address and attack ports
# https://www.hackingarticles.in/detect-nmap-scan-using-snort/
PORT_SCAN_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# Identify NMAP TCP Scan (same link as above)
NMAP_TCP_SCAN_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, 22, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# https://serverfault.com/questions/178437/snort-rules-for-syn-flood-ddos
SYM_FLOOD_DDOS_RULE = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, 80, -1, -1, -1, -1, -1, -1, -1, -1, -1]

# https://github.com/eldondev/Snort/blob/master/rules/ddos.rules
DDOS_RULE_1 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, 27665, -1, -1, -1, -1, -1, -1, -1, -1, -1]

DDOS_RULE_2 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, 15104, -1, -1, -1, -1, -1, -1, -1, -1, -1]

DDOS_RULE_3 = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                  util.ipstring_to_int(util.get_ip_address()), -1, 12754, -1, -1, -1, -1, -1, -1, -1, -1, -1]

QUESTION_VECTORS = [PORT_SCAN_RULE, NMAP_TCP_SCAN_RULE, SYM_FLOOD_DDOS_RULE, DDOS_RULE_1, DDOS_RULE_2, DDOS_RULE_3]

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

def _distance_measure(q, x):
    q_x_sum = 0.0
    q_sum = 0.0
    for j in range(len(q)):
        if q[j] != -1:
            q_sum += 1
            q_x_sum = math.fabs(q[j] - x[j])

    if q_sum == 0:
        return 0

    return q_x_sum / q_sum

def similarity_estimate(agg_sum, q, t_d, t_c):
    sum = 0
    Q_set = set()

    for row in range(len(agg_sum)):
        xi = agg_sum[row][:-1]
        ci = agg_sum[-1]

        if _distance_measure(q, xi) <= t_d:
            sum += ci
            Q_set.add(xi)
    
    if sum >= t_c:
        return True
    
    return False

def postprocess_header_index(agg_sum, h_idx, t_v):
    z = []

    for row in range(len(agg_sum)):
        xi = agg_sum[row][:-1]
        ci = agg_sum[-1]

        for _ in range(ci):
            z.append(xi[h_idx])
    
        variance = np.var(np.concatenate(z, axis=0))
        if variance >= t_v:
            return True
    
    return False

def inference_module(summary):
    agg_sum = create_aggregate_summary(summary)
    for q in QUESTION_VECTORS:
        similarity_estimate(agg_sum, q, )
    

