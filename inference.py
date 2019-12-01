"""
File: inference.py
Description: Inference module, functionality to be implemented in future work.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""

import pandas
import random

def inference_mod(summary):
    rand_num = random.randint(0, 1000)
    if rand_num < 100:
        print("Dummy Error!")

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
    