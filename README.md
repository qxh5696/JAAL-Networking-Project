This code base contains the implementation for the CSCI-651 term project, which implements a intrusion detection system that was proposed in the paper "Jaal: Towards Network Intrusion Detection at ISP Scale" by Aqil et al.
The paper can be found here: `http://www.cse.psu.edu/~trj1/papers/conext17.pdf`

To run this program with Python 3, the following dependencies are required, and can be installed using pip:
- numpy
- pandas
- scapy
- sklearn

Additionally, a test file containing a TCP packet dump is needed. We use a PCAP file from the MAWI group, which can be downloaded from http://mawi.wide.ad.jp/mawi/samplepoint-F/2016/201601011400.html. Our program expects it to be in the same directory as the main driver file `jaal.py`, with the name '201601011400.pcap'.

To run our program, ensure that the dependencies and file are present, and then run the command `python3 jaal.py` via a terminal. If errors occur, ensure that the environment you are using is Linux or Unix based--machines running Windows have been known to have issues with the sklearn library. 

The program will output the flow assignment results, and every time a monitor is assigned 1,000 packets, it will run the summarization and inference modules. The types of attacks and counts for attack packets are printed at this time. The program will not stop on its own--after some time, use CTRL + C to end the program and see a print out of the total number of times the attacks were tested, the correctly identified attack/not attacks, as well as false negatives and false positives.