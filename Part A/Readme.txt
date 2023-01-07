How to run program

1. Install prerequisite library

pip install dpkt

2. Make sure a copy of assignment2.pcap should be in the Part A directory

python analysis_pcap_part_A.py

Program Output-------------------------------------------------

Number of Tcp Connections = 3 
----------------------------------- Connection 1 ---------------------------------------
MSS: 1460
For the first 2 transactions after the TCP connection is set up
seq# (raw) =  705669103 | ack# (raw) =  1921750144 | receive window size =  3
seq# (raw) =  705669127 | ack# (raw) =  1921750144 | receive window size =  3
Throughput = 42.01083 Mbs
Average RTT = 73.00401 ms
Loss Rate = 0.00057
----------------------------------- Connection 2 ---------------------------------------
MSS: 1460
For the first 2 transactions after the TCP connection is set up
seq# (raw) =  3636173852 | ack# (raw) =  2335809728 | receive window size =  3
seq# (raw) =  3636173876 | ack# (raw) =  2335809728 | receive window size =  3
Throughput = 10.28329 Mbs
Average RTT = 72.70503 ms
Loss Rate = 0.01344
----------------------------------- Connection 3 ---------------------------------------
MSS: 1460
For the first 2 transactions after the TCP connection is set up
seq# (raw) =  2558634630 | ack# (raw) =  3429921723 | receive window size =  3
seq# (raw) =  2558634654 | ack# (raw) =  3429921723 | receive window size =  3
Throughput = 11.85125 Mbs
Average RTT = 73.50779 ms
Loss Rate = 0.00137



