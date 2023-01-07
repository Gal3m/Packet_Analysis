import struct
import dpkt
from collections import defaultdict

def extract_values(buffer,f,position,field_size):
    if(len(buffer)>position):
        return str(struct.unpack(f,buffer[position:position+field_size])[0])
    else:
        pass

class TCP_Packet:
    is_valid = True
    timestamp = 0
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    seq_number = ""
    ack_number = ""
    syn = ""
    ack = ""
    header_size = ""
    window_size = ""
    size = ""
    mss = ""
      
    def parse_packets(P,timestamp,buffer):
        try:
            x,y = 26,30
            while x<29:
                P.src_ip = P.src_ip + extract_values(buffer,">B",x,1) + "."
                P.dst_ip = P.dst_ip + extract_values(buffer,">B",y,1) + "."
                x=x+1
                y=y+1
            P.timestamp = timestamp
            P.src_ip = P.src_ip + extract_values(buffer,">B",x,1)
            P.dst_ip =P.dst_ip + extract_values(buffer,">B",y,1)
            P.src_port = extract_values(buffer,">H",34,2)
            P.dst_port = extract_values(buffer,">H",36,2)
            P.seq_number = extract_values(buffer,">I",38,4)
            P.ack_number = extract_values(buffer,">I",42,4)
            P.syn = "{0:16b}".format(int(extract_values(buffer,">H",46,2)))[14]
            P.ack = "{0:16b}".format(int(extract_values(buffer,">H",46,2)))[11]
            P.header_size = extract_values(buffer,">B",46,1)
            P.window_size = extract_values(buffer,">H",48,2)
            P.size = len(buffer)
            P.mss = extract_values(buffer,">H",56, 2)
            if(P.size > 66):
                P.request = str(extract_values(buffer,">s",66,1))+str(extract_values(buffer,">s",67,1)) + str(extract_values(buffer,">s",68,1))
                P.response = str(extract_values(buffer,">s",66,1))+str(extract_values(buffer,">s",67,1)) + str(extract_values(buffer,">s",68,1))+str(extract_values(buffer,">s",69,1))
        except:
            P.is_valid = False

class Connection:
    packets=[]
    src_port = ""
    dst_port= ""
    def __init__(P,src,dst):
        P.src_port=src
        P.dst_port=dst

if __name__=='__main__':
    pcap_files = ['http_1080.pcap','tcp_1081.pcap','tcp_1082.pcap']
    for f in pcap_files:
        print ("------------------------------PCAP File: %s--------------------------------"%f)
        packets = []
        connections = []
        tcp_connection_count = 0
        packet_count = 0
        total_payload = 0

        for timestamp,buffer in dpkt.pcap.Reader(open(f,'rb')):
            p = TCP_Packet()
            p.parse_packets(timestamp,buffer)
            if p.is_valid:
                packets.append(p)
                packet_count += 1
                total_payload += p.size
                if p.syn == "1" and p.ack == "1":
                    tcp_connection_count += 1

        print ("Tcp connection count = %s"%tcp_connection_count)
        print ("Time Taken = %s"%str(packets[len(packets)-1].timestamp-packets[0].timestamp))
        print ("Packet Count = %s"%str(packet_count))
        print ("Raw data size = %s \n"%str(total_payload))
    
        req_dict = defaultdict(list)
        rsp_dict = defaultdict(list)
 
        for packet in packets:
            if(packet.size > 66):
                get_value = "b'G'b'E'b'T'"
                http_value = "b'H'b'T'b'T'b'P'"
                i=0
                if packet.request == get_value:
                    x = packet.src_ip
                    if packet.src_port not in req_dict:
                        req_dict[packet.src_port].append((packet.src_ip,packet.dst_ip,packet.seq_number,packet.ack_number))
                if packet.response == http_value and packet.dst_ip == x:
                    dict = []
                    dict += ((packet.src_ip,packet.dst_ip,packet.seq_number,packet.ack_number))
                rsp_dict[packet.dst_port].append(dict)
                    
        req_set = set(req_dict)
        resp_set = set(rsp_dict)

        for key in req_set.intersection(resp_set):
            print ("HTTP REQUEST %s " %str(req_dict[key]))
            print ("Response: ")
            for value in rsp_dict[key]:
                print (value)
            print ("\n")

        print ("\n")

 
