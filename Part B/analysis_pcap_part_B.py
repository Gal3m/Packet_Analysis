import struct
import dpkt

number_of_transactions = 2
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
        except:
            P.is_valid = False

class Connection:
    packets=[]
    src_port = ""
    dst_port= ""
    def __init__(P,src,dst):
        P.src_port=src
        P.dst_port=dst

#check for packet loss
def calc_loss(connection):
    loss = 0
    triple_acknowledgement_loss = 0
    ack_dict = {}
    sequence_dict = {}
    
    for p in connection.packets:
        if (p.src_ip == "130.245.145.12" and p.dst_ip == "128.208.2.198"):
            sequence_dict[p.seq_number] = sequence_dict.get(p.seq_number,0) + 1
        if (p.src_ip == "128.208.2.198" and p.dst_ip == "130.245.145.12"):
            ack_dict[p.ack_number] = ack_dict.get(p.ack_number,0) + 1

    for key,value in sequence_dict.items():
        if (key in ack_dict) and (ack_dict[key] > 2):
            triple_acknowledgement_loss += sequence_dict[key]-1
        elif key in sequence_dict:
            loss += sequence_dict[key]-1

    print ("Triple Acknowledgement Loss = %s "%str(triple_acknowledgement_loss))
    print ("Timeout Loss = %s"%str(loss))

def check_ports(p1,p2):
    if p1.src_port == p2.dst_port and p2.src_port == p1.dst_port:
        return True
    if p1.src_port == p2.src_port and p2.dst_port == p1.dst_port:
        return True
    return False
 
def congestionWindow(connection):
    congestion_windows = []
    first_packet = True
    first_packet_timestamp = last_packet_timestamp = 0
    seq_number = 0
    i = 0
    count = 0
    c = 0
    for p in connection.packets:
        c += 1
        if i > 11:
            break
        if (p.src_ip == "130.245.145.12" and p.dst_ip == "128.208.2.198"):
            count = count + 1
            if first_packet:
                first_packet_timestamp = p.timestamp
                first_packet = False
                seq_number = int(p.seq_number)
            elif (p.timestamp-first_packet_timestamp)>(0.073):
                if i!=0:
                    print ("Congestion Window = %s "%(count*1460))
                count = 0
                first_packet = True
                i += 1
    print("\n")

if __name__=='__main__':
    packets = []
    connections = []
    tcp_connection_count = 0
    for timestamp,buffer in dpkt.pcap.Reader(open('assignment2.pcap','rb')):
        p = TCP_Packet()
        p.parse_packets(timestamp,buffer)
        if p.is_valid:
            packets.append(p)
            if p.syn == "1" and p.ack == "1":
                tcp_connection_count += 1
                connection = Connection(p.src_port, p.dst_port)
                connection.packets = []
                connections.append(connection)

    for p in packets:
        for connection in range(0,len(connections),1):
            if check_ports(p,connections[connection]):
                connections[connection].packets.append(p)

    k=1
    print ("\nTcp connection count = %s \n"%tcp_connection_count)
    for connection in connections:
        print ("----------------------------------- Connection %s ---------------------------------------" %k)
        calc_loss(connection)
        congestionWindow(connection)
        k = k + 1
 
