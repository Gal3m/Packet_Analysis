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

#calculate throughput
def calc_throughput(connection):
    first_packet = True
    total_payload = 0
    first_packet_timestamp = 0
    last_packet_timestamp = 0
    tput = 0
    i=0
    for p in connection.packets:
        if p.dst_ip == "128.208.2.198":
            if first_packet:
                first_packet_timestamp = p.timestamp
                first_packet = False
            else:
                if i <= number_of_transactions:
                    if i!=0:
                        print ('seq# (raw) = ',p.seq_number,'| ack# (raw) = ',p.ack_number,'| receive window size = ',p.window_size)
                    i += 1
                total_payload += int(p.size)
                last_packet_timestamp = p.timestamp

    tput = (total_payload/(last_packet_timestamp-first_packet_timestamp))/125000
    return tput

#check for packet loss
def calc_loss(connection):
    loss = 0
    total_sent = 0
    sequence_dict = {}
    
    for p in connection.packets:
        if (p.src_ip == "130.245.145.12" and p.dst_ip == "128.208.2.198"):
            total_sent += 1
            sequence_dict[p.seq_number] = sequence_dict.get(p.seq_number,0) + 1

    for key,value in sequence_dict.items():
        if key in sequence_dict:
            loss += sequence_dict[key]-1

    return (loss*1.0/total_sent)

def check_ports(p1,p2):
    if p1.src_port == p2.dst_port and p2.src_port == p1.dst_port:
        return True
    if p1.src_port == p2.src_port and p2.dst_port == p1.dst_port:
        return True
    return False

def calc_rtt(connection):
    ack_dict = {}
    sequence_dict = {}
    transactions = 0
    total_time = 0
    for p in connection.packets:
        if (p.src_ip == "130.245.145.12" and p.dst_ip == "128.208.2.198" and p.seq_number not in sequence_dict):
            sequence_dict[p.seq_number] = p.timestamp
        
        if p.src_ip == "128.208.2.198" and p.dst_ip == "130.245.145.12":
            ack_dict[p.ack_number] = p.timestamp

    for key,value in sequence_dict.items():
        if str((int(key)+1)) in ack_dict:
            transactions += 1
            total_time += ack_dict[str((int(key)+1))] - value

    return (total_time/transactions)

def make_output(connections):
    k=1
    print ("\nNumber of Tcp Connections = %s "%tcp_connection_count)
    for connection in connections:
        print ("----------------------------------- Connection %s ---------------------------------------" %k)
        print ("MSS: %s" %connection.packets[0].mss)
        print ("For the first 2 transactions after the TCP connection is set up")
        print ("Throughput = %0.5f Mbs" %(calc_throughput(connection)))
        print ("Average RTT = %0.5f ms" %(calc_rtt(connection)*1000))
        print ("Loss Rate = %0.5f"%calc_loss(connection))
        k = k + 1

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

    make_output(connections)
 
