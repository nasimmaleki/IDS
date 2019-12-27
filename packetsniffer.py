import socket, sys
import operator
from threading import Timer
from Queue import Queue
from collections import defaultdict, Counter
from struct import *

connections = []


# This Function is for getting mac addr
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# create second thread
start_index = 0
end_index = 0


f = open("featureflow.csv", "w")
f2=open("networkflow.csv","w")
result=""


def thread():
    global start_index
    global end_index
    start_index = end_index
    end_index = len(connections)
    T_connections = connections[start_index:end_index]
    # print(len(connections),end_index,start_index,"aliiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii",len(T_connections))
    if len(T_connections) != 0:
        cnt_SIP = Counter()
        cnt_SIP_DProtocolService = Counter()
        zerosize=0

        for item in T_connections:
            cnt_SIP[item['SIP']] += 1
            cnt_SIP_DProtocolService[item['SIP'] + ' ' + item['protocol'] + ' ' + item['DP']] += 1
            if item['size']==0:
                zerosize+=1
        if len(cnt_SIP) != 0:
            SIP_max = max(cnt_SIP.iteritems(), key=operator.itemgetter(1))
            print(SIP_max)
        if len(cnt_SIP) != 0:
            DP_max = max(cnt_SIP_DProtocolService.iteritems(), key=operator.itemgetter(1))
            print(DP_max)
        global result
        if DP_max[0]== "192.168.1.3 TCP 80" :
            label=1
        else:
            label=0
        result=str(DP_max[1])+","+str(SIP_max[1])+","+str(zerosize/(len(T_connections)*1.0))+","+str(label)+"\n"
        # result= DP_max[0] + ":" + str(DP_max[1]) + ", " + SIP_max[0] + ":" + str(SIP_max[1]) + "\n"
        # writeQueue.put(repr(result))

    Timer(10, thread).start()


Timer(1, thread).start()

# create a AF_PACKET type raw socket (thats basically packet level)
# define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
    # print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet

while True:

    # while not qu.empty():

    f.write(result)
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        if (s_addr == "127.0.0.1" or s_addr == "127.0.1.1") and (d_addr == "127.0.0.1" or d_addr == "127.0.1.1"):
            continue
        # print '\nDestination MAC: ' + eth_addr(packet[0:6]) + '\nSource MAC : ' + eth_addr(packet[6:12]) + '\nProtocol : ' + str(eth_protocol)+'\nVersion : ' + str(version) + '\nIP Header Length : ' + str(ihl) + '\n TTL : ' + str(ttl) + '\nProtocol : ' + str(protocol) + '\nSource Address : ' + str(s_addr) + '\nDestination Address : ' + str(d_addr)+'\n'
        # connections.append({'SIP': str(s_addr),'DIP': str(d_addr),'SP': '','DP': '','protocol': str(protocol)})
        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            # now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            # print'\nDestination MAC : ' + eth_addr(packet[0:6]) + '\nSource MAC : ' + eth_addr(packet[6:12]) + '\nProtocol : ' + str(eth_protocol)+'\nprotocol: TCP' + '\nSource Port : ' + str(source_port) + '\nDest Port : ' + str(dest_port) + ' \nSequence Number : ' + str(sequence) + '\nAcknowledgement : ' + str(acknowledgement) + '\nTCP header length : ' + str(tcph_length)+'\n'


            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            connections.append({'size': len(data), 'SIP': str(s_addr), 'DIP': str(d_addr), 'SP': str(source_port),
                                'DP': str(dest_port),
                                'protocol': "TCP"})
            print (connections[-1])
            flow='size:'+str(len(data))+'SIP:'+ str(s_addr)+'DIP:'+str(d_addr)+'SP:'+str(source_port)+'DP:'+ str(dest_port)+'protocol:TCP'
            f2.write(flow)
            # print 'Data : ' + data

        # ICMP Packets
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]

            # now unpack them :)
            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            # print'\nDestination MAC : ' + eth_addr(packet[0:6]) + '\nSource MAC : ' + eth_addr(packet[6:12]) + '\nProtocol : ' + str(eth_protocol)+'\nprotocol: ICMP \nType : ' + str(icmp_type) + '\nCode : ' + str(code) + '\nChecksum : ' + str(checksum)+'\n'

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            connections.append(
                {'size': len(data), 'SIP': str(s_addr), 'DIP': str(d_addr), 'SP': '', 'DP': '', 'protocol': "ICMP"})
            print (connections[-1])
            flow = 'size:' + str(len(data)) + 'SIP:' + str(s_addr) + 'DIP:' + str(d_addr) + 'SP:' + str(
                source_port) + 'DP:' + str(dest_port) + 'protocol:ICMP'
            f2.write(flow)
            # print 'Data : ' + data

        # UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]

            # now unpack them :)
            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            # print'\nDestination MAC : ' + eth_addr(packet[0:6]) + '\nSource MAC : ' + eth_addr(packet[6:12]) + '\nProtocol : ' + str(eth_protocol)+'\nprotocol: UDP \nSource Port : ' + str(source_port) + '\nDest Port : ' + str(dest_port) + '\nLength : ' + str(length) + '\nChecksum : ' + str(checksum)+'\n'


            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]
            connections.append({'size': len(data), 'SIP': str(s_addr), 'DIP': str(d_addr), 'SP': str(source_port),
                                'DP': str(dest_port),
                                'protocol': "UDP"})
            print (connections[-1])
            flow = 'size:' + str(len(data)) + 'SIP:' + str(s_addr) + 'DIP:' + str(d_addr) + 'SP:' + str(
                source_port) + 'DP:' + str(dest_port) + 'protocol:UDP'
            f2.write(flow)
            #  print 'Data : ' + data

        # some other IP packet like IGMP
        else:
            # print 'Protocol other than TCP/UDP/ICMP'
            pass

            # print

