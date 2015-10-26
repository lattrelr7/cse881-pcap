#!python3
import argparse
import ctypes
import socket
import struct
import sys
import uuid
from ip_structs import *

# Constants
OUTGOING = 0
INCOMING = 1
SESSION_TIMEOUT = 3000000 # us to expire session

# Globals
session_keys = {}
session_key_feature_map = {}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", type=str, help="Wireshark capture in tcpdump format.")
    parser.add_argument("nic_ip", type=str, help="Capture NICs IP address.")
    args = parser.parse_args()
    
    # Convert nic_ip string to int
    nic_ip = int.from_bytes(socket.inet_aton(args.nic_ip), byteorder="big", signed=False)
    
    # Import the pcap dll
    try:
        wpcap = ctypes.WinDLL("wpcap")
    except Exception as e:
        print("Failed to load dll: ", e)
        sys.exit(1)
    
    # Open the pcap file
    err_buf = ctypes.create_string_buffer(256)
    file_path = ctypes.c_char_p(bytes(args.pcap_file, 'utf-8'))
    pcap_handle = wpcap.pcap_open_offline(file_path, err_buf)
    
    # Verify pcap file was opened OK
    if(pcap_handle != 0):
        # Extract the data from the raw packet
        pkthdr_ptr = ctypes.POINTER(pcap_pkthdr_t)()
        pktdata_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        status = wpcap.pcap_next_ex(pcap_handle, ctypes.byref(pkthdr_ptr), ctypes.byref(pktdata_ptr))
        while(status >= 0):
            process_packet(pkthdr_ptr.contents, pktdata_ptr, nic_ip)
            status = wpcap.pcap_next_ex(pcap_handle, ctypes.byref(pkthdr_ptr), ctypes.byref(pktdata_ptr))
    else:
        print("Failed to open file: ", err_buf.value.decode())
        sys.exit(1)
        
    for session in session_key_feature_map.values():
        print(session)
        
def insert_sessions_into_sql():
    """ Prompt cin for class label before insertion of each session?
    """
    pass
        
class SessionFeatures(object):
    def __init__(self):
        # Data to go in DB
        self.bytes_rxed = 0
        self.bytes_txed = 0
        self.src_ports = set()
        self.dst_ports = set()
        self.tcp_syn_count = 0
        self.tcp_ack_count = 0
        self.tcp_rst_count = 0
        self.ip_protocol = 0
        self.ip_fragment_count = 0
        # Helper fields
        self.current_direction = OUTGOING
        self.last_timestamp = 0
        
    def __str__(self):
        print_this = "bytes_rxed: " + str(self.bytes_rxed) + "\n"
        print_this += "bytes_txed: " + str(self.bytes_txed) + "\n"
        print_this += "src_ports: " + str(self.src_ports) + "\n"
        print_this += "dst_ports: " + str(self.dst_ports) + "\n"
        print_this += "ip_protocol: " + str(self.ip_protocol) + "\n"
        return print_this
    
def get_session(foreign_ip, protocol, timestamp):
    """ Get a 'session', which is where the features for the current transaction is
    stored.  A 'session' records data transmitted, ports used, etc, which is later
    stored in a sql database, and then put into a format a data mining algorithm
    case make use of.  A 'session' is defined by the current IP address and
    protocol, and has an arbitrary time for timing out (start a new session 
    instead of updating the old one)
    
    args:
        foreign_ip(int): IP address that is not the capture NICs
        protocol(int): Protocol field from IP header
        timestamp(int): Time packet was received at
    return:
        session(SessionFeatures): Session to store transaction data in
    """
    # Create key to look up our key with.  Kind of meta.
    key_str = str(foreign_ip) + ":" + str(protocol)
    
    # Make a new session if one doesn't exist for this ip/protocol
    # or if the session has expired
    if(session_keys.get(key_str) is None or
       (session_key_feature_map[session_keys[key_str]].last_timestamp + SESSION_TIMEOUT) < timestamp):
        # Create unique key for session
        # and create new SessionFeatures object
        new_session_key = uuid.uuid4()
        session = SessionFeatures()
        session_keys[key_str] = new_session_key
        session_key_feature_map[new_session_key] = session
    # Otherwise our session is the existing one
    else:
        print("Continuing session.")
        session = session_key_feature_map[session_keys[key_str]]
        
    # Update the timestamp for this session
    session.last_timestamp = timestamp
    session.ip_protocol = protocol
    
    return session
            
def process_packet(pktheader, pktdata, nic_ip):
    timestamp = pktheader.ts.tv_sec + (pktheader.ts.tv_usec / 1000000)
    pktdata = bytearray(pktdata[:pktheader.len])

    # Assume first 14 bytes are frame header
    ether_type = process_frame(pktdata)
    offset = FRAME_HDR_LEN
        
    # The session (object for attributes) is based on the IP layer
    # both IPv4 and IPv6 processing can return the session
    session = None
    if(ether_type == ET_IPv4): 
        (ip_type, session) = process_ipv4(pktdata, offset, timestamp, nic_ip)
        offset += IPV4_HDR_LEN
    #elif(ether_type == ET_IPv6): 
    #    (ip_type, session) = process_ipv6(pktdata, offset, timestamp, nic_ip)
    #    offset += IPV6_HDR_LEN
        
    # We will have a session if the IP layer was processed successfully
    # continue parsing the packet - at this point we are at the 
    # transport layer
    if(session is not None):
        if(ip_type == IPT_UDP):
            process_udp(pktdata, offset, session)
            offset += UDP_HDR_LEN
        elif(ip_type == IPT_TCP):
            process_tcp(pktdata, offset, session)
            offset += TCP_HDR_LEN
        
def process_frame(pktdata):
    frame_header = eth_frame_header_t.from_buffer(pktdata[:FRAME_HDR_LEN])
    #print("mac src", hex(frame_header.mac_src_1), hex(frame_header.mac_src_2), hex(frame_header.mac_src_3))
    #print("mac dst", hex(frame_header.mac_dst_1), hex(frame_header.mac_dst_2), hex(frame_header.mac_dst_3))
    #print("ethertype", hex(frame_header.ethertype))
    return frame_header.ethertype

def process_ipv4(pktdata, offset, timestamp, nic_ip):
    """ Extract the data from the IP layer.  Retrieve the
    session for this IP or get a new session.
    
    args:
        pktdata(bytearray): Raw packet bytes
        offset(int): Bytes before the IPv4 header
        timestamp(int): Timestamp for packet arrival
        nic_ip(int): IP of the NIC this packet came in on
    return:
        protocol(int): Value of protocol field in IPv4 packet
        session(SessionFeatures): Object for storing this sessions attributes
    """
    ip_header = ipv4_header_t.from_buffer(pktdata[offset:offset+IPV4_HDR_LEN])
    
    if(ip_header.src_ip == nic_ip):
        session = get_session(ip_header.dst_ip, ip_header.protocol, timestamp)
        session.bytes_txed += ip_header.length + offset
        session.current_direction = OUTGOING
    elif(ip_header.dst_ip == nic_ip):
        session = get_session(ip_header.src_ip, ip_header.protocol, timestamp)
        session.bytes_rxed += ip_header.length + offset
        session.current_direction = INCOMING
    else:
        print("WARNING: Neither", str(ip_header.src_ip), "or", str(ip_header.dst_ip), "match", str(nic_ip))
        session = None
        
    # If fragmented, add bytes txed/rxed, but don't look at lower layers
    # until we have the whole thing.  Do this by setting
    # session to None
    if(ip_header.flags_frag_offset & IP_MORE_FRAGMENTS):
        session.ip_fragment_count += 1
        session = None
    
    return (ip_header.protocol, session)

def process_ipv6(pktdata, offset, timestamp, nic_ip):
    ip_header = ipv6_header_t.from_buffer(pktdata[offset:offset+IPV6_HDR_LEN])
    
    if(ip_header.src_ip == nic_ip):
        session = get_session(ip_header.dst_ip, ip_header.next_header, timestamp)
        session.bytes_txed += ip_header.length + offset
        session.current_direction = OUTGOING
    elif(ip_header.dst_ip == nic_ip):
        session = get_session(ip_header.src_ip, ip_header.next_header, timestamp)
        session.bytes_rxed += ip_header.length + offset
        session.current_direction = INCOMING
        
    return (ip_header.next_header)

def process_icmp(pktdata, offset, session):
    type = 0
    return type

def process_udp(pktdata, offset, session):
    udp_header = udp_header_t.from_buffer(pktdata[offset:offset+UDP_HDR_LEN])
    
    if(session.current_direction == OUTGOING): 
        session.dst_ports.add(udp_header.dst_port)
        session.src_ports.add(udp_header.src_port)
    else:
        session.dst_ports.add(udp_header.src_port)
        session.src_ports.add(udp_header.dst_port)
        
def process_tcp(pktdata, offset, session):
    tcp_header = tcp_header_t.from_buffer(pktdata[offset:offset+TCP_HDR_LEN])
    
    if(session.current_direction == OUTGOING): 
        session.dst_ports.add(tcp_header.dst_port)
        session.src_ports.add(tcp_header.src_port)
    else:
        session.dst_ports.add(tcp_header.src_port)
        session.src_ports.add(tcp_header.dst_port)
    
    if(tcp_header.offset_type & TCP_ACK):
        session.tcp_ack_count += 1
    if(tcp_header.offset_type & TCP_SYN):
        session.tcp_syn_count += 1
    if(tcp_header.offset_type & TCP_RST):
        session.tcp_rst_count += 1

def sql_2_libsvm():
    #Turn sql data into lib svm format
    #lib svm format: <label> <feature_idx>:<feature_value> <feature_idx>:<feature_value> ...
    #also scale any non-binary data from 0 to 1.
    return
    
if __name__ == "__main__": main()