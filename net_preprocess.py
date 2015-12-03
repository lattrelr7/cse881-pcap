#!python3
import argparse
import ctypes
import socket
import struct
import sys
import os
import uuid
import sqlite3
from ip_structs import *

# Constants
OUTGOING = 0
INCOMING = 1
SESSION_TIMEOUT = 3000000 # us to expire session

# Globals
session_keys = {}
session_key_feature_map = {}

def main():
    """ 1) process arguments and the import the wpcap dll
        2) use wpcap dll to extract all the raw packets from the .pcap file
        3) for each raw packet, parse out information from the headers
           each IP found is tracked as a 'session' so we can identify behavior
           that spans beyond a single message.
        4) insert all the sessions into a sparsely populated sqlite3 database
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", type=str, help="Wireshark capture in tcpdump format.")
    parser.add_argument("nic_ip", type=str, help="Capture NICs IP address.")
    parser.add_argument("-label", type=str, help="Label samples as they are inserted?")
    parser.add_argument("--skipdb", action="store_true", help="Don't update db, just print samples")
    args = parser.parse_args()
    
    # Convert nic_ip string to int
    nic_ip = int.from_bytes(socket.inet_aton(args.nic_ip), byteorder="big", signed=False)
    
    # Import the pcap dll
    try:
        wpcap = ctypes.WinDLL("wpcap")
    except Exception as e:
        print("Failed to load dll. Is winpcap installed?: ", e)
        sys.exit(1)
    
    # Open the pcap file
    err_buf = ctypes.create_string_buffer(256)
    file_path = ctypes.c_char_p(bytes(args.pcap_file, 'utf-8'))
    pcap_handle = wpcap.pcap_open_offline(file_path, err_buf)
    
    # Verify pcap file was opened OK
    if(pcap_handle != 0):
        # Extract the data from the raw packets
        pkthdr_ptr = ctypes.POINTER(pcap_pkthdr_t)()
        pktdata_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        status = wpcap.pcap_next_ex(pcap_handle, ctypes.byref(pkthdr_ptr), ctypes.byref(pktdata_ptr))
        count = 0
        while(status >= 0):
            process_packet(pkthdr_ptr.contents, pktdata_ptr, nic_ip)
            count += 1
            if(count % 1000 == 0): 
                show_progress()
            status = wpcap.pcap_next_ex(pcap_handle, ctypes.byref(pkthdr_ptr), ctypes.byref(pktdata_ptr))
    else:
        print("Failed to open file: ", err_buf.value.decode())
        sys.exit(1)
      
    if(args.skipdb):
        # Print out session objects
        for session in session_key_feature_map.values():
            print(session)
    else:
        # Create samples.db if it doesn't exist, then insert sessions
        if(not os.path.exists("samples.db")):
            create_sql_db()     
        insert_sessions_into_samples(args.label)
        insert_sessions_into_tcp_samples(args.label)
        insert_sessions_into_udp_samples(args.label)
        insert_sessions_into_icmp_samples(args.label)
        
        
def insert_sessions_into_samples(label):
    """ Insert the session objects into the samples.db database
    in a format that hopefully makes sense for mining applications
    
    args:
        label(bool): Prompt for class type when inserting a row
    """
    conn = sqlite3.connect('samples.db')
    c = conn.cursor()

    for key, session in session_key_feature_map.items():
        show_progress()
        c.execute('''INSERT INTO samples 
                    (uuid,
                    bytes_txed,
                    bytes_rxed,
                    interarrival_time,
                    udp_protocol,
                    tcp_protocol,
                    icmp_protocol,
                    igmp_protocol,
                    src_port_cnt,
                    dst_port_cnt,
                    tcp_syn_cnt,
                    tcp_rst_cnt,
                    tcp_ack_cnt,
                    icmp_echo_cnt,
                    icmp_reply_cnt,
                    icmp_unreachable_cnt,
                    icmp_redirect_cnt,
                    icmp_timeout_cnt)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                  (hash(key),
                  session.bytes_txed,
                  session.bytes_rxed,
                  session.arrival_diff_avg,
                  int(session.ip_protocol == IPT_UDP),
                  int(session.ip_protocol == IPT_TCP),
                  int(session.ip_protocol == IPT_ICMP),
                  int(session.ip_protocol == IPT_IGMP),
                  len(session.src_ports),
                  len(session.dst_ports),
                  session.tcp_syn_count,
                  session.tcp_rst_count,
                  session.tcp_ack_count,
                  session.icmp_echo_count,
                  session.icmp_reply_count,
                  session.icmp_unreachable_count,
                  session.icmp_redirect_count,
                  session.icmp_timeout_count))
        
        ports = session.dst_ports
        if(len(session.dst_ports) <= 5): # If we save this info from a port scan it messes up distance measures
            for port in ports:
                #Only add if not ephemeral port
                if(port < 49152):
                    show_progress()
                    try:
                        c.execute("ALTER TABLE samples ADD COLUMN 'port_%s' int" % str(port))
                    except sqlite3.OperationalError:
                        pass
                    c.execute('''UPDATE samples SET port_%s=1 WHERE uuid=%s''' % (str(port), str(hash(key))))  
                
        if(label is not None):
            c.execute('''UPDATE samples SET class='%s' WHERE uuid=%s''' % (label, str(hash(key)))) 
            
    conn.commit()
    conn.close()
    
def insert_sessions_into_tcp_samples(label):
    """ Insert the session objects into the samples.db database
    in a format that hopefully makes sense for mining applications
    
    args:
        label(bool): Prompt for class type when inserting a row
    """
    conn = sqlite3.connect('samples.db')
    c = conn.cursor()

    for key, session in session_key_feature_map.items():
        if(session.ip_protocol != IPT_TCP): continue
        show_progress()
        c.execute('''INSERT INTO tcp_samples 
                    (uuid,
                    bytes_txed,
                    bytes_rxed,
                    interarrival_time,
                    src_port_cnt,
                    dst_port_cnt,
                    tcp_syn_cnt,
                    tcp_rst_cnt,
                    tcp_ack_cnt)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                  (hash(key),
                  session.bytes_txed,
                  session.bytes_rxed,
                  session.arrival_diff_avg,
                  len(session.src_ports),
                  len(session.dst_ports),
                  session.tcp_syn_count,
                  session.tcp_rst_count,
                  session.tcp_ack_count))
        
        ports = session.dst_ports
        if(len(session.dst_ports) <= 5): # If we save this info from a port scan it messes up distance measures
            for port in ports:
                #Only add if not ephemeral port
                if(port < 49152):
                    show_progress()
                    try:
                        c.execute("ALTER TABLE tcp_samples ADD COLUMN 'port_%s' int" % str(port))
                    except sqlite3.OperationalError:
                        pass
                    c.execute('''UPDATE tcp_samples SET port_%s=1 WHERE uuid=%s''' % (str(port), str(hash(key))))  
                
        if(label is not None):
            c.execute('''UPDATE tcp_samples SET class='%s' WHERE uuid=%s''' % (label, str(hash(key)))) 
            
    conn.commit()
    conn.close()
    
def insert_sessions_into_udp_samples(label):
    """ Insert the session objects into the samples.db database
    in a format that hopefully makes sense for mining applications
    
    args:
        label(bool): Prompt for class type when inserting a row
    """
    conn = sqlite3.connect('samples.db')
    c = conn.cursor()

    for key, session in session_key_feature_map.items():
        if(session.ip_protocol != IPT_UDP): continue
        show_progress()
        c.execute('''INSERT INTO udp_samples 
                    (uuid,
                    bytes_txed,
                    bytes_rxed,
                    interarrival_time,
                    src_port_cnt,
                    dst_port_cnt)
                    VALUES (?,?,?,?,?,?)''',
                  (hash(key),
                  session.bytes_txed,
                  session.bytes_rxed,
                  session.arrival_diff_avg,
                  len(session.src_ports),
                  len(session.dst_ports)))
        
        ports = session.dst_ports
        if(len(session.dst_ports) <= 5): # If we save this info from a port scan it messes up distance measures
            for port in ports:
                #Only add if not ephemeral port
                if(port < 49152):
                    show_progress()
                    try:
                        c.execute("ALTER TABLE udp_samples ADD COLUMN 'port_%s' int" % str(port))
                    except sqlite3.OperationalError:
                        pass
                    c.execute('''UPDATE udp_samples SET port_%s=1 WHERE uuid=%s''' % (str(port), str(hash(key))))  
                
        if(label is not None):
            c.execute('''UPDATE udp_samples SET class='%s' WHERE uuid=%s''' % (label, str(hash(key)))) 
            
    conn.commit()
    conn.close()
    
def insert_sessions_into_icmp_samples(label):
    """ Insert the session objects into the samples.db database
    in a format that hopefully makes sense for mining applications
    
    args:
        label(bool): Prompt for class type when inserting a row
    """
    conn = sqlite3.connect('samples.db')
    c = conn.cursor()

    for key, session in session_key_feature_map.items():
        if(session.ip_protocol != IPT_ICMP): continue
        show_progress()
        c.execute('''INSERT INTO icmp_samples 
                    (uuid,
                    bytes_txed,
                    bytes_rxed,
                    interarrival_time,
                    icmp_echo_cnt,
                    icmp_reply_cnt,
                    icmp_unreachable_cnt,
                    icmp_redirect_cnt,
                    icmp_timeout_cnt)
                    VALUES (?,?,?,?,?,?,?,?,?)''',
                  (hash(key),
                  session.bytes_txed,
                  session.bytes_rxed,
                  session.arrival_diff_avg,
                  session.icmp_echo_count,
                  session.icmp_reply_count,
                  session.icmp_unreachable_count,
                  session.icmp_redirect_count,
                  session.icmp_timeout_count)) 
        
        if(label is not None):
            c.execute('''UPDATE icmp_samples SET class='%s' WHERE uuid=%s''' % (label, str(hash(key))))
            
    conn.commit()
    conn.close()

def create_sql_db():
    """ Create the database 'samples.db' and setup
    the table for the samples.
    """
    conn = sqlite3.connect('samples.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE samples
               (uuid int primary key,
                class text,
                bytes_txed int,
                bytes_rxed int,
                interarrival_time real,
                udp_protocol int,
                tcp_protocol int,
                icmp_protocol int,
                igmp_protocol int,
                src_port_cnt int,
                dst_port_cnt int,
                tcp_syn_cnt int,
                tcp_rst_cnt int,
                tcp_ack_cnt int,
                icmp_echo_cnt int,
                icmp_reply_cnt int,
                icmp_unreachable_cnt int,
                icmp_redirect_cnt int,
                icmp_timeout_cnt int)''')
    
    c.execute('''CREATE TABLE tcp_samples
               (uuid int primary key,
                class text,
                bytes_txed int,
                bytes_rxed int,
                interarrival_time real,
                src_port_cnt int,
                dst_port_cnt int,
                tcp_syn_cnt int,
                tcp_rst_cnt int,
                tcp_ack_cnt int)''')
    
    c.execute('''CREATE TABLE udp_samples
               (uuid int primary key,
                class text,
                bytes_txed int,
                bytes_rxed int,
                interarrival_time real,
                src_port_cnt int,
                dst_port_cnt int)''')
    
    c.execute('''CREATE TABLE icmp_samples
               (uuid int primary key,
                class text,
                bytes_txed int,
                bytes_rxed int,
                interarrival_time real,
                icmp_echo_cnt int,
                icmp_reply_cnt int,
                icmp_unreachable_cnt int,
                icmp_redirect_cnt int,
                icmp_timeout_cnt int)''')
    
    conn.commit()
    conn.close()
    
def show_progress():
    sys.stdout.write(".")
    sys.stdout.flush()
        
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
        self.icmp_echo_count = 0
        self.icmp_reply_count = 0
        self.icmp_unreachable_count = 0
        self.icmp_redirect_count = 0
        self.icmp_timeout_count = 0
        # Helper fields
        self.current_direction = OUTGOING
        self.last_timestamp = 0
        self.arrival_diff_avg = 0;
        self.num_packets = 0;
        
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
        session.ip_protocol = protocol
        session_keys[key_str] = new_session_key
        session_key_feature_map[new_session_key] = session
    # Otherwise our session is the existing one
    else:
        session = session_key_feature_map[session_keys[key_str]]
        
    # Update the timestamp for this session
    session.num_packets += 1;
    if(session.num_packets > 2):
        # On-line avg calculation...avg = sum / n; sum = avg * n 
        # -- recover sum from avg and n, then plus 1 
        session.arrival_diff_avg = ((session.arrival_diff_avg * (session.num_packets - 1)) 
            + (timestamp - session.last_timestamp)) / session.num_packets
    elif(session.num_packets == 2):
        session.arrival_diff_avg = timestamp - session.last_timestamp
    session.last_timestamp = timestamp 
    
    return session
            
def process_packet(pktheader, pktdata, nic_ip):
    """ Extract data from raw packet starting at frame.
    args:
        pktdata(bytearray): Raw packet bytes
        timestamp(int): Timestamp for packet arrival
        nic_ip(int): IP of the NIC this packet came in on
    """
    timestamp = pktheader.ts.tv_sec + (pktheader.ts.tv_usec / 1000000)
    pktdata = bytearray(pktdata[:pktheader.len])

    # Assume first 14 bytes are frame header
    ether_type = process_frame(pktdata)
    offset = FRAME_HDR_LEN
        
    # The session (object for attributes) is based on the IP layer
    session = None
    if(ether_type == ET_IPv4): 
        (ip_type, session) = process_ipv4(pktdata, offset, timestamp, nic_ip)
        offset += IPV4_HDR_LEN
        
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
        elif(ip_type == IPT_ICMP):
            process_icmp(pktdata, offset, session)
            offset += ICMP_HDR_LEN            
        
def process_frame(pktdata):
    """ Get what type of packet is in the IP layer
    args:
        pktdata(bytearray): Raw packet bytes
    returns:
        ethertype(int): Encapsulated type.  Can be IPv4, IPv6, ARP, etc..
                        Only IPv4 is actually handled, however.
    """    
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
        #print("WARNING: Neither", str(ip_header.src_ip), "or", str(ip_header.dst_ip), "match", str(nic_ip))
        session = None
        
    # If fragmented, add bytes txed/rxed, but don't look at lower layers
    # until we have the whole thing.  Do this by setting
    # session to None
    if(ip_header.flags_frag_offset & IP_MORE_FRAGMENTS):
        session.ip_fragment_count += 1
        session = None
    
    return (ip_header.protocol, session)

def process_icmp(pktdata, offset, session):
    """ Extract data from the ICMP header.
    
    args:
        pktdata(bytearray): Raw packet bytes
        offset(int): Bytes before the ICMP header
        session(SessionFeatures): Current session
    """
    icmp_header = icmp_header_t.from_buffer(pktdata[offset:offset+ICMP_HDR_LEN])
    if(icmp_header.type == ICMPT_ECHO_REPLY):
        session.icmp_reply_count += 1
    elif(icmp_header.type == ICMPT_ECHO_REQUEST):
        session.icmp_echo_count += 1        
    elif(icmp_header.type == ICMPT_DEST_UNREACHABLE):
        session.icmp_unreachable_count += 1  
    elif(icmp_header.type == ICMPT_REDIRECT):
        session.icmp_redirect_count += 1  
    elif(icmp_header.type == ICMPT_TIMEOUT):
        session.icmp_timeout_count += 1          

def process_udp(pktdata, offset, session):
    """ Extract data from the UDP header.
    
    args:
        pktdata(bytearray): Raw packet bytes
        offset(int): Bytes before the UDP header
        session(SessionFeatures): Current session
    """    
    udp_header = udp_header_t.from_buffer(pktdata[offset:offset+UDP_HDR_LEN])
    session.dst_ports.add(udp_header.dst_port)
    session.src_ports.add(udp_header.src_port)
        
def process_tcp(pktdata, offset, session):
    """ Extract data from the TCP header.
    
    args:
        pktdata(bytearray): Raw packet bytes
        offset(int): Bytes before the TCP header
        session(SessionFeatures): Current session
    """       
    tcp_header = tcp_header_t.from_buffer(pktdata[offset:offset+TCP_HDR_LEN])
    session.dst_ports.add(tcp_header.dst_port)
    session.src_ports.add(tcp_header.src_port)
    
    if(tcp_header.offset_type & TCP_ACK):
        session.tcp_ack_count += 1
    if(tcp_header.offset_type & TCP_SYN):
        session.tcp_syn_count += 1
    if(tcp_header.offset_type & TCP_RST):
        session.tcp_rst_count += 1
    
if __name__ == "__main__": main()