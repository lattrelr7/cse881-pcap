from ctypes import *

# Ether types that we handle
# These are types that will be found in the frame header
ET_ARP = 0x0806
ET_REV_ARP = 0x8035
ET_IPv4 = 0x0800
ET_IPv6 = 0x86DD

# IP types that we handle
# These types are found in the ipv4 header
IPT_ICMP = 0x01
IPT_TCP = 0x06
IPT_UDP = 0x11
IPT_IPv6 = 0x29

# ICMP types that we handle
# These are found in the ICMP header
ICMPT_ECHO_REPLY = 0
ICMPT_ECHO_REQUEST = 8
ICMPT_DEST_UNREACHABLE = 3
ICMPT_REDIRECT = 5
ICMPT_ROUTER_AD = 9
ICMPT_ROUTER_DISC = 10
ICMPT_TIMEOUT = 11

# TCP control bit masks
TCP_NS = 0x0100
TCP_CWR = 0x0080
TCP_ECE = 0x0040
TCP_URG = 0x0020
TCP_ACK = 0x0010
TCP_PSH = 0x0008
TCP_RST = 0x0004
TCP_SYN = 0x0002
TCP_FIN = 0x0001

# IPv4 header masks
IP_MORE_FRAGMENTS = 0x2000

# Struct sizes
IPV4_HDR_LEN = 20
IPV6_HDR_LEN = 40
UDP_HDR_LEN = 8
TCP_HDR_LEN = 20
ICMP_HDR_LEN = 8
FRAME_HDR_LEN = 14
ARP_HDR_LEN = 28

#Pcap structures
class timeval_t(Structure):
    _fields_ = [('tv_sec', c_long),
                ('tv_usec', c_long)]
    
class pcap_pkthdr_t(Structure):
    _fields_ = [('ts', timeval_t),
                ('caplen', c_uint32),
                ('len', c_uint32)]

#IP structures
class ipv4_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("version_ihl", c_uint8),
                ("dscp_ecn", c_uint8),
                ("length", c_uint16),
                ("id", c_uint16),
                ("flags_frag_offset", c_uint16),
                ("ttl", c_uint8),
                ("protocol", c_uint8),
                ("checksum", c_uint16),
                ("src_ip", c_uint32),
                ("dst_ip", c_uint32)]
    
class ipv6_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("vers_class_flow_1", c_uint16),
                ("flow_2", c_uint16),
                ("length", c_uint16),
                ("next_header", c_uint8),
                ("hop_limit", c_uint8),
                ("src_addr_1", c_ulonglong),
                ("src_addr_2", c_ulonglong),
                ("dst_addr_1", c_ulonglong),
                ("dst_addr_2", c_ulonglong),]
    
class icmp_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("type", c_uint8),
                ("code", c_uint8),
                ("checksum", c_uint16),
                ("rest_of_header", c_uint32)]    
    
class udp_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("src_port", c_uint16),
                ("dst_port", c_uint16),
                ("length", c_uint16),
                ("checksum", c_uint16)]  
    
class tcp_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("src_port", c_uint16),
                ("dst_port", c_uint16),
                ("sn", c_uint32),
                ("ack_num", c_uint32),
                ("offset_type", c_uint16),
                ("window_size", c_uint16),
                ("checksum", c_uint16),
                ("urgent", c_uint16)]      
    
class arp_message_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("htype", c_uint16),
                ("ptype", c_uint16),
                ("h_addr_len", c_uint8),
                ("p_addr_len", c_uint8),
                ("oper", c_uint16),
                ("mac_src_1", c_uint16),
                ("mac_src_2", c_uint16),
                ("mac_src_3", c_uint16),
                ("src_p_addr", c_uint32),
                ("mac_dst_1", c_uint16),
                ("mac_dst_2", c_uint16),
                ("mac_dst_3", c_uint16),            
                ("dst_p_addr", c_uint32)]       
    
class eth_frame_header_t(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("mac_src_1", c_uint16),
                ("mac_src_2", c_uint16),
                ("mac_src_3", c_uint16),
                ("mac_dst_1", c_uint16),
                ("mac_dst_2", c_uint16),
                ("mac_dst_3", c_uint16),
                ("ethertype", c_uint16)]
    