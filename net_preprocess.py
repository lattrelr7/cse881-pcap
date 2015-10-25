#!python3
import argparse
import ctypes
from ip_structs import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", type=str, help="Wireshark capture in tcpdump format.")
    args = parser.parse_args()
    
    # Import the pcap dll
    print("importing pcap...")
    try:
        wpcap = ctypes.WinDLL("wpcap")
    except Exception as e:
        print("Failed to load dll: ", e)
    print("import OK")
    
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
            process_packet(pkthdr_ptr.contents, pktdata_ptr)
            status = wpcap.pcap_next_ex(pcap_handle, ctypes.byref(pkthdr_ptr), ctypes.byref(pktdata_ptr))
    else:
        print("Failed to open file: ", err_buf.value.decode())
    
def process_packet(pktheader, pktdata):
    timestamp = pktheader.ts.tv_sec + (pktheader.ts.tv_usec / 1000000)
    pktdata = bytearray(pktdata[:pktheader.len])
    #print(timestamp, pktdata)

    # Assume first 14 bytes are frame header
    ether_type = process_frame(pktdata)
    offset = FRAME_HDR_LEN
    if(ether_type == ET_ARP): 
        print("ARP!")
        
    elif(ether_type == ET_IPv4): 
        ip_type = process_ipv4(pktdata, offset)
        offset += IPV4_HDR_LEN
        if(ip_type == IPT_UDP):
            process_udp(pktdata, offset)
            offset += UDP_HDR_LEN
            
    elif(ether_type == ET_IPv6): 
        ip_type = process_ipv6(pktdata, offset)
        offset += IPV6_HDR_LEN
        if(ip_type == IPT_UDP):
            process_udp(pktdata, offset)
            offset += UDP_HDR_LEN
        
def process_frame(pktdata):
    frame_header = eth_frame_header_t.from_buffer(pktdata[:FRAME_HDR_LEN])
    #print("mac src", hex(frame_header.mac_src_1), hex(frame_header.mac_src_2), hex(frame_header.mac_src_3))
    #print("mac dst", hex(frame_header.mac_dst_1), hex(frame_header.mac_dst_2), hex(frame_header.mac_dst_3))
    #print("ethertype", hex(frame_header.ethertype))
    return frame_header.ethertype

def process_ipv4(pktdata, offset):
    print("IPv4!") 
    ip_header = ipv4_header_t.from_buffer(pktdata[offset:offset+IPV4_HDR_LEN])
    #print("ip src", hex(ip_header.src_ip))
    #print("ip dst", hex(ip_header.dst_ip)) 
    #TODO Verify it is version 4 and is only size 20
    #TODO handle fragments - don't need the data, just need to find final size.
    return ip_header.protocol

def process_ipv6(pktdata, offset):
    print("IPv6!") 
    ip_header = ipv6_header_t.from_buffer(pktdata[offset:offset+IPV6_HDR_LEN])
    return ip_header.next_header

def process_arp(pktdata, offset):
    type = 0
    return type

def process_icmp(pktdata, offset):
    type = 0
    return type

def process_udp(pktdata, offset):
    print("UDP!") 
    udp_header = udp_header_t.from_buffer(pktdata[offset:offset+UDP_HDR_LEN])
    print("src port", udp_header.src_port)
    print("dst port", udp_header.dst_port) 

def process_tcp(pktdata, offset):
    type = 0
    return type
    
if __name__ == "__main__": main()