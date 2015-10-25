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
    frame_header = eth_frame_header_t.from_buffer(pktdata[:14])
    print("mac src", hex(frame_header.mac_src_1), hex(frame_header.mac_src_2), hex(frame_header.mac_src_3))
    print("mac dst", hex(frame_header.mac_dst_1), hex(frame_header.mac_dst_2), hex(frame_header.mac_dst_3))
    print("ethertype", hex(frame_header.ethertype))
    
    if(frame_header.ethertype == ET_ARP): 
        print("ARP!")
        
    elif(frame_header.ethertype == ET_IPv4): 
        print("IPv4!") 
        #TODO Verify it is version 4 and is only size 20
        #TODO handle fragments - don't need the data, just need to find final size.
        #ip_header = ipv4_header_t.from_buffer(pktdata[14:34])
        #print("ip src")
        #print("ip dst")        
    
    elif(frame_header.ethertype == ET_IPv6): 
        print("IPv6!")

if __name__ == "__main__": main()