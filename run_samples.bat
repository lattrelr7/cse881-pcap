py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\upload_to_cloud1.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\upload_to_cloud2.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\unreal_tournament.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\video_stream.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\background_noise.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\background_noise2.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\background_noise3.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\background_noise4.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\background_and_music.pcap 10.99.99.203 -label NORMAL
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\music_stream.pcap 10.99.99.203 -label NORMAL

py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-udp.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-udp2.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-o-v-1-decoy.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-o-v.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-ip.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap-ip2.pcap 10.88.88.88 -label PROBE
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\nmap_tcp_syn.pcap 10.88.88.88 -label PROBE

py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\hping_udp_flood_rand_port.pcap 10.88.88.88 -label DOS
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\hping_syn_rand_port.pcap 10.88.88.88 -label DOS
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\hping_syn_rand_port3.pcap 10.88.88.88 -label DOS
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\hping_syn_p21.pcap 10.88.88.88 -label DOS
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\hping_syn_p21-2.pcap 10.88.88.88 -label DOS

py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\inviteflood1.pcap 10.88.88.88 -label DOS
py net_preprocess.py C:\Users\ryan\OneDrive\MSU\CSE881\project\samples\inviteflood2.pcap 10.88.88.88 -label DOS

copy samples.db samples_raw.db
py process_db.py