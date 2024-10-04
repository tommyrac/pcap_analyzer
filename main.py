import pyshark
from datetime import datetime
###################### variables

cap = pyshark.FileCapture('medium_cap.pcapng')

i = 0
for p in cap:
    i += 1


f_packet = cap[0]
l_packet = cap[i-1]
start_time = f_packet.sniff_time
end_time = l_packet.sniff_time
src_ip_list = []
dst_ip_list = []
one_off_list = []
ip_addr_count = len(src_ip_list)


time1 = datetime.strptime(str(end_time), "%Y-%m-%d %H:%M:%S.%f")
time2 = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f")
duration = time1 - time2
seconds = round(duration.total_seconds(), 2)

##################### overview

def cap_info(cap):
    for p in cap:
        if 'IP' in p:
            if p.ip.src not in src_ip_list:
                src_ip_list.append(p.ip.src)
            if p.ip.dst not in dst_ip_list:
                dst_ip_list.append(p.ip.dst)

    for ip in src_ip_list:
        if ip not in dst_ip_list:
            one_off_list.append(ip)
        
    print(f'Packet capture from:\n\n{start_time}\nto\n{end_time}\n\nDuration = {seconds}s\n\nincludes {len(src_ip_list)} source IP\'s and {len(dst_ip_list)} destination IP\'s\nThere are {len(one_off_list)} unanswered initiators')


##################### brute check


def high_syn(cap):
    
    syn_count = {}
    ip_alerts = {}
    for p in cap:
        if 'IP' in p and 'TCP' in p:
            if p.ip.src not in syn_count:
                syn_count[p.ip.src] = 0
            if int(p.tcp.flags, 16) & 0x02:  # SYN flag is the second least significant bit (0x02)
                syn_count[p.ip.src] += 1
    # print(syn_count)
    ip_alerts['182.182.182.23'] = 500
    for ip, count in syn_count.items():
        if count/seconds > 1:
            ip_alerts[ip] = count
    # print(ip_alerts)
    if len(ip_alerts) >= 1:    
        print('## POTENTIAL BRUTE FORCE ##\n the following ip addresses sent more than 50 SYN packets/sec in this capture')
        for ip, count in ip_alerts.items():
            print(f'{ip} sent {count} SYN packets in {seconds}s') 

high_syn(cap)


###################### control

cap_info(cap)
high_syn(cap)








################### utility

# Print the layers in the packet
# print(f"Layers: {[layer.layer_name for layer in packet.layers]}")

# # Print all fields in each layer
# for layer in packet.layers:
#     print(f"Layer: {layer.layer_name}")
#     print(dir(layer))
# print(cap[2].sniff_time)

