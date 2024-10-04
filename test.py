import pyshark
from datetime import datetime
from main import seconds

cap = pyshark.FileCapture('medium_cap.pcapng')

# print(cap[0].pretty_print_layer_fields)

# for packet in cap:
#     print(f'Packet Number: {packet.number}')
#     for layer in packet.layers:
#         print(f'Layer: {layer.layer_name}')
#         print(layer)  # This prints all the fields and values for the layer
#     print('--- End of Packet ---\n')

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
