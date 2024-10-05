import pyshark
from datetime import datetime
import time


# ###################### variables
start_runtime = time.time()

cap = pyshark.FileCapture('tcp_udp.pcapng') 


cap.load_packets() 


# Now you can access the packets quickly
# print(f"Total number of packets: {len(cap)}")
f_packet = cap[0]  # Access the first packet
l_packet = cap[-1]  # Access the last packet
src_ip_list = []
dst_ip_list = []
one_off_list = []
ip_addr_count = len(src_ip_list)

start_time = f_packet.sniff_time
end_time = l_packet.sniff_time

time1 = datetime.strptime(str(end_time), "%Y-%m-%d %H:%M:%S.%f")
time2 = datetime.strptime(str(start_time), "%Y-%m-%d %H:%M:%S.%f")
duration = time1 - time2
seconds = round(duration.total_seconds(), 2)

def duration(seconds, duration):
    print(f"Capture duration: {duration}")
    print(f"Duration in seconds: {seconds}")

# # print(cap[0].pretty_print_layer_fields)

# for packet in cap:
#     print(f'Packet Number: {packet.number}')
#     for layer in packet.layers:
#         print(f'Layer: {layer.layer_name}')
#         print(layer)  # This prints all the fields and values for the layer
#     print('--- End of Packet ---\n')



# #------------------------------------------------------- original high_syn
# def high_syn(cap):
    
#     synack_count = {}
#     ip_alerts = {}
#     for p in cap:
#         if 'IP' in p and 'TCP' in p:
#             if p.ip.src not in synack_count:
#                 synack_count[p.ip.src] = [0, 0]
#             if int(p.tcp.flags, 16) & 0x02:  # SYN flag is the second least significant bit (0x02)
#                 synack_count[p.ip.src][0] += 1
#             if int(p.tcp.flags, 16) & 0x10:
#                 synack_count[p.ip.src][1] += 1

#     # print(synack_count)
#     # for ip, count in synack_count.items():
#     #     print(count[0]/seconds) 
#     ip_alerts['182.182.182.23'] = [500, 3]
#     for ip, count in synack_count.items():
#         if count[0]/seconds !=0:
#             ip_alerts[ip] = count
#     # print(ip_alerts)
#     if len(ip_alerts) >= 1:    
#         print('## POTENTIAL BRUTE FORCE ##\n the following ip addresses sent more than 50 SYN packets/sec in this capture')
#         for ip, count in ip_alerts.items():
#             print(f'{ip} sent {count[0]} SYN packets in {seconds}s') 
# #------------------------------------------------------- original high_syn



master = {}

def gather(master, cap):
    def get_time_chunk(start_time, packet_time):
        time_difference = packet_time - start_time
        chunk_index = int(time_difference.total_seconds() // 1) * 1
        return f"{chunk_index}s"

    # cap = pyshark.FileCapture('3minute_cap.pcapng')
    start_time = cap[0].sniff_time

    for packet in cap:
        packet_time = packet.sniff_time
        chunk_index = get_time_chunk(start_time, packet_time)
        
        if chunk_index not in master:
            master[chunk_index] = {}


    def flag_stat(cap, start_time, master):  
        for p in cap:
            if 'IP' in p and 'TCP' in p:
                packet_time = p.sniff_time
                chunk_index = get_time_chunk(start_time, packet_time)
                if p.ip.src not in master[chunk_index]:
                    if int(p.tcp.flags, 16) & 0x02 | int(p.tcp.flags, 16) & 0x10 != 0:
                        master[chunk_index][p.ip.src] = {'syn': 0, 'ack': 0, 'syn-ack': 0}
                if int(p.tcp.flags, 16) & 0x02: 
                    master[chunk_index][p.ip.src]['syn'] +=1
                if int(p.tcp.flags, 16) & 0x10: 
                    master[chunk_index][p.ip.src]['ack'] +=1  

    flag_stat(cap, start_time, master)
    return master
    
trigger_list = {}             

def triggers(master, trigger_list):
    for chunk, ips in master.items():
        trigger_list[chunk] = {}
        for ip, flags in ips.items():
            for flag, count in flags.items():
                if flag == 'syn':
                    if count > 1:
                        trigger_list[chunk] = {'syn': count, 'ip': ip} 
    if trigger_list:
        print('## POTENTIAL BRUTE FORCE ##\n')
        for chunk, items in trigger_list.items():
            if items:
            # print(f'{items['ip']} sent {items['syn']} syn packets in {chunk} time chunk')
                bar = ''
                for i in range(items['syn']):
                    bar += '='
                bar += ']'
                if len(chunk) == 2:
                    print(f'{chunk}   | {bar} {items['syn']} SYN packets from {items['ip']}')
                elif len(chunk) == 3:
                    print(f'{chunk}  | {bar} {items['syn']} SYN packets from {items['ip']}')
                elif len(chunk) == 4:
                    print(f'{chunk} | {bar} {items['syn']} SYN packets from {items['ip']}')
            else:
                if len(chunk) == 2:
                    print(f'{chunk}   |')
                elif len(chunk) == 3:
                    print(f'{chunk}  |')
                elif len(chunk) == 4:
                    print(f'{chunk} |')
    else:
            print("No potential brute force detected.")

master = gather(master, cap)

###################### control

# cap_info(cap)
# high_syn(cap)
triggers(master, trigger_list)



end_runtime = time.time()
runtime = end_runtime - start_runtime
print(f"Total program runtime: {runtime:.4f} seconds")
















def block():
    synack_count = {}
    ip_alerts = {}
    for p in cap:
        if 'IP' in p and 'TCP' in p:
            if p.ip.src not in synack_count:
                synack_count[p.ip.src] = [0, 0]
            if int(p.tcp.flags, 16) & 0x02:  # SYN flag is the second least significant bit (0x02)
                synack_count[p.ip.src][0] += 1
            if int(p.tcp.flags, 16) & 0x10:
                synack_count[p.ip.src][1] += 1

    # print(synack_count)
    # for ip, count in synack_count.items():
    #     print(count[0]/seconds) 
    ip_alerts['182.182.182.23'] = [500, 3]
    for ip, count in synack_count.items():
        if count[0]/seconds !=0:
            ip_alerts[ip] = count
    # print(ip_alerts)
    if len(ip_alerts) >= 1:    
        print('## POTENTIAL BRUTE FORCE ##\n the following ip addresses sent more than 50 SYN packets/sec in this capture')
        for ip, count in ip_alerts.items():
            print(f'{ip} sent {count[0]} SYN packets in {seconds}s') 







# duration(seconds, duration)
end_runtime = time.time()
runtime = end_runtime - start_runtime
print(f"Total program runtime: {runtime:.4f} seconds")