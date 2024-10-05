import pyshark
from datetime import datetime
import time
import pprint


# ###################### variables
start_runtime = time.time()

cap = pyshark.FileCapture('tcp_udp.pcapng') 


cap.load_packets()  # Loads all packets into memory

# Now you can access the packets quickly
print(f"Total number of packets: {len(cap)}")
f_packet = cap[0]  # Access the first packet
l_packet = cap[-1]  # Access the last packet

#----------------------------------------------------------use for big caps
# packet_count = sum(1 for packet in cap)
# print(f"Total number of packets: {packet_count}")


# cap.close() 
# cap = pyshark.FileCapture('xlarge_cap.pcapng')


# f_packet = cap[0] 
# for l_packet in cap:
#     pass 
#----------------------------------------------------------
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

print(f"Capture duration: {duration}")
print(f"Duration in seconds: {seconds}")




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


master = {}

def gather(master):
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
                src_ip = p.ip.src
                dst_ip = p.ip.dst
                src_port = p.tcp.srcport
                dst_port = p.tcp.dstport
                pkey = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                if pkey not in master[chunk_index]:
                    if int(p.tcp.flags, 16) & 0x02 | int(p.tcp.flags, 16) & 0x10 != 0:
                        master[chunk_index][pkey] = {'tcp_src_ip': '', 'tcp_src_mac': '', 'tcp_dst_ip': '', 'tcp_dst_mac': '', 'syn': 0, 'ack': 0, 'syn-ack': 0, 'tcp_dst_port': 0, 'tcp_src_port': 0}
                if int(p.tcp.flags, 16) & 0x02: 
                    master[chunk_index][pkey]['syn'] +=1
                    master[chunk_index][pkey]['tcp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['tcp_dst_port'] = p.tcp.dstport
                    master[chunk_index][pkey]['tcp_src_port'] = p.tcp.srcport
                    master[chunk_index][pkey]['tcp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['tcp_dst_mac'] = p.eth.dst
                    master[chunk_index][pkey]['tcp_src_ip'] = p.ip.src
                elif int(p.tcp.flags, 16) & 0x10: 
                    master[chunk_index][pkey]['ack'] +=1  
                    master[chunk_index][pkey]['tcp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['tcp_dst_port'] = p.tcp.dstport
                    master[chunk_index][pkey]['tcp_src_port'] = p.tcp.srcport
                    master[chunk_index][pkey]['tcp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['tcp_dst_mac'] = p.eth.dst
                    master[chunk_index][pkey]['tcp_src_ip'] = p.ip.src
            if 'UDP' in p:
                packet_time = p.sniff_time
                chunk_index = get_time_chunk(start_time, packet_time)
                src_ip = p.ip.src
                dst_ip = p.ip.dst
                src_port = p.udp.srcport
                dst_port = p.udp.dstport
                pkey = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                if pkey not in master[chunk_index]:
                    master[chunk_index][pkey] = {'udp_src_ip': '', 'src_mac': '', 'udp_dst_ip': '', 'dst_mac': '', 'udp': 0, 'udp_dst_port': '', 'udp_src_port': ''}
                    master[chunk_index][pkey]['udp'] +=1
                    master[chunk_index][pkey]['udp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['udp_dst_port'] = p.udp.dstport
                    master[chunk_index][pkey]['udp_src_port'] = p.udp.srcport
                    master[chunk_index][pkey]['src_mac'] = p.eth.src
                    master[chunk_index][pkey]['dst_mac'] = p.eth.dst
                    master[chunk_index][pkey]['udp_src_ip'] = p.ip.src
                else:
                    master[chunk_index][pkey]['udp_src_ip'] = p.ip.src 
                    master[chunk_index][pkey]['udp'] +=1
                    master[chunk_index][pkey]['udp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['udp_dst_port'] = p.udp.dstport  
                    master[chunk_index][pkey]['udp_src_port'] = p.udp.srcport
                    master[chunk_index][pkey]['src_mac'] = p.eth.src
                    master[chunk_index][pkey]['dst_mac'] = p.eth.dst


    flag_stat(cap, start_time, master)
    return master  
master = gather(master)
def print_master_dict(master):
    for chunk, connections in master.items():
        print(f"Time Chunk: {chunk}")
        for pkey, details in connections.items():
            print(f"  {pkey}:")
            for key, value in details.items():
                print(f"    {key}: {value}")
        print()  # Add an empty line for better readability between chunks

# Print the master dictionary in a readable format
print_master_dict(master)
# trigger_list = {}             

# def triggers(master, trigger_list):
#     for chunk, ips in master.items():
#         trigger_list[chunk] = {}
#         for ip, flags in ips.items():
#             for flag, count in flags.items():
#                 if flag == 'syn':
#                     if count > 1:
#                         trigger_list[chunk] = {'syn': count, 'ip': ip} 
                
#     if trigger_list:
#         print('## POTENTIAL BRUTE FORCE ##\n')
#         for chunk, items in trigger_list.items():
#             if items:
#             # print(f'{items['ip']} sent {items['syn']} syn packets in {chunk} time chunk')
#                 bar = ''
#                 for i in range(items['syn']):
#                     bar += '='
#                 bar += ']'
#                 if len(chunk) == 2:
#                     print(f'{chunk}   | {bar} {items['syn']} SYN packets from {items['ip']}')
#                 elif len(chunk) == 3:
#                     print(f'{chunk}  | {bar} {items['syn']} SYN packets from {items['ip']}')
#                 elif len(chunk) == 4:
#                     print(f'{chunk} | {bar} {items['syn']} SYN packets from {items['ip']}')
#             else:
#                 if len(chunk) == 2:
#                     print(f'{chunk}   |')
#                 elif len(chunk) == 3:
#                     print(f'{chunk}  |')
#                 elif len(chunk) == 4:
#                     print(f'{chunk} |')
#     else:
#             print("No potential brute force detected.")

# udp_list = {}

# def traffic(master, udp_list):
#     for chunk, ips in master.items():
#         udp_list[chunk] = {}
#         for ip, flags in ips.items():
#             for flag, count in flags.items():
#                 if flag == 'udp':
#                     if count > 1:
#                         udp_list[chunk] = {'udp': count, 'ip': ip, 'udp_dst_ip': flags['udp_dst_ip'], 'udp_dst_port': flags['udp_dst_port'], 'udp_src_port': flags['udp_src_port']} 
#     if udp_list:
#         print('## UDP Connections ##\n')
#         for chunk, items in udp_list.items():
#             if items:
#             # print(f'{items['ip']} sent {items['syn']} syn packets in {chunk} time chunk')
#                 bar = ''
#                 for i in range(items['udp']):
#                     bar += '='
#                 bar += ']'
#                 if len(chunk) == 2:
#                     print(f'{chunk}   | {bar} {items['udp']} UDP packets from {items['ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
#                 elif len(chunk) == 3:
#                     print(f'{chunk}  | {bar} {items['udp']} UDP packets from {items['ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
#                 elif len(chunk) == 4:
#                     print(f'{chunk} | {bar} {items['udp']} UDP packets from {items['ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
#             else:
#                 if len(chunk) == 2:
#                     print(f'{chunk}   |')
#                 elif len(chunk) == 3:
#                     print(f'{chunk}  |')
#                 elif len(chunk) == 4:
#                     print(f'{chunk} |')
#     else:
#             print("No UDP connections detected.")



# master = gather(master)

# ###################### control

# cap_info(cap)
# # high_syn(cap)
# triggers(master, trigger_list)
# print(traffic(master, udp_list))



# end_runtime = time.time()
# runtime = end_runtime - start_runtime
# print(f"Total program runtime: {runtime:.4f} seconds")




################### utility

# Print the layers in the packet
# print(f"Layers: {[layer.layer_name for layer in packet.layers]}")

# # Print all fields in each layer
# for layer in packet.layers:
#     print(f"Layer: {layer.layer_name}")
#     print(dir(layer))
# print(cap[2].sniff_time)










//im getting duplicates in the master dict, 