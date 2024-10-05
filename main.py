import pyshark
from datetime import datetime
import time
import pprint


# ###################### variables
start_runtime = time.time()

cap = pyshark.FileCapture('nmap_cap.pcapng') 


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
user_ips = []
user_macs = []
user_uagents = []

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

def user_info(user_ips, user_macs, user_uagents):
    if user_ips:
        print('\nExpected IP\'(s): {user_ips}')
    else:
        print('\nNo expected IP\'s defined')
    if user_macs:
        print('Expected MAC address\'(es): {user_macs}')
    else:
        print('No expected MAC\'s defined')
    if user_uagents:
        print('Expected user agents\'(s): {user_uagents}\n')
    else:
        print('No expected user agents\'s defined\n')






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
global_chunk_index = None
def gather(master):
    global global_chunk_index
    def get_time_chunk(start_time, packet_time):
        time_difference = packet_time - start_time
        chunk_index = int(time_difference.total_seconds() // 1) * 1
        global_chunk_index = chunk_index
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
                pkey = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                if pkey not in master[chunk_index]:
                    if int(p.tcp.flags, 16) & 0x02 | int(p.tcp.flags, 16) & 0x10 != 0:
                        master[chunk_index][pkey] = {
                            'tcp_src_ip': '', 'tcp_src_mac': '', 'tcp_dst_ip': '', 'tcp_dst_mac': '', 
                            'syn': 0, 'ack': 0, 'syn-ack': 0, 'tcp_dst_port': 0, 'tcp_src_port': 0, 
                            'user_agent': ''  # Add user_agent field
                        }
                if int(p.tcp.flags, 16) & 0x02: 
                    master[chunk_index][pkey]['syn'] += 1
                    master[chunk_index][pkey]['tcp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['tcp_dst_port'] = p.tcp.dstport
                    master[chunk_index][pkey]['tcp_src_port'] = p.tcp.srcport
                    master[chunk_index][pkey]['tcp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['tcp_dst_mac'] = p.eth.dst
                    master[chunk_index][pkey]['tcp_src_ip'] = p.ip.src
                elif int(p.tcp.flags, 16) & 0x10: 
                    master[chunk_index][pkey]['ack'] += 1  
                    master[chunk_index][pkey]['tcp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['tcp_dst_port'] = p.tcp.dstport
                    master[chunk_index][pkey]['tcp_src_port'] = p.tcp.srcport
                    master[chunk_index][pkey]['tcp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['tcp_dst_mac'] = p.eth.dst
                    master[chunk_index][pkey]['tcp_src_ip'] = p.ip.src
                if 'HTTP' in p:
                    try:
                        user_agent = p.http.user_agent
                        master[chunk_index][pkey]['user_agent'] = user_agent
                    except AttributeError:
                        pass
            elif 'IP' in p and any(proto in p for proto in ['UDP', 'RTP', 'RTSP', 'QUIC']):
                packet_time = p.sniff_time
                chunk_index = get_time_chunk(start_time, packet_time)
                src_ip = p.ip.src
                dst_ip = p.ip.dst
                src_port = p.udp.srcport
                dst_port = p.udp.dstport
                pkey = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                if pkey not in master[chunk_index]:
                    master[chunk_index][pkey] = {
                        'udp_src_ip': '', 'udp_src_mac': '', 'udp_dst_ip': '', 'udp_dst_mac': '', 
                        'udp': 0, 'udp_dst_port': '', 'udp_src_port': ''
                    }
                    master[chunk_index][pkey]['udp'] += 1
                    master[chunk_index][pkey]['udp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['udp_dst_port'] = p.udp.dstport
                    master[chunk_index][pkey]['udp_src_port'] = p.udp.srcport
                    master[chunk_index][pkey]['udp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['udp_dst_mac'] = p.eth.dst
                else:
                    master[chunk_index][pkey]['udp_src_ip'] = p.ip.src 
                    master[chunk_index][pkey]['udp'] += 1
                    master[chunk_index][pkey]['udp_dst_ip'] = p.ip.dst
                    master[chunk_index][pkey]['udp_dst_port'] = p.udp.dstport  
                    master[chunk_index][pkey]['udp_src_port'] = p.udp.srcport
                    master[chunk_index][pkey]['udp_src_mac'] = p.eth.src
                    master[chunk_index][pkey]['udp_dst_mac'] = p.eth.dst
    flag_stat(cap, start_time, master)
    return master 


trigger_list = {}             

def detect_nmap_scan(master, port_threshold=10):  # The threshold can be adjusted
    potential_scans = {}
    
    print("## Detecting Potential Nmap Scans ##")
    
    for chunk, connections in master.items():
        scan_candidates = {}  # Store how many unique ports each src_ip or src_mac has targeted
        
        for pkey, items in connections.items():
            src_ip = items.get('tcp_src_ip', '')
            src_mac = items.get('tcp_src_mac', '')
            dst_ip = items.get('tcp_dst_ip', '')
            dst_port = items.get('tcp_dst_port', '')

            if not src_ip and not src_mac:
                continue

            # Track by src_ip or src_mac
            identifier = src_ip if src_ip else src_mac

            # Initialize dictionary for this identifier if it doesn't exist
            if identifier not in scan_candidates:
                scan_candidates[identifier] = set()  # Use a set to store unique destination ports

            # Add the destination port to the set for the src_ip/src_mac
            if dst_port:
                scan_candidates[identifier].add(dst_port)

        # Check if any identifier (src_ip or src_mac) has sent to too many different ports
        for identifier, target_ports in scan_candidates.items():
            if len(target_ports) > port_threshold:  # If more than 'port_threshold' unique ports were hit
                if identifier not in potential_scans:
                    potential_scans[identifier] = []
                potential_scans[identifier].append({
                    'chunk': chunk,
                    'target_ips': len(set([target[0] for target in target_ports])),  # Get unique target IPs
                    'port_count': len(target_ports)  # Count of unique ports attempted
                })

    # Output the results
    if potential_scans:
        for identifier, scans in potential_scans.items():
            print(f"\nPotential Nmap scan detected for {identifier}:")
            for scan in scans:
                print(f"  - {scan['port_count']} unique ports to {scan['target_ips']} target IPs in chunk {scan['chunk']}")
    else:
        print("No potential Nmap scans detected.")



def bf_triggers(master):
    check = 0
    print('## POTENTIAL BRUTE FORCE ##\n')
    for chunk, connections in master.items():
        time_in_seconds = int(chunk.replace('s', ''))
        for pkey, items in connections.items():
            if 'TCP' in pkey:
                if items['syn'] / (time_in_seconds + 1) > 50:   # this can be changed for sensitivity, should link to 
                    check = 1                                   # earlier time check
                    bar = ''
                    for i in range(items['syn']):
                        bar += '='
                    bar += ']'
                    if len(chunk) == 2:
                        print(f'{chunk}   | {bar} {items['syn']} SYN packets from {items['tcp_src_ip']} port {items['tcp_src_port']}  ->  {items['tcp_dst_ip']} port {items['tcp_dst_port']}')
                    elif len(chunk) == 3:
                        print(f'{chunk}  | {bar} {items['syn']} SYN packets from {items['tcp_src_ip']} port {items['tcp_src_port']}  ->  {items['tcp_dst_ip']} port {items['tcp_dst_port']}')
                    elif len(chunk) == 4:
                        print(f'{chunk} | {bar} {items['syn']} SYN packets from {items['tcp_src_ip']} port {items['tcp_src_port']}  ->  {items['tcp_dst_ip']} port {items['tcp_dst_port']}')
    if check == 1:
        print('done')
    else:
        print("No potential brute force detected.")

def bf_triggers_mac(master):
    check = 0
    print('## POTENTIAL BRUTE FORCE ##\n')
    for chunk, connections in master.items():
        time_in_seconds = int(chunk.replace('s', ''))
        for pkey, items in connections.items():
            if 'TCP' in pkey:
                if items['syn'] / (time_in_seconds + 1) > 50:   # this can be changed for sensitivity, should link to 
                    check = 1                                   # earlier time check
                    bar = ''
                    for i in range(items['syn']):
                        bar += '='
                    bar += ']'
                    if len(chunk) == 2:
                        print(f'{chunk}   | {bar} {items['syn']} SYN packets from {items['tcp_src_mac']} port {items['tcp_src_port']}  ->  {items['tcp_dst_mac']} port {items['tcp_dst_port']}')
                    elif len(chunk) == 3:
                        print(f'{chunk}  | {bar} {items['syn']} SYN packets from {items['tcp_src_mac']} port {items['tcp_src_port']}  ->  {items['tcp_dst_mac']} port {items['tcp_dst_port']}')
                    elif len(chunk) == 4:
                        print(f'{chunk} | {bar} {items['syn']} SYN packets from {items['tcp_src_mac']} port {items['tcp_src_port']}  ->  {items['tcp_dst_mac']} port {items['tcp_dst_port']}')
    if check == 1:
        print('done')
    else:
        print("No potential brute force detected.")


def udp_traffic(master):
    check = 0
    print('## UDP Connections by IP ##\n')
    for chunk, connections in master.items():
        for pkey, items in connections.items():
            if 'UDP' in pkey:
                check = 1
                bar = ''
                udp_count = items['udp']
                if udp_count <= 60:
                    bar = '=' * udp_count  # Add the exact number of '='
                    bar += ']'  # Close the bar
                else:
                    bar = '=' * 60  # Limit to 30 '=' characters
                    bar += '>>'
                if len(chunk) == 2:
                    print(f'{chunk}   | {bar} {items['udp']} UDP packets from {items['udp_src_ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
                elif len(chunk) == 3:
                    print(f'{chunk}  | {bar} {items['udp']} UDP packets from {items['udp_src_ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
                elif len(chunk) == 4:
                    print(f'{chunk} | {bar} {items['udp']} UDP packets from {items['udp_src_ip']} port {items['udp_src_port']}  ->  {items['udp_dst_ip']} port {items['udp_dst_port']}')
    if check == 1:
        print('done')
    else:
        print("\nNo UDP connections detected.")

def mac_udp_traffic(master):
    check = 0
    print('## UDP Connections by MAC address ##\n')
    for chunk, connections in master.items():
        for pkey, items in connections.items():
            if 'UDP' in pkey:
                check = 1
                bar = ''
                udp_count = items['udp']
                if udp_count <= 60:
                    bar = '=' * udp_count  # Add the exact number of '='
                    bar += ']'  # Close the bar
                else:
                    bar = '=' * 60  # Limit to 30 '=' characters
                    bar += '>>'
                if len(chunk) == 2:
                    print(f'{chunk}   | {bar} {items['udp']} UDP packets from {items['udp_src_mac']} port {items['udp_src_port']}  ->  {items['udp_dst_mac']} port {items['udp_dst_port']}')
                elif len(chunk) == 3:
                    print(f'{chunk}  | {bar} {items['udp']} UDP packets from {items['udp_src_mac']} port {items['udp_src_port']}  ->  {items['udp_dst_mac']} port {items['udp_dst_port']}')
                elif len(chunk) == 4:
                    print(f'{chunk} | {bar} {items['udp']} UDP packets from {items['udp_src_mac']} port {items['udp_src_port']}  ->  {items['udp_dst_mac']} port {items['udp_dst_port']}')
    if check == 1:
        print('done')
    else:
        print("\nNo UDP connections detected.")
master = gather(master)


# ###################### control

cap_info(cap)
# high_syn(cap)
user_info(user_ips, user_macs, user_uagents)


# print('********** Stats based on IP address **********')
# bf_triggers(master, trigger_list)
# print(udp_traffic(master, udp_list))
# print('********** Stats based on MAC address **********')
# print(bf_triggers_mac(master, trigger_list))
# print(mac_udp_traffic(master, udp_list))
# print('********** Stats based on User Agent **********')



def full(master):
    gather(master)
    print('********** Stats based on IP address **********')
    udp_traffic(master)
    bf_triggers(master)
    print('********** Stats based on MAC address **********')
    mac_udp_traffic(master)
    bf_triggers_mac(master)
    detect_nmap_scan(master, port_threshold=10)
    

def ip_stats(master):
    print('********** Stats based on IP address **********')
    gather(master)
    udp_traffic(master)
    bf_triggers(master)

def mac_stats(master):
    print('********** Stats based on MAC address **********')
    gather(master)
    mac_udp_traffic(master)
    bf_triggers_mac(master)

    

def alerts():
    detect_nmap_scan(master, port_threshold=10)

def user_agent_stats():
    print('********** Stats based on User Agent **********')
    pass
mac_stats(master)


end_runtime = time.time()
runtime = end_runtime - start_runtime
print(f"Total program runtime: {runtime:.4f} seconds")



################### utility

# Print the layers in the packet
# print(f"Layers: {[layer.layer_name for layer in packet.layers]}")

# # Print all fields in each layer
# for layer in packet.layers:
#     print(f"Layer: {layer.layer_name}")
#     print(dir(layer))
# print(cap[2].sniff_time)



