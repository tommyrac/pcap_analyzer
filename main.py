import pyshark
from datetime import datetime
import time
import pprint

print('\n\nNote, this program mainly checks for common attack attempts and UDP traffic behavior. For the purposes of this tool, protocols such as UDP, RTP, RTSP, and QUIC have been categorized under \'UDP\' \n\nThis program allows expected mac and ip addresses to be specified, and will check for behavior outside of what is expected\n\nThe capture may take up to a few seconds to analyze\n\n')


# ###################### variables
start_runtime = time.time()
target_file = input("Provide path to pcap file (for demonstration, type 'nmap_cap.pcapng'): \n\n")
print('Please wait while capture is analyzed...\n\n')
cap = pyshark.FileCapture(target_file) 


cap.load_packets() 


print(f"Total number of packets: {len(cap)}")
f_packet = cap[0] 
l_packet = cap[-1]  

#----------------------------------------------------------use for large caps
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


IOT_ip = []
IOT_mac = []
IOT_ua = []

def user_info(IOT_ip, IOT_mac, IOT_ua):
    if IOT_ip:
        print(f'\nExpected IP\'(s): {IOT_ip}')
    else:
        print('\nNo expected IP\'s defined')
    if IOT_mac:
        print(f'Expected MAC address\'(es): {IOT_mac}')
    else:
        print('No expected MAC\'s defined')
    if IOT_ua:
        print(f'Expected user agents\'(s): {IOT_ua}\n')
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
trigger_list = {}  
global_chunk_index = None
def gather(master):
    global global_chunk_index
    def get_time_chunk(start_time, packet_time):
        time_difference = packet_time - start_time
        chunk_index = int(time_difference.total_seconds() // 1) * 1
        global_chunk_index = chunk_index
        return f"{chunk_index}s"
    
    
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
                    if (int(p.tcp.flags, 16) & 0x02) or (int(p.tcp.flags, 16) & 0x10):
                        master[chunk_index][pkey] = {
                            'tcp_src_ip': src_ip, 'tcp_src_mac': p.eth.src, 'tcp_dst_ip': dst_ip, 'tcp_dst_mac': p.eth.dst, 
                            'syn': 0, 'ack': 0, 'syn-ack': 0, 'tcp_dst_port': dst_port, 'tcp_src_port': src_port, 'user_agent': ''
                        }
                        
                
                if int(p.tcp.flags, 16) & 0x02: 
                    master[chunk_index][pkey]['syn'] += 1
                if int(p.tcp.flags, 16) & 0x10: 
                    master[chunk_index][pkey]['ack'] += 1  

                
                if 'HTTP' in p:
                    try:
                        master[chunk_index][pkey]['user_agent'] = p.http.user_agent
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
                        'udp_src_ip': src_ip, 'udp_src_mac': p.eth.src, 'udp_dst_ip': dst_ip, 'udp_dst_mac': p.eth.dst,
                        'udp': 1, 'udp_dst_port': dst_port, 'udp_src_port': src_port, 'user_agent': ''
                    }
                else:
                    
                    master[chunk_index][pkey]['udp'] += 1

                
                if 'HTTP' in p:
                    try:
                        master[chunk_index][pkey]['user_agent'] = p.http.user_agent
                    except AttributeError:
                        pass  


    flag_stat(cap, start_time, master)
    return master             

def detect_nmap_scan(master, port_threshold=10):  
    potential_scans = {}
    
    print("## Detecting Potential Nmap Scans ##")
    
    for chunk, connections in master.items():
        scan_candidates = {}  
        
        for pkey, items in connections.items():
            src_ip = items.get('tcp_src_ip', '')
            src_mac = items.get('tcp_src_mac', '')
            dst_ip = items.get('tcp_dst_ip', '')
            dst_port = items.get('tcp_dst_port', '')

            if not src_ip and not src_mac:
                continue

            
            identifier = src_ip if src_ip else src_mac

            
            if identifier not in scan_candidates:
                scan_candidates[identifier] = set()  

            
            if dst_port:
                scan_candidates[identifier].add(dst_port)

        
        for identifier, target_ports in scan_candidates.items():
            if len(target_ports) > port_threshold:  
                if identifier not in potential_scans:
                    potential_scans[identifier] = []
                potential_scans[identifier].append({
                    'chunk': chunk,
                    'target_ips': len(set([target[0] for target in target_ports])),  
                    'port_count': len(target_ports)  
                })

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
                if items['syn'] / (time_in_seconds + 1) > 50:   
                    check = 1                                   
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
                if items['syn'] / (time_in_seconds + 1) > 50:   
                    check = 1                                   
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
                    bar = '=' * udp_count  
                    bar += ']'  
                else:
                    bar = '=' * 60  
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
                    bar = '=' * udp_count  
                    bar += ']'  
                else:
                    bar = '=' * 60  
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



def full(master):
    print('********** Stats based on IP address **********')
    udp_traffic(master)
    bf_triggers(master)
    print('********** Stats based on MAC address **********')
    mac_udp_traffic(master)
    bf_triggers_mac(master)
    detect_nmap_scan(master, port_threshold=10)
    
def ip_stats(master):
    print('********** Stats based on IP address **********')
    udp_traffic(master)
    bf_triggers(master)

def mac_stats(master):
    print("mac_stats called")
    print('********** Stats based on MAC address **********')
    mac_udp_traffic(master)
    bf_triggers_mac(master)

def alerts():
    detect_nmap_scan(master, port_threshold=10)

def user_agent_stats():
    user_agents = set()  
    print('********** User Agents found in capture **********\n')
    
    for chunk, connections in master.items():
        for pkey, data in connections.items():
            if 'user_agent' in data and data['user_agent']:
                user_agents.add(data['user_agent'])  

   
    if user_agents:
        for agent in user_agents:
            print(agent)
    else:
        print('No user agents found.')



def solenoid(master):
    global IOT_mac, IOT_ip, IOT_ua, target_file
    
    while True:
        option1 = input("\n\n********** Tool Options **********\nWould you like to define IOT device? (yes/no): ").lower()
        
        if option1 == 'yes' or option1 == 'no':
            break  
        else:
            print("Please type 'yes' or 'no'.")
    if option1 == 'yes':
        print('\nSorry! Not quite functional yet :-(')
        # IOT_mac = input('IOT MAC address(es): ')
        # IOT_ip = input('IOT IP address(es): ')
        # IOT_ua = input('IOT user agent(s): ')


    while True:
        option2 = input("\nWould you like to define expected behavior? (yes/no): ").lower()
        
        if option2 == 'yes' or option2 == 'no':
            break  
        else:
            print("Please type 'yes' or 'no'.")
    if option2 == 'yes':
        print('\nSorry! Not quite functional yet :-(')

        # exp_mac = input('Expected MAC address(es): ')
        # exp_ip = input('Expected IP address(es): ')
        # exp_ua = input('Expected user agent(s): ')
    while True:
        option3 = input('\nWhat would you like to analyze: \n'
                        '1. All stats\n'
                        '2. Stats by IP address\n'
                        '3. Stats by MAC address\n'
                        '4. User Agent info\n'
                        '5. Alerts only\n'
                        '6. Exit\n')
        
        
        if option3.isdigit() and int(option3) in (range(1, 7)):
            option3 = int(option3)  
        else:
            print('Enter a valid number between 1 - 6')
            continue  

        if option3 == 1:
            user_info(IOT_ip, IOT_mac, IOT_ua)
            full(master)
        elif option3 == 2:
            user_info(IOT_ip, IOT_mac, IOT_ua)
            ip_stats(master)
        elif option3 == 3:
            print('progress')
            user_info(IOT_ip, IOT_mac, IOT_ua)
            mac_stats(master)
        elif option3 == 4:
            user_info(IOT_ip, IOT_mac, IOT_ua)
            user_agent_stats()
        elif option3 == 5:
            user_info(IOT_ip, IOT_mac, IOT_ua)
            alerts()
        elif option3 == 6:
            print("Exiting the program.")
            break

cap_info(cap)
master = gather(master)
end_runtime = time.time()
runtime = end_runtime - start_runtime
print(f"Total time to analyze: {runtime:.4f} seconds")
solenoid(master)


