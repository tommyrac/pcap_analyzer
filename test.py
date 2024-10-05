print('Note, this program mainly checks for common attack attempts and UDP traffic behavior. For the purposes of this tool, protocols such as UDP, RTP, RTSP, and QUIC have been categorized under \'UDP\' \n\nThis program allows expected mac and ip addresses to be specified, and will check for behavior outside of what is expected')

target_file = input("Provide path to pcap file (for demonstration, type nmap_cap.pcapng): ")
while True:
    option1 = input("Would you like to define expected behavior? (yes/no): ").lower()
    
    if option1 == 'yes' or option1 == 'no':
        break  # Exit the loop if the input is valid
    else:
        print("Please type 'yes' or 'no'.")
if option1 == 'yes':
    print('\nIf there is no value to set, simply hit Enter')
    exp_mac = input('Expected MAC address(es): ')
    exp_ip = input('Expected IP address(es): ')
    exp_ua = input('Expected user agent(s): ')
while True:
    option2 = input('what would you like to analyze: \n'
                    '1. All stats\n'
                    '2. Stats by IP address\n'
                    '3. Stats by MAC address\n'
                    '4. User Agent info\n'
                    '5. Alerts only\n')
    if option2.isdigit() and int(option2) in (range(1, 6)):
        break
    else:
        print('Enter number 1 - 5')

if option2 == 1:
    full(master)
if option2 == 2:
    ip_stats(master)
if option2 == 3:
    mac_stats(master)
if option2 == 4:
    user_agent_stats()
if option2 == 5:
    alerts()



