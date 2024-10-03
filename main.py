import pyshark

print('go')

cap = pyshark.FileCapture('small_cap.pcapng')

# def get_ip():
#     for p in cap:
#         print(p.ip.source)

for packet in cap:
    if 'IP' in packet:
        print(f"Source IP: {packet.ip.src}")
        print(f"Destination IP: {packet.ip.dst}")

