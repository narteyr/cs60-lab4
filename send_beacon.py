from scapy.all import *
import struct
import uuid
import time

def send_beacon(interface="wlan0"):
    # extra bytes for identification
    magic = b"RESCUEME"
    # Add lower 32 bits of mac to payload to make frame even more unique 
    mac = uuid.getnode()
    mac_bytes = mac.to_bytes(6, 'big')
    mac_string = ':'.join(f'{b:02x}' for b in mac_bytes)
    survivor_id = mac & 0xFFFFFFFF
    id_bytes = struct.pack('!I', survivor_id)
    
    # create frame
    frame = RadioTap() / \
        Dot11(type=2,           
              subtype=0,            
              addr1="ff:ff:ff:ff:ff:ff",  
              addr2=mac_string, 
              addr3="ff:ff:ff:ff:ff:ff") / \
        Raw(load=magic + id_bytes)
    
    sendp(frame, iface=interface, verbose=False)
    print(f"Sent beacon from Survivor {survivor_id}")

# Survivor device continuously broadcasts
try:
    while True:
        send_beacon()
        time.sleep(2)
except KeyboardInterrupt:
    print("Stopped survivor beacon transmission.")   