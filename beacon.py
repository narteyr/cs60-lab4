from scapy.all import *
import struct
import time

def send_beacon(survivor_id, interface="eth0"):
    # Build payload
    magic = b"RESCUEME"
    mac = uuid.getnode()
    id_bytes = struct.pack('!I', mac & 0xFFFFFFFF)

    
    # Create frame
    frame = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x88B5) / \
            Raw(load=magic + id_bytes)
    
    # Send it
    sendp(frame, iface=interface, verbose=False)
    
    print(f"Sent beacon from Survivor {survivor_id}")

# Survivor device continuously broadcasts
SURVIVOR_ID = 12345
while True:
    send_beacon(SURVIVOR_ID)
    time.sleep(2)  # Every 2 seconds