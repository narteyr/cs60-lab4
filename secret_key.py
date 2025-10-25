from scapy.all import *
import time 
import uuid 

READY_FRAME = b"READY"
ACK_FRAME = b"ACK"

def send_frame(payload, interface="wlan0"):
    """ Helper function to send frames """
    mac = uuid.getnode()
    mac_bytes = mac.to_bytes(6, 'big')
    mac_string = ':'.join(f'{b:02x}' for b in mac_bytes)

    frame = (RadioTap() /
             Dot11(type=2,
                   subtype=0,
                   addr1="ff:ff:ff:ff:ff:ff",
                   addr2=mac_string,
                   addr3="ff:ff:ff:ff:ff:ff") /
             Raw(load=payload))

    sendp(frame, iface=interface, verbose=False)

def determine_role(interface="wlan0"):
    """ Listens for ready frames
        If received, this host is the initiator
        Otherwise, this host is the receiver
    """
    found_initiator = False
    def check_ready(pkt):
        nonlocal found_initiator
        packet_bytes = bytes(pkt)
        if READY_FRAME in packet_bytes:
            print("Detected Ready Frame from another device")
            found_initiator = True

    print("Listening for Ready Frames...")
    sniff(iface=interface, prn=check_ready, timeout=3, store=0) # Wait 3 seconds
    if found_initiator:
        print("This device is the responder")
        send_ack(interface)
        return "responder"
    else:
        print("This device is the initiator")
        return "initiator"

def send_ack(interface="wlan0"):
    """ Send ack frames to initiator """
    print("Sending ACK frames to initiator...")
    for i in range(5):
        send_frame(ACK_FRAME, interface)
        time.sleep(0.2)

def wait_for_responder(interface="wlan0", timeout=5):
    """ Listens for ACK frames from the responder """
    start_time = time.time()

    heard_responder = False
    def check_ack(pkt):
        nonlocal heard_responder
        packet_bytes = bytes(pkt)
        if ACK_FRAME in packet_bytes:
            print("Detected ACK frame from responder")
            heard_responder = True

    # send ready frames until timeout or we have a responder 
    while time.time() - start_time < timeout and not heard_responder:
        send_frame(READY_FRAME, interface)
        sniff(iface=iface, prn=check_ack, timeout=0.5, store=0)

    if heard_responder:
        print("Responder found")
        return True
    else:
        print("Could not find a responder")
        return False

def main():
    interface = "wlan0"

    print("Determining role...")
    role = determine_role(interface)

    if role == "initiator":
        print("ROLE: Initiator")
        if wait_for_responder(initiator):
            print("Responder has connected")
        else:
            print("No responder found")
    elif role == "responder":
        print("ROLE: Responder")

if __name__ = "__main__":
    main():
        

    
        
    


    





    
