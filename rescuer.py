from scapy.all import Dot11, Raw, sniff
import sys
import threading

SURVIVOR_MAGIC = b"RESCUEME" 

# You MUST use an interface in MONITOR MODE.
# "wlan0" will not work. It's usually "wlan0mon" or "mon0".
INTERFACE = "wlan0" 


def is_our_beacon(pkt):
    """
    This is the Scapy function for sniffing.
    It returns True only for our survivor's packets.
    """


    # 1. Check if it's a Dot11 frame first.
    #    If not, we can't check pkt.type, so we return False immediately.
    if not pkt.haslayer(Dot11):
        return False

        
    # 2. Now that we know it has Dot11, we check if it's our Data frame.
    #    type=2 (Data), subtype=0 (Standard Data)
    if not (pkt.type == 2 and pkt.subtype == 0):
        return False

    print("found some packet")

    # 3. If it's a Data frame, check if it has our magic payload.
    try:
        # We must also check haslayer(Raw) before accessing pkt[Raw]
        if pkt.haslayer(Raw) and pkt[Raw].load.startswith(SURVIVOR_MAGIC):
            # This is our packet!
            return True
    except Exception as e:
        # Catch any errors from malformed packets
        print(f"Error checking payload: {e}", file=sys.stderr)
        return False

    # Failed the payload check
    return False


# print(f"[*] Sniffing for beacons on {INTERFACE}...")
# try:
#     # We add a 'prn' function to *do* something when a packet is found
#     sniff(iface=INTERFACE, lfilter=is_our_beacon, prn=lambda pkt: print(f"FOUND: {pkt.summary()}"))
# except OSError as e:
#     print(f"\n[!] ERROR: {e}")
#     print(f"[!] Is '{INTERFACE}' in MONITOR mode and correct?")
# except KeyboardInterrupt:
#     print("\n[*] Sniffing stopped.")



class Rescuer:
    def __init__(self,interface):
        self.interface = interface


        # they contain the status of each survivors sniffed {mac_address: "db"}
        self.survivors = {}
        self.lock = threading.Lock()
        self.running = True


    def _is_our_beacon(pkt):
        """
        This is the Scapy function for sniffing.
        It returns True only for our survivor's packets.
        """


        # 1. Check if it's a Dot11 frame first.
        #    If not, we can't check pkt.type, so we return False immediately.
        if not pkt.haslayer(Dot11):
            return False

            
        # 2. Now that we know it has Dot11, we check if it's our Data frame.
        #    type=2 (Data), subtype=0 (Standard Data)
        if not (pkt.type == 2 and pkt.subtype == 0):
            return False

        print("found some packet")

        # 3. If it's a Data frame, check if it has our magic payload.
        try:
            # We must also check haslayer(Raw) before accessing pkt[Raw]
            if pkt.haslayer(Raw) and pkt[Raw].load.startswith(SURVIVOR_MAGIC):
                # This is our packet!
                return True
        except Exception as e:
            # Catch any errors from malformed packets
            print(f"Error checking payload: {e}", file=sys.stderr)
            return False

        # Failed the payload check
        return False

    def _sniffer_loop(self):
        """
        This is the target function for our sniffer thread
        """

        try: 
            sniff(
                iface=self.interface,
                lfilter=self._is_our_beacon,
                prn=self._packet_handler,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            print("[-] sniffer thread stopping")

    def run(self):
        """
        Starts the application
        """
        #1. Starts the sniffer thread in the background
        sniffer_thread = threading.Thread(target=self._sniffer_loop, daemon=True)
        sniffer_thread.start()

    def stop(self):
        self.running = False
    

if __name__ == "__main__":
    app = Rescuer(INTERFACE)
    try:
        app.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down (Ctrl +c)...")
        app.stop()