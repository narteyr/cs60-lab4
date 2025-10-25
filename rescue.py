from scapy.all import *
import struct
import threading
import time
import curses

survivors = {}
survivors_lock = threading.Lock()

APP_RUNNING = True

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    if not pkt.haslayer(Raw):
        return

    packet_bytes = bytes(pkt)
    if not b'RESCUEME' in packet_bytes:
        return
    
    pos = packet_bytes.find(b"RESCUEME")
        
    # Used Claude to figure out how to extract RSSI
    if pos + 12 <= len(packet_bytes):
        # First 8 bytes should be "RESCUEME", next 4 should be id
        survivor_id = struct.unpack("!I", packet_bytes[pos+8:pos+12])[0]

        # Get RSSI
        rssi = None
        if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal'):
            rssi = pkt[RadioTap].dBm_AntSignal

        mac = None
        if hasattr(pkt[Dot11], "addr2"):
            mac = pkt[Dot11].addr2
        last_seen = time.time()

        if mac != None:
            with survivors_lock:
                survivors[mac] = {
                    "id": survivor_id,
                    "rssi": rssi,
                    "last_seen": last_seen
                }

def ncurses_main(stdscr):
    """
    This is the main function for our ncurses GUI.
    It runs in the MAIN THREAD.
    """
    global APP_RUNNING
    stdscr.nodelay(True)
    curses.curs_set(0)

    #set up color pairs
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)

    while APP_RUNNING:
        try:
            key = stdscr.getch()
            if key == ord('q'):
                APP_RUNNING = False
                break
        except:
            pass

        survivor_copy = {}
        with survivors_lock:
            survivor_copy = survivors.copy()
        
        stdscr.clear()
        current_time = time.time()


        # Draw the header
        stdscr.addstr(0,0, "RESCUER CONSOLE (Press 'q' to quit )")
        stdscr.addstr(2,0, "MAC Address\t\tRSSI\tLast Seen (s)\t Survivor ID")
        stdscr.addstr(3,0, "-"*70)

        row = 4

        #sort survivors by RSSI (strongest first)
        sorted_survivors = sorted(survivor_copy.items(),
                                key=lambda item: int(item[1]['rssi']) if item[1]['rssi'] is not None else -999,
                                reverse=True
        )


        for mac, info in sorted_survivors:
            time_ago = current_time - info['last_seen']
            rssi_val = info['rssi']
            id_val = info['id']


            if row < curses.LINES - 1:
                line = f"{mac}\t{rssi_val} dBm\t{time_ago:.1f} s\t\t{id_val}"
                stdscr.addstr(row, 0, line)
                row += 1

        # refresh display
        stdscr.refresh()
        time.sleep(0.1)


def sniffer_thread(interface):
    print(f"Sniffer started on {interface}")
    sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: not APP_RUNNING)

def main():
    interface = "wlan0"
    sniffer = threading.Thread(target=sniffer_thread, args=(interface,), daemon=True)
    sniffer.start()

    try:
        curses.wrapper(ncurses_main)
    except KeyboardInterrupt:
        print("[-] Stopped by Ctrl+C")
    finally:
        APP_RUNNING = False

    sniffer.join()
    print("Sniffer threaded exited.")

if __name__ == "__main__":
    main()