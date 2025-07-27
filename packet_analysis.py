import sys
import time
from collections import Counter, defaultdict
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, ARP
try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    class HTTPRequest: pass
from colorama import init, Fore, Style

init(autoreset=True)

# Themes
THEMES = {
    'default': {
        'TCP': Fore.CYAN, 'UDP': Fore.YELLOW, 'ICMP': Fore.MAGENTA, 'ARP': Fore.LIGHTWHITE_EX,
        'HTTP': Fore.GREEN, 'DNS': Fore.BLUE, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.WHITE, 'SRC': Fore.GREEN, 'DST': Fore.RED,
        'INFO': Fore.YELLOW, 'WARN': Fore.YELLOW, 'ERROR': Fore.RED + Style.BRIGHT,
        'TIME': Fore.BLUE
    },
    'dark': {
        'TCP': Fore.LIGHTCYAN_EX, 'UDP': Fore.LIGHTYELLOW_EX, 'ICMP': Fore.LIGHTMAGENTA_EX, 'ARP': Fore.LIGHTWHITE_EX,
        'HTTP': Fore.LIGHTGREEN_EX, 'DNS': Fore.CYAN, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.LIGHTWHITE_EX, 'SRC': Fore.LIGHTGREEN_EX, 'DST': Fore.LIGHTRED_EX,
        'INFO': Fore.LIGHTYELLOW_EX, 'WARN': Fore.LIGHTYELLOW_EX, 'ERROR': Fore.LIGHTRED_EX + Style.BRIGHT,
        'TIME': Fore.LIGHTBLUE_EX
    },
    'light': {
        'TCP': Fore.BLUE, 'UDP': Fore.YELLOW, 'ICMP': Fore.MAGENTA, 'ARP': Fore.LIGHTWHITE_EX,
        'HTTP': Fore.GREEN, 'DNS': Fore.CYAN, 'OTHER': Fore.LIGHTBLACK_EX,
        'HEADER': Fore.WHITE, 'SRC': Fore.GREEN, 'DST': Fore.RED,
        'INFO': Fore.YELLOW, 'WARN': Fore.RED, 'ERROR': Fore.RED + Style.BRIGHT,
        'TIME': Fore.BLUE
    }
}

THEME = THEMES['default']

def choose_theme():
    global THEME
    print("Choose color theme: [default/dark/light] (default=default)")
    choice = input().strip().lower()
    if choice in THEMES:
        THEME = THEMES[choice]
    print(Style.RESET_ALL)

def time_str(pkt):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(pkt.time)))
    except Exception:
        return '??'

def get_protocol(pkt):
    if pkt.haslayer(HTTPRequest):
        return 'HTTP'
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        return 'DNS'
    elif pkt.haslayer(TCP):
        return 'TCP'
    elif pkt.haslayer(UDP):
        return 'UDP'
    elif pkt.haslayer(ICMP):
        return 'ICMP'
    elif pkt.haslayer(ARP):
        return 'ARP'
    else:
        # Heuristic for some protocols (optional)
        if TCP in pkt:
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                return 'TLS?'
            if pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                return 'SSH?'
        return 'OTHER'

# Map severity levels to colors and emoji
SEVERITY_LEVELS = {
    None:     ('', ''),
    'info':   (THEME['INFO'], 'ℹ️'),
    'note':   (THEME['INFO'], '📝'),
    'warn':   (THEME['WARN'], '⚠️'),
    'error':  (THEME['ERROR'], '❗'),
}

def wireshark_expert(pkt):
    # Detect basic anomalies modeled after Wireshark expert info
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags == 0:
            return 'warn', 'TCP Null Flags'
        if flags & 0x04:
            return 'note', 'TCP Reset'
        if flags & 0x20:
            return 'note', 'TCP URG'
        if flags & 0x03 == 0x03:
            return 'warn', 'Abnormal TCP flags'
        if hasattr(pkt[TCP], 'chksum') and pkt[TCP].chksum == 0:
            return 'warn', 'TCP Checksum Zero'
    if pkt.haslayer(UDP) and hasattr(pkt[UDP], 'chksum') and pkt[UDP].chksum == 0:
        return 'warn', 'UDP Checksum Zero'
    if pkt.haslayer(ICMP) and hasattr(pkt[ICMP], 'chksum') and pkt[ICMP].chksum == 0:
        return 'warn', 'ICMP Checksum Zero'
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1 and pkt[ARP].hwsrc == "00:00:00:00:00:00":
            return 'error', 'ARP Rogue Source'
        if pkt[ARP].op == 2 and pkt[ARP].hwsrc == pkt[ARP].hwdst:
            return 'warn', 'Possible ARP Spoof'
    if getattr(pkt, 'malformed', False):
        return 'error', 'Malformed Packet'
    return None, ''

def get_info(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors='replace')
        return f"DNS Query: {qname}"
    elif pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        try:
            method = req.Method.decode(errors='ignore')
            path = req.Path.decode(errors='ignore')
            host = ''
            if hasattr(req, 'Host') and req.Host:
                host = req.Host.decode(errors='ignore')
            return f"HTTP: {method} {path} Host: {host}"
        except Exception:
            return "HTTP Request"
    elif pkt.haslayer(TCP):
        f = pkt[TCP].sprintf("%flags%")
        parts = []
        if "S" in f: parts.append("SYN")
        if "A" in f: parts.append("ACK")
        if "F" in f: parts.append("FIN")
        if "R" in f: parts.append("RST")
        if pkt.haslayer(Raw):
            try:
                snippet = pkt[Raw].load[:30].decode('utf-8', 'replace').replace("\n"," ").replace("\r"," ")
                parts.append(f"Data: {snippet}")
            except Exception:
                pass
        return "TCP " + "/".join(parts) if parts else "TCP Packet"
    elif pkt.haslayer(UDP):
        return "UDP Data"
    elif pkt.haslayer(ICMP):
        codes = {0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect", 8: "Echo Request"}
        t = pkt[ICMP].type
        return f"ICMP {codes.get(t, 'Type '+str(t))}"
    elif pkt.haslayer(ARP):
        op_map = {1: 'request', 2: 'reply'}
        return f"ARP: {op_map.get(pkt[ARP].op, 'op:'+str(pkt[ARP].op))}"
    else:
        return "Other Protocol"

def packet_matches(pkt, proto_sel, src_ip, dst_ip, port, keyword):
    if get_protocol(pkt) != proto_sel:
        return False

    if src_ip:
        if not (pkt.haslayer(IP) and pkt[IP].src == src_ip):
            return False

    if dst_ip:
        if not (pkt.haslayer(IP) and pkt[IP].dst == dst_ip):
            return False

    if port:
        port = str(port)
        # Check TCP or UDP ports
        if pkt.haslayer(TCP):
            if str(pkt[TCP].sport) != port and str(pkt[TCP].dport) != port:
                return False
        elif pkt.haslayer(UDP):
            if str(pkt[UDP].sport) != port and str(pkt[UDP].dport) != port:
                return False
        else:
            return False

    if keyword:
        if keyword.lower() not in get_info(pkt).lower():
            return False

    return True

def color_row(pkt, pkts):
    proto = get_protocol(pkt)
    proto_color = THEMES['default'].get(proto, Fore.WHITE) if proto not in THEMES else THEMES['default'][proto]
    src = pkt[IP].src if pkt.haslayer(IP) else (pkt[ARP].psrc if pkt.haslayer(ARP) else "—")
    dst = pkt[IP].dst if pkt.haslayer(IP) else (pkt[ARP].pdst if pkt.haslayer(ARP) else "—")
    ts = time_str(pkt)
    severity, expertmsg = wireshark_expert(pkt)
    sev_color, emoji = SEVERITY_LEVELS.get(severity, ('', ''))
    true_idx = pkts.index(pkt) + 1
    info = f"{get_info(pkt)} {sev_color}{emoji}{(' ' + expertmsg) if expertmsg else ''}{Style.RESET_ALL}"
    proto_col = THEME.get(proto, Fore.WHITE)
    return f"{Style.BRIGHT}{Fore.WHITE}{true_idx:>5}{Style.RESET_ALL} " \
           f"{THEME['TIME']}{ts}{Style.RESET_ALL} " \
           f"{proto_color}{proto:<7}{Style.RESET_ALL} " \
           f"{THEME['SRC']}{src:<15} {THEME['DST']}{dst:<15} " \
           f"{info}"

def print_header():
    print(f"{Style.BRIGHT}{THEME['HEADER']}{'No.':>5} {'Date/Time':<19} {'Proto':<7} {'Source':<15} {'Destination':<15} Info{Style.RESET_ALL}")

def paginated_view(filtered, pkts):
    print_header()
    idx, per_page = 0, 50
    while idx < len(filtered):
        for pkt in filtered[idx:idx+per_page]:
            print(color_row(pkt, pkts))
        idx += per_page
        if idx >= len(filtered):
            break
        user_input = input("\nType 'm' or 'more' to show 30 more, or [ENTER] to return: ").strip().lower()
        if user_input in ['m', 'more']:
            per_page = 30
        else:
            break

def summarize_flows(pkts, proto_filter=None):
    flows = Counter()
    for pkt in pkts:
        if IP in pkt and (proto_filter is None or get_protocol(pkt) == proto_filter):
            if TCP in pkt:
                key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                flows[key] += 1
            elif UDP in pkt:
                key = (pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport)
                flows[key] += 1
    print(f"\nConversation/Session Summary ({proto_filter if proto_filter else 'ALL'}):")
    print(f"{'SrcIP':<15} {'SPort':<6} {'DstIP':<15} {'DPort':<6} {'Count':<8}")
    for k, cnt in flows.most_common(15):
        print(f"{k[0]:<15} {k[1]:<6} {k[2]:<15} {k[3]:<6} {cnt:<8}")

def analyze_existing():
    filename = input("Enter pcap filename: ").strip()
    try:
        pkts = rdpcap(filename)
    except Exception as e:
        print(Fore.RED + f"[!] Error reading PCAP file: {e}")
        return
    stats = Counter(get_protocol(pkt) for pkt in pkts)
    print("\n| Protocol | Count |")
    print("|----------|-------|")
    for proto, count in stats.items():
        print(f"| {proto:<8} | {count:<5}|")
    print_header()
    protos = list(stats.keys())

    while True:
        try:
            sel = input(f"Protocol ({'/'.join(protos)}), or Ctrl+C to exit, [flows] for session summary: ").strip().upper()
        except KeyboardInterrupt:
            print("\nExiting protocol view.")
            break
        if sel == "":
            continue
        if sel == "FLOWS":
            pf = input("Show flows for protocol? (e.g. TCP/UDP or ENTER for all): ").strip().upper()
            summarize_flows(pkts, proto_filter=pf if pf else None)
            continue
        if sel not in protos:
            print(f"Invalid protocol {sel}. Please choose from {', '.join(protos)}.")
            continue

        print("Enter filters (press ENTER to skip):")
        src_ip = input("Source IP filter (src IP): ").strip()
        dst_ip = input("Destination IP filter (dst IP): ").strip()
        port = input("Port filter (src or dst port): ").strip()
        keyword = input("Search keyword in Info field: ").strip()

        filtered_packets = [pkt for pkt in pkts if packet_matches(pkt, sel, src_ip, dst_ip, port, keyword)]
        if not filtered_packets:
            print(f"No packets match the selected filters for protocol {sel}.")
            continue

        paginated_view(filtered_packets, pkts)

        export = input("Export these packets to filtered_output.pcap? (y/n): ").strip().lower()
        if export == 'y':
            try:
                wrpcap("filtered_output.pcap", filtered_packets)
                print(Fore.GREEN + "[✔] Exported to filtered_output.pcap")
            except Exception as ex:
                print(Fore.RED + f"Failed to export packets: {ex}")

        dump = input("Dump TCP/Raw payloads to payload_dump.txt? (y/n): ").strip().lower()
        if dump == 'y':
            try:
                with open("payload_dump.txt", "w", encoding='utf-8') as f:
                    for pkt in filtered_packets:
                        if pkt.haslayer(Raw):
                            try:
                                f.write(pkt[Raw].load.decode('utf-8', errors='ignore') + '\n')
                            except:
                                pass
                print(Fore.GREEN + "[✔] Payload dump saved to payload_dump.txt")
            except Exception as ex:
                print(Fore.RED + f"Failed to dump payloads: {ex}")

def live_capture():
    captured = []
    print_header()

    def callback(pkt):
        captured.append(pkt)
        print(color_row(pkt, captured))

    print(THEME['INFO'] + "[+] Starting live capture... Press Ctrl+C to stop.\n")
    try:
        sniff(prn=callback, store=True)
    except KeyboardInterrupt:
        print(THEME['WARN'] + f"\n[+] Capture stopped with {len(captured)} packets.")

    if captured:
        try:
            wrpcap("new_packet.pcap", captured)
            print(THEME['INFO'] + "[✔] Packets saved to new_packet.pcap")
        except Exception as e:
            print(Fore.RED + f"Failed to save capture: {e}")
    else:
        print(THEME['WARN'] + "[!] No packets captured.")

def main():
    print(Style.BRIGHT + Fore.CYAN + "Wireshark-Style Packet Analyzer with PDF-Style Coloring (Python Edition)" + Style.RESET_ALL)
    choose_theme()
    print("1) Capture and analyze real-time traffic")
    print("2) Analyze an existing pcap file")
    opt = input("Select option (1 or 2): ").strip()
    if opt == '1':
        live_capture()
    elif opt == '2':
        analyze_existing()
    else:
        print(Fore.RED + "[!] Invalid option. Please choose 1 or 2.")

if __name__ == "__main__":
    main()
