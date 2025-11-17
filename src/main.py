"""
Hinweis:
 Dieses Projekt dient ausschließlich zu Bildungszwecken! Scanne nur Systeme, 
 für die du ausdrückliche Erlaubnis hast! Illegale Scans sind strikt verboten.

 Das Projekt zeigt, wie man mit Python einen einfachen Portscanner 
 implementiert, inklusive Banner-Grabbing und TLS-Zertifikatsabfrage.

Achtung: Missbrauch des Codes für unbefugte Scans kann rechtliche Konsequenzen nach sich ziehen.
------------------------
"""
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from colorama import Fore, Style, init
init(autoreset=True) # sorgt dafür, dass die Farben nach jedem Print resettet werden 

# Konfigurationen/ Globals
DEFAULT_TIMEOUT = 1.5    # Timeout für normale Verbindungen
DEFAULT_TLS_TIMEOUT = 3.0 # Timeout für TLS Verbindungen
DEFAULT_WORKERS = 100 # Max gleichzeitige Threads
DEBUG = False

openPorts = 0 # Globaler Zähler für gefundenen Offene Ports
openPortsLock = threading.Lock() # Schutz damit Threads nicht gleichzeitig Werte bearbeitet

# (IN ARBEIT) später zum Speichern für weitere Informationen 
foundServices = [] #z.B. Liste mit port, Beschreibung, extra Informationen
foundServicesLock = threading.Lock() # Lock für die gemeinsame Nutzung der List

# -----------------------
# Farbschema 
# -----------------------

CLR_HEADER = Fore.BLACK               # App-Titel & Meta-Infos
CLR_INFO   = Fore.WHITE              # neutrale Infos
CLR_OK     = Fore.GREEN              # offene Ports bzw. erfolgreiche Aktionen
CLR_WARN   = Fore.LIGHTYELLOW_EX     # Warnungen & Hinweise
CLR_ERR    = Fore.RED                # Fehler & Abbrüche
CLR_TLS    = Fore.LIGHTBLUE_EX       # TLS Zertifikate
CLR_BANNER = Fore.CYAN    # Banner Ausgaben (z.B. Serverantworten)


#Funktionen
def parse_port_range(inp):
    """
    Parst die Benutzereingabe und gibt ein range-Objekt zurück.
    Akzeptiert:
     - "1" → 0-1023
     - "2" → 0-49151
     - "3" → 0-65535
     - "start-end" → inklusiver Bereich
    Falls Eingabe ungültig ist, wird Standard 0-1023 zurückgegeben.
    """
    inp = inp.strip() # Entfernt Whitespaces
    # Vordefinierte Auswahl
    if inp == "1":
        return range(0, 1024)  # System Ports 0-1023
    if inp == "2":
        return range(0, 49152)  # System Ports + Registered Ports 0-49151
    if inp == "3" or inp =="all":
        return range(0, 65536)  # Alle Ports 0-65535
    
    # Benutzerdefinierter Bereich "start-end"
    if "-" in inp:
        parts = inp.split("-")
        if len(parts) == 2:
            try:
                start = int(parts[0])
                end = int(parts[1])
                if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                    # range endet exklusiv, daher +1 für inklusives Ende
                    return range(start, end + 1)  # inklusiv end
            except ValueError:
                # ungültige Eingabe -> Fallback 
                pass

    # Fallback: falls ungültig -> Standard 0-1023
    print(CLR_WARN + "[!] Ungültige Eingabe — Standard 0-1023 wird verwendet.")
    return range(0, 1024)

def resolve_service_name(port):
    try:
        service = socket.getservbyport(port, "tcp")
        return service
    except OSError:
        return "unknown"


# Banner Grabbing + TLS
def try_recv(socketobj: socket.socket, timeout: float = 1.0) -> Optional[str]:
    """
    Versucht, bis zu 4096 Bytes vom Socket zu lesen.
    Rückgabe: decodierter String oder leerer String bei Fehler/Timeout.
    
    Viele Dienste senden nach Verbindungsaufbau direkt eine "Begrüßung" (z.B. FTP, SMTP).
    Ansonsten manuelle Anfrage 
    """
    try:
        socketobj.settimeout(timeout)
        data = socketobj.recv(4096)
        if not data:
            return ""
        return data.decode(errors="replace").strip()
    except socket.timeout:
        if DEBUG:
            print(CLR_WARN + "[!] Timeout während Banner Grabbing")
            return ""
    except Exception as e:
        if DEBUG:
            print(CLR_WARN + f"[!] tryRecv: exception: {e}")
            return ""


def simple_banner_probe(host, port):
    """
    Versucht, ein Banner (z.B. Server Begrüßung oder HTTP-Header)zu lesen.
    Ansonsten wird ein HTTP Head Req gesendet.
    → Dienste erkennen z. B. 220 FTP Server Ready
    """
    try:
        with socket.create_connection((host, port), timeout=1) as s: # Versucht TCP Verbindung herzustellen
            # 1. Warten ob Server von sich aus was sendet
            banner = try_recv(s)
            if banner:
                return banner

            # 2. Ansonsten Versuch mit einfacher HTTP Anfrage
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
            banner = try_recv(s)
            return banner
    except:
        pass

def grab_tls_cert(host, port):
    """
    Führt einen TLS-Handshake mit dem Server durch.
    Wenn der Server ein Zertifikat anbietet (z. B. HTTPS, SMTPS),
    wird dieses ausgelesen, um Informationen über den Betreiber zu erhalten.
    """
    try:
        context = ssl.create_default_context() # setzt einen sicheren TLS Kontext
        context.check_hostname = False
        
        with socket.create_connection((host, port), timeout=1) as sock: # eröffnet eine TCP Verbindung
            with context.wrap_socket(sock, server_hostname=host) as ssock: # führt TLS Handshake durch 
                cert = ssock.getpeercert() # liefert strukturierte & lesbare Zertifikatsfelder
                if not cert:
                    return None

                subject = cert.get("subject", [])
                for item in subject:
                    if item[0][0] == "commonName":
                        return item[0][1]

                return "Unknown CN"
    except Exception:
        return None


# Output Funktion
def print_port_result(port, banner, tls_cn):
    service = resolve_service_name(port)
    proto = "tcp"

    # Grundzeile (immer)
    base = f"{CLR_OK}[OPEN]{Style.RESET_ALL} {port}/{proto:<4} {service:<10}"

    if banner:
        base += f" {CLR_BANNER}{banner.splitlines()[0]}{Style.RESET_ALL}"

    if tls_cn:
        base += f" {Fore.CYAN}TLS:{Style.RESET_ALL} {tls_cn}"
    
    print(base)



# Scan Funktionen
def scan_port(host, port):
    """
    Prüft nach offenen Ports und liest danach Banner + TLS Zertifikat
    """
    global openPorts
    try:
        with socket.create_connection((host, port), timeout=1.5): # Socket Create unterstützt auch IPv6
            

            # Mehrere Threads greifen gleichzeitig auf die Variable `openPorts` zu.
            # Der Lock stellt sicher, dass immer nur ein Thread diesen Zähler verändert,
            # um Race Conditions (Fehler durch gleichzeitige Zugriffe) zu verhindern.

            with openPortsLock:
                openPorts += 1
            # Versuch Banner Informationen zu bekommen
            banner = simple_banner_probe(host, port)
            # Versuch TLS Informationen zu bekommen
            tls_info = grab_tls_cert(host, port)

            print_port_result(port, banner, tls_info)
            

    except Exception as e:
        if DEBUG:
            # beim Entwickeln nützlich: zeigt, warum ein Port nicht gescannt werden konnte
            print(CLR_WARN + f"[!] Fehler bei Port {port}: {e}")
        # Produktion: ignorieren, weil Timeouts/Refused normal sind
        pass

def main_scan(host, ports, max_workers=100):
    print(CLR_OK + f"Starte Scan ({len(ports)} Ports)...")

    # Auflösen des Hostnamens in IP
    try:
        resolved = socket.gethostbyname(host)
        if resolved != host: # Damit keine doppelte Ausgabe erfolgt
            print(CLR_OK + f"Aufgelöst: {resolved}")
    except socket.gaierror:
        print(CLR_ERR + "[!] Ungültiger Hostname.")
        return

    # Threads: adaptive Anzahl, max. DEFAULT_WORKERS
    worker_count = min(max_workers, max(4, len(list(ports))))
    print(CLR_INFO + f"[i] {worker_count} worker threads")
    
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        # Erstellt parallel ausgeführte Scan-Aufgaben (Futures)
        futures = [executor.submit(scan_port, resolved, p) for p in ports]
    
        try:
            for _ in as_completed(futures):  # wartet, bis einzelne Tasks abgeschlossen sind
                pass  # Ergebnisse werden direkt in scan_port ausgegeben
        except KeyboardInterrupt:
            print(CLR_ERR + "\n[!] Scan abgebrochen.")
    
    print(CLR_OK + f"\nScan abgeschlossen. {openPorts} offene Ports gefunden.")

# UI
def show_banner():
    print(CLR_HEADER + r"""
┌───────────────────────────────────────────────┐
│           PORTISCOPE — Port Scanner           │
│       Version 1.0.0 • by EmirhanCodes         │
└───────────────────────────────────────────────┘

""")

#Programmstart / Main
if __name__ == "__main__":
    show_banner()
    # Benutzereingaben
    hostIP = input("Ziel IP: ").strip()
    portRangeInput = input(
        "Portbereich wählen:\n"
        "  1 = 0–1023\n"
        "  2 = 0–49151\n"
        "  3 = 0–65535\n"
        "  custom = z.B. 100-500\n"
        "> "
    ).strip()
    # Gewählten Portbereich parsen 
    portRange = parse_port_range(portRangeInput)
    # Starten
    main_scan(hostIP, portRange, max_workers=100)
    #max_workers: maximale Anzahl gleichzeitiger Threads im Pool

#Coming Soon
# Service Erkennung
# Fehlerlogging
# Fortschrittsanzeige