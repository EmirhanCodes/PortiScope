'''
Hinweis:
 Dieses Projekt dient ausschließlich zu Bildungszwecken! Scanne nur Systeme, 
 für die du ausdrückliche Erlaubnis hast! Illegale Scans sind strikt verboten.

 Das Projekt zeigt, wie man mit Python einen einfachen Portscanner 
 implementiert, inklusive Banner-Grabbing und TLS-Zertifikatsabfrage.

Achtung: Missbrauch des Codes für unbefugte Scans kann rechtliche Konsequenzen nach sich ziehen.
------------------------
'''
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
# Konfigurationen/ Globals
DEFAULT_TIMEOUT = 1.5    # Timeout für normale Verbindungen
DEFAULT_TLS_TIMEOUT = 3.0 # Timeout für TLS Verbindungen
DEFAULT_WORKERS = 100 # Max gleichzeitige Threads


openPorts = 0 # Globaler Zähler für gefundenen Offene Ports‚
openPortsLock = threading.Lock() # Schutz damit Threads nicht gleichzeitig Werte bearbeitet

# IN ARBEIT Später zum Speichern für weitere Infos 
foundServices = [] #Liste mit (port, Beschreibung, extra Infos)
foundServicesLock = threading.Lock() # Lock für die gemeinsame Nutzung der List

#Funktionen
def parse_port_range(inp):
    """
    Parst die Benutzereingabe und gibt ein range-Objekt zurück.
    Akzeptiert:
     - "1" -> 0-1023
     - "2" -> 0-49151
     - "3" -> 0-65535
     - "start-end" -> inklusiver Bereich
    Falls Eingabe ungültig ist, wird Standard 0-1023 zurückgegeben.
    """
    inp = inp.strip() # Entfernt Whitespaces
    # Vordefinierte Auswahl
    if inp == "1":
        return range(0, 1024)  # System Ports 0-1023
    if inp == "2":
        return range(0, 49152)  # System Ports + Registered Ports 0-49151
    if inp == "3":
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
    print("Ungültige Eingabe — Standard 0-1023 wird verwendet.")
    return range(0, 1024)

# Banner Grabbing + TLS
def tryRecv(socketObj: socket.socket, timeout: float = 1.0) -> str:
    """
    Versucht, bis zu 4096 Bytes vom Socket zu lesen.
    Rückgabe: decodierter String oder leerer String bei Fehler/Timeout.
    
    Viele Dienste senden nach Verbindungsaufbau direkt eine "Begrüßung" (z.B. FTP, SMTP).
    Ansonsten Manuelle Anfrage 
    """
    try:
        socketObj.settimeout(timeout)
        data = socketObj.recv(4096)
        if not data:
            return ""
        return data.decode(errors="replace").strip()
    except socket.timeout:
        print("tryRecv: timeout")
        return ""
    except Exception as e:
        print(f"tryRecv: exception: {e}")
        return ""

def grab_tls_cert(host, port):
    """
    Führt einen TLS-Handshake mit dem Server durch.
    Wenn der Server ein Zertifikat anbietet (z. B. HTTPS, SMTPS),
    wird dieses ausgelesen, um Informationen über den Betreiber zu erhalten.
    """
    try:
        context = ssl.create_default_context() # setzt einen sicheren TLS Kontext
        with socket.create_connection((host, port), timeout=3) as sock: # eröffnet eine TCP Verbindung
            with context.wrap_socket(sock, server_hostname=host) as ssock: # führt TLS Handshake durch 
                cert = ssock.getpeercert() # liefert strukturierte & lesbare Zertifikatsfelder
                if not cert:
                    return None
                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter")
                }
    except Exception:
        return None



def simple_banner_probe(host, port):
    """
    Versucht, ein Banner (z.B. Server Begrüßung oder HTTP-Header)zu lesen.
    Ansonsten wird ein HTTP Head Req gesendet.
    -> Dienste erkennen z.B 220 FTP Server Ready
    """
    try:
        with socket.create_connection((host, port), timeout=1) as s: # Versucht TCP Verbindung herzustellen
            # 1. Warten ob Server von sich aus was sendet
            banner = tryRecv(s)
            if banner:
                return banner
    
            # 2. Ansonsten Versuch mit einfacher HTTP Anfrage
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
            banner = tryRecv(s)
            return banner
    except Exception:
        return ""

# Einzelnen Port Scannen
def scan_port(host, port):
    """
    Prüft nach offenen Ports und liest danach  Banner + TLS Zertifikat
    """
    global openPorts
    try:
        with socket.create_connection((host, port), timeout=1.5): # Socket Create unterstützt auch IPv6
            print(f"[+] Port {port} ist offen.")
            # Mehrere Threads greifen gleichzeitig auf die Variable `openPorts` zu.
            # Der Lock stellt sicher, dass immer nur ein Thread diesen Zähler verändert,
            # um Race Conditions (Fehler durch gleichzeitige Zugriffe) zu verhindern.

            with openPortsLock:
                openPorts += 1
            # Versuch Banner Infos zu bekommen
            banner = simple_banner_probe(host, port)
            # Versuch TLS Infos zu bekommen
            tls_info = grab_tls_cert(host, port)
            
            #Ergebnisse
            if banner:
                print(f" └─ Banner: {banner[:80]}")  # nur ersten Teil ausgeben
            if tls_info:
                print(f" └─ TLS-Zertifikat gefunden ({tls_info['issuer']})")

    except:
        # Mögliche Fehler wie Timeout, Refused, Reset,... sind völlig normal
        # Wir ignorieren diese bewusst, da wir nur offene Ports augeben wollen.
        # optional könnte man dies loggen
        pass

#Haupt Scan Funktion
def main_scan(host, ports, max_workers=100):
    print(f"Starte Scan auf {host} ({len(ports)} Ports)...")

    # Auflösen des Hostnamens in IP
    try:
        resolved = socket.gethostbyname(host)
        if resolved != host: # Damit keine Doppelte Ausgabe erfolgt
            print(f"Aufgelöst: {resolved}")
    except socket.gaierror:
        print("Ungültiger Hostname.")
        return
    # Wir starten für jeden Port ein eigenen Task, der parallel im Hintegrund läuft.
    # ThreadPoolExecutor sorgt dafür, dass die Anzahl der Task begrentzt sind (max_workers) 
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, resolved, p) for p in ports]
        try:
            for _ in as_completed(futures): # as_completed wartet auf fertige Tasks
                pass # Ergebnisse werden in ScanPort ausgegeben
        except KeyboardInterrupt:
            print("\nScan abgebrochen.")

    print(f"\nScan abgeschlossen. {openPorts} offene Ports gefunden.")

def show_banner():
    print(r"""
╔════════════════════════════════════════╗
║              PORTISCOPE 🕵️‍♂️             ║
║        by EmirhanCodes | v1.0.0        ║
╚════════════════════════════════════════╝
""")





#Programmstart / Main
if __name__ == "__main__":
    show_banner()
    # Benutzereingaben
    hostIP = input("IP Adresse oder Hostname: ").strip()
    portRangeInput = input(
        "Wähle die Anzahl der Ports aus: 1: 0-1023 2: 0–49151 3: 0-65535 oder benutzerdefiniert z.B. 100-500: "
    )
    # Gewählten Portbereich parsen 
    portRange = parse_port_range(portRangeInput)
    # Starten
    main_scan(hostIP, portRange, max_workers=100)
    #max_workers: maximale Anzahl gleichzeitiger Threads im Pool

#Coming Soon
# Service Erkennung
# Farbige Cli
# Fehlerlogging
# Fortschrittsanzeige