# 🕵️ PortiScope

![Educational Project](https://img.shields.io/badge/Educational-Project-blue)

*Ein lightweight Python Portscanner zur Erkennung offener Ports und Dienste.*

---

## 🚀 Überblick
**PortiScope** ist ein in Python entwickelter Portscanner.  
Es erkennt offene Ports eines Zielhosts und versucht, durch Banner-Grabbing und TLS-Inspektion Hinweise auf laufende Dienste zu erhalten.

Dieses Projekt entstand als Lernprozesses, um ein tieferes Verständnis für folgende Themen zu entwickeln:
- TCP/IP und Socket-Programmierung
- Nebenläufigkeit mit Python Threads
- Grundprinzipien der Netzwerksicherheit und Portanalyse  

---

## 👁️‍🗨️ Ein Blick auf PortiScope
![Bildschirmfoto 2025-11-08 um 20.41.52.png](img/Bildschirmfoto%202025-11-08%20um%2020.41.52.png)
---

## ⚙️ Funktionen
- 🔍 **Multithreading** 
- 🔒 **TLS Zertifikatsprüfung**:  ermittelt Aussteller, Gültigkeit und Betreff
- 🪪 **Banner Grabbing**: erkennt typische Dienste anhand ihrer Begrüßung oder Header
- ⏱️ **Custom Portbereiche und Timeouts**

---

## 🧩 Wie funktioniert PortiScope?
1. **Eingabeaufforderung:** Der Benutzer gibt Hostname/IP und Portbereich ein.
2. **Parallelisierung:** Es werden mehrere Task gestartet, die Ports parallel prüfen.
3. **Verbindungstest:** Jeder Port wird per `socket.create_connection()` getestet.
4. **Banner Abfrage:** Falls offen, wird versucht, ein Dienstbanner oder Header zu lesen.
5. **TLS-Prüfung:** Falls TLS reagiert, wird das Zertifikat ausgelesen.
6. **Ergebnis:** Informationen werden in der Konsole ausgegeben; offene Ports werden gezählt.
---

## 📚 Motivation
PortiScope ist ein Lehrprojekt, um folgende Konzepte praktisch zu verstehen:
- Socket Programmierung (TCP)
- TLS/SSL Grundlagen
- Nebenläufigkeit / Thread Synchronisation

Es ist nicht als Ersatz für professionelle Tools (z. B. Nmap) gedacht, sondern als Lernhilfe.

---

## ⚠️ Rechtlicher Hinweis
Dieses Tool ist ausschließlich für **Bildungs- und Testzwecke** gedacht.  
Das Scannen fremder Systeme **ohne ausdrückliche Genehmigung** ist **illegal** und kann strafrechtlich verfolgt werden.

Verwende das Programm nur auf eigenen oder autorisierten Netzwerken.

---

## 🧑‍💻 Autor
**Emirhan I.**  
🎓 *Auszubildender Fachinformatiker für Systemintegration*  
💡 *Leidenschaft für Netzwerke, Automatisierung & IT-Sicherheit*  

_Made with ❤️ by [EmirhanCodes](https://github.com/EmirhanCodes)_
