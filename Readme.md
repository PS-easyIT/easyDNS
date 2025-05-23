# easyDNS Advanced - DNS Server Management Tool

## Übersicht

easyDNS Advanced ist ein umfassendes PowerShell-basiertes Tool zur Verwaltung von DNS-Servern. Es bietet eine grafische Benutzeroberfläche (GUI) für die einfache Verwaltung von DNS-Zonen und -Einträgen. Ziel ist es, die DNS-Administration zu vereinfachen und effizienter zu gestalten.

## Kernfunktionen

*   **Benutzerfreundliche GUI**: Intuitive grafische Oberfläche für eine einfache Bedienung.
*   **Zonenverwaltung**:
    *   Erstellung, Löschung und Auflistung von Forward- und Reverse-Lookupzonen.
    *   Unterstützung für verschiedene Zonentypen (primär, sekundär, Stub).
*   **DNS Records Management**:
    *   Hinzufügen, Bearbeiten und Löschen von DNS-Einträgen (A, AAAA, CNAME, MX, PTR, TXT, SRV, NS, CAA, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM).
    *   Einfache Bearbeitung von Record-Eigenschaften.
*   **Import/Export**:
    *   Importieren und Exportieren von DNS-Konfigurationen in verschiedenen Formaten (CSV, JSON, BIND Zone File, Tab-getrennte Werte, HTML, PowerShell).
    *   Automatisches Erstellen fehlender Zonen beim Import.
    *   Datenvorschau vor dem Import/Export.
*   **DNSSEC Management**:
    *   Aktivieren, Deaktivieren und Verwalten von DNSSEC für Zonen.
    *   Unterstützung für verschiedene Signierungsalgorithmen und Schlüssellängen.
    *   Verwaltung von DNSSEC-Schlüsselinformationen.
*   **DNS Tools**:
    *   Integrierte Tools zur Diagnose und Fehlerbehebung (Ping, Tracert, Nslookup, PathPing, Test-NetConnection).
    *   DNS-Cache leeren (Client und Server).
    *   Erstellung von DNS-Server Zustandsberichten.
*   **Troubleshooting & Auditing**:
    *   Erweiterte Diagnosefunktionen zur Identifizierung und Behebung von DNS-Problemen.
    *   Zonenkonfigurationsprüfung auf Fehler und Inkonsistenzen.
    *   DNSSEC-Validierungsprüfung.
    *   Netzwerkdiagnose.
    *   Audit-Protokollierung von DNS-Änderungen zur Nachverfolgung von Änderungen.
*   **Automatisierung**: Automatisierung von Routineaufgaben durch PowerShell-Skripte.

## Anforderungen

*   Windows PowerShell 5.1 oder höher
*   DNS Server Rolle muss installiert sein
*   Ausführungsrichtlinie muss entsprechend gesetzt sein (z.B. `Set-ExecutionPolicy RemoteSigned`)
*   Administratorrechte

## Verwendung

1.  **Download**: Laden Sie das Skript `easyDNS_V0.1.2.ps1` und die zugehörige Konfigurationsdatei `easyDNS_Advanced.ini` herunter.
2.  **Konfiguration**: Passen Sie die `easyDNS.ini` Datei an, um Standardwerte für Server, Pfade und andere Einstellungen festzulegen.
3.  **Ausführung**: Führen Sie das Skript `easyDNS_V0.1.2.ps1` mit Administratorrechten aus.

    ```powershell
    .\easyDNS_V0.1.2.ps1
    ```
4.  **GUI**: Verwenden Sie die GUI, um DNS-Server zu verwalten.

## Registerkarten-Beschreibungen

*   **Forward Zones**: Verwaltung von Forward-Lookupzonen.
    *   Aktualisieren der Zonenliste
    *   Erstellen neuer Zonen (primär, sekundär, Stub)
    *   Löschen vorhandener Zonen
*   **Reverse Zones**: Verwaltung von Reverse-Lookupzonen.
    *   Aktualisieren der Zonenliste
    *   Erstellen neuer Zonen
    *   Löschen vorhandener Zonen
    *   IP-Netzwerk-Generator zur einfachen Erstellung von Reverse-Lookupzonen
*   **DNS Records**: Verwaltung von DNS-Einträgen.
    *   Auswahl der Zone
    *   Auswahl des Record Typs
    *   Erstellen, Testen, Anzeigen und Löschen von DNS-Einträgen
*   **Import/Export**: Import und Export von DNS-Daten.
    *   Unterstützte Formate: CSV, JSON, BIND Zone File, Tab-getrennte Werte, HTML, PowerShell
    *   Option zum automatischen Erstellen fehlender Zonen beim Import
    *   Vorschau der Daten vor dem Import/Export
*   **DNSSEC**: Verwaltung von DNSSEC-Einstellungen.
    *   Aktivieren und Deaktivieren von DNSSEC für Zonen
    *   Anzeige von DNSSEC-Schlüsselinformationen
    *   Auswahl des Signierungsalgorithmus und der Schlüssellänge
*   **DNS Tools**: Netzwerkdiagnose-Tools.
    *   Ping, Tracert, Nslookup, PathPing, Test-NetConnection
    *   DNS-Cache leeren (Client und Server)
    *   DNS-Server Zustandsbericht
*   **Troubleshooting & Audit**: Erweiterte Diagnose- und Audit-Funktionen.
    *   DNS-Server Diagnose
    *   Zonenkonfigurationsprüfung
    *   DNSSEC-Validierungsprüfung
    *   Netzwerkdiagnose
    *   Audit-Protokollierung von DNS-Änderungen

## Geplante Erweiterungen

*   **Verbesserte GUI**:
    *   Umstellung auf WPF für eine modernere und flexiblere Benutzeroberfläche.
    *   Anpassbare Dashboards zur Überwachung des DNS-Serverstatus.
    *   Erweiterte Filterung und Suche in den DataGridViews.
    *   Drag & Drop Unterstützung für Zonen und Records.
*   **Erweiterte Automatisierung**:
    *   Integration mit REST-APIs zur Automatisierung von DNS-Verwaltungsaufgaben.
    *   Unterstützung für das Erstellen von benutzerdefinierten PowerShell-Skripten zur Automatisierung komplexer Aufgaben.
*   **Verbesserte Fehlerbehandlung**:
    *   Detailliertere Fehlermeldungen und automatische Fehlerbehebung.
    *   Automatisierte Benachrichtigungen bei kritischen Ereignissen.
*   **Erweiterte DNSSEC-Funktionen**:
    *   Unterstützung für Key Rollover, Verwaltung von Trust Anchors.
    *   Automatisierte DNSSEC-Konfiguration und -Überwachung.
*   **Automatisierte Berichterstellung**:
    *   Generierung von Berichten über den DNS-Serverstatus und die Konfiguration.
    *   Anpassbare Berichte zur Erfüllung spezifischer Anforderungen.
*   **Remote-Verwaltung**:
    *   Möglichkeit zur Verwaltung von DNS-Servern über PowerShell Remoting.
    *   Sichere Remote-Verbindung mit Authentifizierung und Verschlüsselung.
*   **Benutzerauthentifizierung**:
    *   Integration von Benutzerauthentifizierung und Autorisierung.
    *   Rollenbasierte Zugriffskontrolle zur Steuerung des Zugriffs auf Funktionen und Daten.
*   **Unterstützung für dynamische DNS-Updates**:
    *   Integration mit DHCP-Servern zur automatischen Aktualisierung von DNS-Einträgen.
    *   Unterstützung für Secure DNS Updates.
*   **Erweiterte Filterung und Suche**:
    *   Verbesserte Suchfunktionen in den DataGridViews.
    *   Filterung nach verschiedenen Kriterien (z.B. Record-Typ, Zone, Alter).
*   **Mehrsprachigkeit**:
    *   Unterstützung für weitere Sprachen.
    *   Einfache Anpassung der Benutzeroberfläche an verschiedene Sprachen.
*   **Zonen Vorlagen**:
    *   Möglichkeit, Vorlagen für neue Zonen zu erstellen.
    *   Vorlagen für verschiedene Zonentypen (z.B. Standard, Active Directory integriert).
*   **Integration mit Active Directory**:
    *   Verbesserte Integration mit Active Directory zur Verwaltung von DNS-Zonen.
    *   Automatisches Erstellen von DNS-Zonen in Active Directory.
*   **Leistungsoptimierung**:
    *   Optimierung der Skriptlaufzeit durch effizientere Algorithmen und Datenstrukturen.
    *   Caching von häufig verwendeten Daten zur Reduzierung der Serverlast.
*   **Erweiterte Protokollierung**:
    *   Detailliertere Protokollierung von Ereignissen und Fehlern.
    *   Integration mit zentralen Protokollierungssystemen (z.B. Splunk, ELK Stack).
*   **Unterstützung für Cloud-DNS-Dienste**:
    *   Integration mit Cloud-DNS-Diensten wie Azure DNS und AWS Route 53.
    *   Verwaltung von DNS-Zonen und -Einträgen in der Cloud.
*   **Versionskontrolle**:
    *   Integration mit Versionskontrollsystemen wie Git zur Nachverfolgung von Änderungen.
    *   Möglichkeit, ältere Versionen von DNS-Konfigurationen wiederherzustellen.

## Contributing
Beiträge sind willkommen! Bitte erstellen Sie einen Issue oder Pull Request auf GitHub.

## Lizenz
Dieses Projekt ist unter der MIT-Lizenz lizenziert

## Kontakt
Andreas Hepp  
[www.phinit.de](www.phinit.de)  
[www.psscripts.de](www.psscripts.de)