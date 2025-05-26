# easyDNS v0.2.27 - DNS Server Management Tool

## Overview (English)

easyDNS v0.2.27 is a PowerShell-based DNS server management tool featuring a modern Windows 11-style WPF interface. 

### Key Features

- **Modern WPF Interface**: Windows 11-inspired design with responsive layout and intuitive navigation
- **Comprehensive Zone Management**: Create, manage, and monitor both forward and reverse DNS zones
- **Advanced DNS Records**: Support for A, AAAA, CNAME, MX, PTR, TXT, SRV, NS, SOA records with validation
- **DNSSEC Management**: Complete DNSSEC implementation with key management and validation
- **Import/Export**: Flexible data exchange in CSV, XML, and JSON formats
- **Real-time Monitoring**: Live DNS query monitoring with performance metrics and analytics
- **Diagnostic Tools**: Comprehensive troubleshooting suite including ping, nslookup, traceroute, and DNS benchmarking
- **Audit & Logging**: Detailed logging system with event tracking and export capabilities
- **Auto-Detection**: Automatic detection and connection to local DNS servers
- **Performance Analytics**: Response time analysis, throughput monitoring, and health reporting

---

## Übersicht (Deutsch)

easyDNS v0.2.27 ist ein PowerShell-basiertes DNS-Server-Verwaltungstool mit einer modernen Windows 11-Style WPF-Oberfläche.

### Hauptfunktionen

- **Moderne WPF-Oberfläche**: Windows 11-inspiriertes Design mit responsivem Layout und intuitiver Navigation
- **Umfassende Zonenverwaltung**: Erstellen, verwalten und überwachen von Forward- und Reverse-DNS-Zonen
- **Erweiterte DNS-Einträge**: Unterstützung für A, AAAA, CNAME, MX, PTR, TXT, SRV, NS, SOA-Einträge mit Validierung
- **DNSSEC-Verwaltung**: Vollständige DNSSEC-Implementierung mit Schlüsselverwaltung und Validierung
- **Import/Export**: Flexibler Datenaustausch in CSV-, XML- und JSON-Formaten
- **Echtzeit-Überwachung**: Live-DNS-Abfrage-Überwachung mit Leistungsmetriken und Analysen
- **Diagnose-Tools**: Umfassende Fehlerbehebungs-Suite mit Ping, Nslookup, Traceroute und DNS-Benchmarking
- **Audit & Protokollierung**: Detailliertes Protokollierungssystem mit Ereignisverfolgung und Exportfunktionen
- **Auto-Erkennung**: Automatische Erkennung und Verbindung zu lokalen DNS-Servern
- **Leistungsanalysen**: Antwortzeit-Analyse, Durchsatz-Überwachung und Gesundheitsberichte

---

## Changelog

### Version 0.2.27 (Latest - 26.05.2025)
- **Complete WPF Rewrite**: Modern Windows 11-style interface with improved user experience
- **Enhanced Navigation**: Streamlined panel-based navigation system with 8 main sections
- **Real-time Monitoring**: Live DNS query monitoring with performance analytics and pattern analysis
- **Advanced Diagnostics**: Comprehensive diagnostic tools including DNS benchmarking, leak testing, and traceroute analysis
- **Improved DNSSEC**: Enhanced DNSSEC management with key generation, validation, and rollover support
- **Auto-Detection**: Automatic detection of local DNS server roles with smart connection handling
- **Performance Metrics**: Response time analysis, throughput monitoring, and comprehensive health reporting
- **Enhanced Logging**: Advanced logging system with filtering, export capabilities, and rotation
- **Modern UI Components**: Windows 11-inspired design elements, responsive layout, and dark navigation
- **Inline Configuration**: No external INI file required - all configuration embedded in script
- **Import/Export**: Flexible data exchange in CSV, XML, and JSON formats with validation
- **Audit & Event Tracking**: Complete audit trail with event log integration and monitoring

### Version 0.1.11 (11.05.2025)
- **Enhanced WPF Interface**: Improved Windows 11-style design with better responsiveness
- **Performance Monitoring**: Added performance counters and connection status caching
- **Advanced Logging**: Extended logging with component-based categorization and log rotation
- **Auto-Refresh**: Configurable automatic refresh functionality (5-minute intervals)
- **Connection Management**: Smart DNS server detection with auto-connect for local servers
- **Error Handling**: Robust error handling with retry mechanisms and safe operations
- **Extended Record Support**: Support for A, AAAA, CNAME, MX, PTR, TXT, SRV, NS, SOA records
- **Input Validation**: Enhanced input validation and sanitization
- **Temporary Files**: Proper temporary file management and cleanup
- **Cache Management**: Improved caching for better performance

### Version 0.0.14 (21.03.2025)
- **Initial WPF Implementation**: First version with Windows Presentation Foundation interface
- **Basic DNS Management**: Core functionality for zone and record management
- **Windows 11 Design**: Modern design language with Windows 11 color scheme
- **Export/Import**: Basic CSV, XML, and JSON export/import functionality
- **DNS Server Detection**: Automatic detection of local DNS server installations
- **Logging System**: Basic logging with file rotation and color-coded console output
- **Zone Management**: Forward and reverse zone creation and management
- **Record Operations**: Basic DNS record CRUD operations
- **Configuration Management**: Inline configuration system
- **Error Handling**: Basic error handling and user feedback

### Early Development Versions
- **v0.0.x**: Initial development versions with basic PowerShell DNS cmdlet integration
- **Pre-release**: Proof-of-concept versions with command-line interface

---

## Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016/2019/2022
- **PowerShell**: Version 5.1 or higher (PowerShell 7+ recommended)
- **DNS Server Role**: Must be installed on target server
- **Permissions**: Administrator rights required
- **Execution Policy**: Set to RemoteSigned or Unrestricted
- **.NET Framework**: 4.7.2 or higher (for WPF components)

## Installation & Usage

1. **Download**: Download the script `easyDNS_V0.2.27.ps1`
2. **Execution Policy**: Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. **Run as Administrator**: Execute the script with administrator privileges:
   ```powershell
   .\easyDNS_V0.2.27.ps1
   ```
4. **Auto-Connection**: The tool automatically detects local DNS server roles and connects
5. **Manual Connection**: For remote servers, enter the server name/IP and click "Connect"

## Interface Overview

### Main Panels

- **Dashboard**: System overview with server information and DNS statistics
- **Forward Zones**: Management of forward lookup zones
- **Reverse Zones**: Management of reverse lookup zones  
- **DNS Records**: Create, edit, and delete DNS records
- **Import/Export**: Data exchange in multiple formats
- **DNSSEC**: DNSSEC configuration and key management
- **Diagnostic Tools**: Comprehensive troubleshooting suite
- **Audit and Logs**: Event monitoring and log analysis

### Diagnostic Tools Features

- **Quick Tools**: Ping, Nslookup, DNS resolution, connection testing
- **Cache Management**: DNS server and client cache control
- **Service Management**: DNS service start/stop/restart operations
- **Configuration**: Server settings and network adapter DNS information
- **Forwarders**: DNS forwarder configuration and management
- **Zone Tools**: Zone-specific operations and transfers
- **Event Logs**: DNS, system, and security event analysis
- **Advanced Diagnostics**: DNS benchmarking, latency testing, leak detection
- **Real-time Monitoring**: Live query monitoring with pattern analysis

## Configuration

The application uses inline configuration with the following key settings:

```powershell
$global:AppConfig = @{
    AppName = "easyDNS"
    ScriptVersion = "0.2.27"
    AutoRefreshInterval = 300  # seconds
    MaxLogEntries = 10000
    DefaultTTL = 3600
    EnableLogging = $true
    DebugMode = $false
}
```

## Logging

- **Location**: `Logs/easyDNS_YYYYMMDD_USERNAME.log`
- **Rotation**: Automatic rotation at 10MB
- **Levels**: INFO, WARN, ERROR, DEBUG, SUCCESS
- **Export**: Logs can be exported in various formats

## Performance Features

- **Caching**: Intelligent caching for improved responsiveness
- **Async Operations**: Non-blocking operations for better UI experience
- **Connection Pooling**: Efficient DNS server connection management
- **Auto-Refresh**: Configurable automatic data refresh
- **Performance Counters**: Built-in performance monitoring

## Security Features

- **Input Validation**: Comprehensive input sanitization
- **Safe Operations**: Error handling with retry mechanisms
- **Audit Trail**: Complete logging of all operations
- **Permission Checks**: Automatic permission validation

## Troubleshooting

### Common Issues

1. **Connection Failed**: Ensure DNS server role is installed and running
2. **Permission Denied**: Run PowerShell as Administrator
3. **Execution Policy**: Set appropriate PowerShell execution policy
4. **WPF Issues**: Ensure .NET Framework 4.7.2+ is installed

### Debug Mode

Enable debug mode for detailed logging:
```powershell
$global:AppConfig.DebugMode = $true
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description


## Support & Contact

- **Author**: Andreas Hepp
- **Website**: [PHscripts.de](https://github.com/PS-easyIT/)
- **GitHub**: [PS-easyIT/easyDNS](https://github.com/PS-easyIT/)
- **Version**: 0.2.27
- **Last Update**: 26.05.2025

## Acknowledgments

- Microsoft PowerShell Team for the robust PowerShell platform
- Windows DNS Server team for comprehensive DNS management cmdlets
- Community contributors for feedback and suggestions

---

*easyDNS v0.2.27 - Simplifying DNS Management with Modern Technology*
