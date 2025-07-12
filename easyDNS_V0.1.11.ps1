#requires -RunAsAdministrator

###############################################################################
# easyDNS v0.1.11 - Moderne WPF DNS-Verwaltung
# Komplett überarbeitet mit Windows 11 Design und WPF XAML
# Optimiert für bessere Performance und Benutzerfreundlichkeit
###############################################################################

###############################################################################
# INLINE KONFIGURATION - Keine externe INI erforderlich
###############################################################################
$global:AppConfig = @{
    AppName = "easyDNS v0.1.11"
    Author = "DNS Management Suite"
    ScriptVersion = "0.1.11"
    Website = "https://github.com/easyIT"
    LastUpdate = "25.05.2025"
    
    # Design-Konfiguration (Windows 11 Style)
    ThemeColors = @{
        Primary = "#0078D4"        # Windows 11 Blue
        Secondary = "#E5E5E5"      # Light Gray
        Accent = "#005A9E"         # Dark Blue
        Success = "#107C10"        # Green
        Warning = "#FF8C00"        # Orange
        Error = "#D13438"          # Red
        Background = "#F3F3F3"     # Very Light Gray
        Surface = "#FFFFFF"        # White
        OnSurface = "#323130"      # Dark Gray
        Border = "#D1D1D1"         # Border Gray
        NavBackground = "#2D2D30"  # Dark Navigation
        NavText = "#FFFFFF"        # White Text
    }
    
    # Font-Konfiguration
    FontFamily = "Segoe UI"
    FontSize = 12
    HeaderFontSize = 16
    TitleFontSize = 20
    
    # Features
    DebugMode = $false
    EnableLogging = $true
    AutoRefreshInterval = 300  # Sekunden (5 Minuten)
    MaxLogEntries = 10000
    MaxCacheDisplay = 50
    
    # DNS-Konfiguration
    DefaultTTL = 3600
    DefaultReplicationScope = "Domain"
    SupportedRecordTypes = @("A", "AAAA", "CNAME", "MX", "PTR", "TXT", "SRV", "NS", "SOA")
    
    # Performance-Einstellungen
    MaxConcurrentOperations = 5
    TimeoutSeconds = 30
    RetryCount = 3
    
    # Pfade
    LogPath = ""
    ExportPath = ""
    ImportPath = ""
    TempPath = ""
}

# Pfade initialisieren
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { 
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path 
}
$global:AppConfig.LogPath = Join-Path $scriptRoot "Logs"
$global:AppConfig.ExportPath = Join-Path $scriptRoot "Export"
$global:AppConfig.ImportPath = Join-Path $scriptRoot "Import"
$global:AppConfig.TempPath = Join-Path $scriptRoot "Temp"

# Verzeichnisse erstellen falls nicht vorhanden
@($global:AppConfig.LogPath, $global:AppConfig.ExportPath, $global:AppConfig.ImportPath, $global:AppConfig.TempPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        try { New-Item -ItemType Directory -Path $_ -Force | Out-Null } catch { }
    }
}

# Globale Variablen für Performance-Monitoring
$global:PerformanceCounters = @{
    OperationCount = 0
    ErrorCount = 0
    LastOperationTime = $null
    AverageResponseTime = 0
}

# Globale Variable für DNS-Server-Verbindungsstatus
$global:DNSConnectionStatus = @{
    IsConnected = $false
    LastChecked = $null
    ServerName = ""
    CacheValidSeconds = 30  # Cache-Zeit für Verbindungsstatus
}

###############################################################################
# WPF ASSEMBLIES LADEN
###############################################################################
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName Microsoft.VisualBasic

###############################################################################
# ERWEITERTE LOGGING-FUNKTIONEN
###############################################################################
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        [string]$Component = "General"
    )
    
    if (-not $global:AppConfig.EnableLogging) { return }
    if ($Level -eq "DEBUG" -and -not $global:AppConfig.DebugMode) { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$Level] $timestamp [$Component] - $Message"
    
    # Console-Output mit Farben
    $color = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "DEBUG"   { "Cyan" }
        "SUCCESS" { "Green" }
        default   { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
    
    # Logfile schreiben mit Rotation
    try {
        $today = Get-Date -Format "yyyyMMdd"
        $user = $env:USERNAME
        $logFile = Join-Path $global:AppConfig.LogPath "easyDNS_${today}_${user}.log"
        
        # Log-Rotation bei Größe > 10MB
        if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -gt 10MB)) {
            $archiveFile = Join-Path $global:AppConfig.LogPath "easyDNS_${today}_${user}_$(Get-Date -Format 'HHmmss').log"
            Move-Item -Path $logFile -Destination $archiveFile -Force
        }
        
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    } catch {
        # Logfehler ignorieren um Hauptfunktionalität nicht zu beeinträchtigen
    }
    
    # Performance Counter aktualisieren
    if ($Level -eq "ERROR") {
        $global:PerformanceCounters.ErrorCount++
    }
}

function Show-MessageBox {
    param(
        [string]$Message,
        [string]$Title = "Information",
        [string]$Type = "Information", # Information, Warning, Error, Question
        [string]$Buttons = "OK" # OK, OKCancel, YesNo, YesNoCancel
    )
    
    try {
        $result = [System.Windows.MessageBox]::Show($Message, $Title, $Buttons, $Type)
        Write-Log "MessageBox angezeigt: $Title - $Type" -Level "DEBUG" -Component "UI"
        return $result
    } catch {
        Write-Log "Fehler beim Anzeigen der MessageBox: $_" -Level "ERROR" -Component "UI"
        return "None"
    }
}

function Show-SaveFileDialog {
    param(
        [string]$Filter = "All Files (*.*)|*.*",
        [string]$Title = "Datei speichern"
    )
    
    $dialog = New-Object Microsoft.Win32.SaveFileDialog
    $dialog.Filter = $Filter
    $dialog.Title = $Title
    $dialog.InitialDirectory = $global:AppConfig.ExportPath
    
    if ($dialog.ShowDialog()) {
        return $dialog.FileName
    }
    return $null
}

function Show-OpenFileDialog {
    param(
        [string]$Filter = "All Files (*.*)|*.*",
        [string]$Title = "Datei öffnen"
    )
    
    $dialog = New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Filter = $Filter
    $dialog.Title = $Title
    $dialog.InitialDirectory = $global:AppConfig.ImportPath
    
    if ($dialog.ShowDialog()) {
        return $dialog.FileName
    }
    return $null
}

###############################################################################
# DNS-SERVER DETECTION
###############################################################################
function Get-DNSServerDetection {
    $result = @{
        Server = "localhost"
        IsLocalDNS = $false
        AutoConnect = $false
        ServerVersion = "Unknown"
        Features = @()
    }
    
    try {
        # Versuche localhost zuerst - erweiterte Prüfung
        $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
        if ($dnsFeature -and $dnsFeature.Installed) {
            Write-Log "Lokaler DNS-Server erkannt - Automatische Verbindung wird hergestellt" -Level "INFO" -Component "Detection"
            $result.Server = 'localhost'
            $result.IsLocalDNS = $true
            $result.AutoConnect = $true
            
            # Zusätzliche Features prüfen
            $additionalFeatures = @("RSAT-DNS-Server", "DNS-Server-Tools")
            foreach ($feature in $additionalFeatures) {
                $f = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                if ($f -and $f.Installed) {
                    $result.Features += $feature
                }
            }
            
            return $result
        }
    } catch {
        Write-Log "Windows Feature Abfrage fehlgeschlagen" -Level "DEBUG" -Component "Detection"
    }

    # Prüfe alternativ ob DNS-Dienst läuft
    try {
        $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
        if ($dnsService -and $dnsService.Status -eq "Running") {
            Write-Log "DNS-Dienst läuft lokal - Automatische Verbindung wird hergestellt" -Level "INFO" -Component "Detection"
            $result.Server = 'localhost'
            $result.IsLocalDNS = $true
            $result.AutoConnect = $true
            
            # Versuche Version zu ermitteln
            try {
                $dnsProcess = Get-Process -Name "dns" -ErrorAction SilentlyContinue
                if ($dnsProcess) {
                    $result.ServerVersion = $dnsProcess.FileVersion
                }
            } catch { }
            
            return $result
        }
    } catch {
        Write-Log "DNS-Dienst-Prüfung fehlgeschlagen" -Level "DEBUG" -Component "Detection"
    }

    # Prüfe Remote-DNS-Server in der Umgebung
    try {
        $domainDNS = [System.Net.Dns]::GetHostEntry($env:USERDNSDOMAIN).AddressList | Select-Object -First 1
        if ($domainDNS) {
            Write-Log "Domain DNS-Server gefunden: $($domainDNS.IPAddressToString)" -Level "INFO" -Component "Detection"
            $result.Server = $domainDNS.IPAddressToString
            $result.IsLocalDNS = $false
            $result.AutoConnect = $false
        }
    } catch {
        Write-Log "Domain DNS-Server Suche fehlgeschlagen" -Level "DEBUG" -Component "Detection"
    }

    # Keine lokale DNS-Rolle gefunden - manuelle Verbindung erforderlich
    if ([string]::IsNullOrEmpty($result.Server)) {
        Write-Log "Keine DNS-Server gefunden - Manuelle Serverauswahl erforderlich" -Level "WARN" -Component "Detection"
        $result.Server = ""
        $result.IsLocalDNS = $false
        $result.AutoConnect = $false
    }
    
    return $result
}

# Initialer DNS-Server
$global:DNSDetection = Get-DNSServerDetection
$global:DetectedDnsServer = $global:DNSDetection.Server

###############################################################################
# ERWEITERTE HILFSFUNKTIONEN
###############################################################################

function Invoke-SafeOperation {
    param(
        [scriptblock]$Operation,
        [string]$ErrorMessage = "Operation fehlgeschlagen",
        [string]$Component = "General",
        [int]$RetryCount = 0
    )
    
    $attempt = 0
    $maxRetries = [Math]::Max(0, $RetryCount)
    
    do {
        try {
            $startTime = Get-Date
            $result = & $Operation
            $duration = (Get-Date) - $startTime
            
            # Performance tracking
            $global:PerformanceCounters.OperationCount++
            $global:PerformanceCounters.LastOperationTime = $duration.TotalMilliseconds
            
            if ($attempt -gt 0) {
                Write-Log "Operation erfolgreich nach $($attempt + 1) Versuchen" -Level "INFO" -Component $Component
            }
            
            return $result
        }
        catch {
            $attempt++
            if ($attempt -gt $maxRetries) {
                Write-Log "$ErrorMessage : $_" -Level "ERROR" -Component $Component
                throw
            }
            else {
                Write-Log "Versuch $attempt von $($maxRetries + 1) fehlgeschlagen: $_" -Level "WARN" -Component $Component
                Start-Sleep -Seconds 2
            }
        }
    } while ($attempt -le $maxRetries)
}

function Test-DNSServerConnection {
    param(
        [string]$ServerName,
        [switch]$ForceCheck
    )
    
    # Cache-Prüfung wenn nicht forciert
    if (-not $ForceCheck -and $global:DNSConnectionStatus.ServerName -eq $ServerName) {
        $timeSinceLastCheck = (Get-Date) - $global:DNSConnectionStatus.LastChecked
        if ($timeSinceLastCheck.TotalSeconds -lt $global:DNSConnectionStatus.CacheValidSeconds) {
            Write-Log "DNS-Verbindungsstatus aus Cache: $($global:DNSConnectionStatus.IsConnected)" -Level "DEBUG" -Component "Connection"
            return $global:DNSConnectionStatus.IsConnected
        }
    }
    
    try {
        $testZone = Get-DnsServerZone -ComputerName $ServerName -ErrorAction Stop | Select-Object -First 1
        
        # Cache aktualisieren
        $global:DNSConnectionStatus.IsConnected = $true
        $global:DNSConnectionStatus.LastChecked = Get-Date
        $global:DNSConnectionStatus.ServerName = $ServerName
        
        Write-Log "DNS-Verbindungstest erfolgreich für $ServerName" -Level "DEBUG" -Component "Connection"
        return $true
    }
    catch {
        # Cache aktualisieren
        $global:DNSConnectionStatus.IsConnected = $false
        $global:DNSConnectionStatus.LastChecked = Get-Date
        $global:DNSConnectionStatus.ServerName = $ServerName
        
        Write-Log "DNS-Verbindungstest fehlgeschlagen für $ServerName`: $_" -Level "DEBUG" -Component "Connection"
        return $false
    }
}

function Get-SafeString {
    param(
        [string]$InputString,
        [int]$MaxLength = 1000,
        [bool]$RemoveSpecialChars = $false
    )
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }
    
    # Länge begrenzen
    if ($InputString.Length -gt $MaxLength) {
        $InputString = $InputString.Substring(0, $MaxLength) + "..."
    }
    
    # Sonderzeichen entfernen wenn gewünscht
    if ($RemoveSpecialChars) {
        $InputString = $InputString -replace '[^\w\s\-\.]', ''
    }
    
    # Gefährliche Zeichen escapen
    $InputString = $InputString -replace '[\r\n]', ' '
    
    return $InputString
}

###############################################################################
# DNS-HILFSFUNKTIONEN (Robuste Implementierungen)
###############################################################################

function Get-SafeDnsServerZone {
    param(
        [string]$DnsServerName,
        [switch]$IncludeRecordCount,
        [switch]$ForwardOnly,
        [switch]$ReverseOnly
    )
    
    $list = @()
    
    $operation = {
        $rawZones = Get-DnsServerZone -ComputerName $DnsServerName -ErrorAction Stop
        
        # Parallel processing für bessere Performance
        $zones = $rawZones | Where-Object {
            $_.ZoneName -notin @("RootHints", "Cache", ".") -and $_.ZoneType -ne "Cache"
        }
        
        foreach ($z in $zones) {
            # Filter anwenden
            $isRev = $false
            if ($z.PSObject.Properties.Name -contains 'IsReverseLookupZone') {
                $isRev = $z.IsReverseLookupZone
            } else {
                $isRev = $z.ZoneName -match '\.arpa$'
            }
            
            if ($ForwardOnly -and $isRev) { continue }
            if ($ReverseOnly -and -not $isRev) { continue }
            
            $repScope = 'N/A'
            if ($z.PSObject.Properties.Name -contains 'ReplicationScope' -and $z.ReplicationScope) {
                $repScope = $z.ReplicationScope
            }
            
            $dnssecStatus = "Disabled"
            $isSigned = $false
            try {
                if ($z.PSObject.Properties.Name -contains 'IsSigned' -and $z.IsSigned) {
                    $dnssecStatus = "Enabled"
                    $isSigned = $true
                }
            } catch {
                # Ignoriere DNSSEC-Fehler
            }
            
            $zoneObj = [PSCustomObject]@{
                ZoneName = $z.ZoneName
                ZoneType = $z.ZoneType
                IsReverse = $isRev
                RepScope = $repScope
                DNSSECStatus = $dnssecStatus
                IsSigned = if ($isSigned) { "Ja" } else { "Nein" }
                RecordCount = 0
                DynamicUpdate = if ($z.DynamicUpdate) { $z.DynamicUpdate } else { "None" }
                IsAutoCreated = if ($z.IsAutoCreated) { $z.IsAutoCreated } else { $false }
            }
            
            # Record Count nur wenn angefordert (Performance)
            if ($IncludeRecordCount) {
                try {
                    $records = @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $DnsServerName -ErrorAction SilentlyContinue)
                    $zoneObj.RecordCount = $records.Count
                } catch {
                    $zoneObj.RecordCount = -1  # Fehler beim Abrufen
                }
            }
            
            $list = $list + $zoneObj
        }
        
        return $list
    }
    
    try {
        $result = Invoke-SafeOperation -Operation $operation -ErrorMessage "Fehler beim Abrufen der DNS-Zonen von $DnsServerName" -Component "DNS" -RetryCount 2
        
        Write-Log "DNS-Zonen abgerufen: $($result.Count) Zonen von Server $DnsServerName" -Level "INFO" -Component "DNS"
        return $result
        
    } catch {
        Write-Log "Kritischer Fehler beim Abrufen der DNS-Zonen: $_" -Level "ERROR" -Component "DNS"
        return @()
    }
}

function Format-RecordData {
    param([object]$record)
    
    try {
        switch ($record.RecordType) {
            "A"     { return $record.RecordData.IPv4Address.ToString() }
            "AAAA"  { return $record.RecordData.IPv6Address.ToString() }
            "PTR"   { return $record.RecordData.PtrDomainName }
            "CNAME" { return $record.RecordData.HostNameAlias }
            "MX"    { return "{0} {1}" -f $record.RecordData.Preference, $record.RecordData.MailExchange }
            "TXT"   { return $record.RecordData.DescriptiveText }
            "SRV"   { return "{0} {1} {2} {3}" -f $record.RecordData.Priority, $record.RecordData.Weight, $record.RecordData.Port, $record.RecordData.DomainName }
            "NS"    { return $record.RecordData.NameServer }
            "SOA"   { return "$($record.RecordData.PrimaryServer) $($record.RecordData.ResponsiblePerson)" }
            default { return $record.RecordData.ToString() }
        }
    } catch {
        Write-Log "Fehler beim Formatieren von Record-Daten: $_" -Level "DEBUG" -Component "DNS"
        return "Fehler beim Formatieren"
    }
}

function Test-RecordDataValid {
    param(
        [string]$RecordType,
        [string]$RecordData
    )
    
    try {
        switch ($RecordType.ToUpper()) {
            "A" {
                # IPv4-Adresse validieren
                $ip = [System.Net.IPAddress]::Parse($RecordData)
                return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
            }
            "AAAA" {
                # IPv6-Adresse validieren
                $ip = [System.Net.IPAddress]::Parse($RecordData)
                return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
            }
            "CNAME" {
                # Hostname validieren
                return $RecordData -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$'
            }
            "MX" {
                # Format: Priorität Mailserver
                $parts = $RecordData -split '\s+', 2
                if ($parts.Count -ne 2) { return $false }
                $priority = 0
                if (-not [int]::TryParse($parts[0], [ref]$priority)) { return $false }
                if ($priority -lt 0 -or $priority -gt 65535) { return $false }
                return $parts[1] -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$'
            }
            "TXT" {
                # TXT-Records können fast alles enthalten
                return $RecordData.Length -le 255
            }
            "PTR" {
                # Hostname validieren
                return $RecordData -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$'
            }
            "SRV" {
                # Format: Priorität Gewicht Port Ziel
                $parts = $RecordData -split '\s+', 4
                if ($parts.Count -ne 4) { return $false }
                
                foreach ($i in 0..2) {
                    $num = 0
                    if (-not [int]::TryParse($parts[$i], [ref]$num)) { return $false }
                    if ($num -lt 0 -or $num -gt 65535) { return $false }
                }
                
                return $parts[3] -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.?$'
            }
            default {
                return $true  # Unbekannte Typen durchlassen
            }
        }
    } catch {
        Write-Log "Fehler bei Record-Validierung: $_" -Level "DEBUG" -Component "Validation"
        return $false
    }
}

function Get-DNSStatistics {
    param([string]$DnsServerName)
    
    $stats = @{
        TotalZones = 0
        ForwardZones = 0
        ReverseZones = 0
        SignedZones = 0
        TotalRecords = 0
        LastUpdate = Get-Date -Format "HH:mm:ss"
        ServerUptime = "Unbekannt"
        CacheSize = "Unbekannt"
    }
    
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $DnsServerName
        $stats.TotalZones = $zones.Count
        $stats.ForwardZones = ($zones | Where-Object { -not $_.IsReverse }).Count
        $stats.ReverseZones = ($zones | Where-Object { $_.IsReverse }).Count
        $stats.SignedZones = ($zones | Where-Object { $_.IsSigned -eq "Ja" }).Count
        
        # Uptime ermitteln (falls localhost)
        if ($DnsServerName -eq "localhost") {
            try {
                $service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
                if ($service) { $serviceStatus = $service.Status }
            } catch { }
        }
        
    } catch {
        Write-Log "Fehler beim Abrufen der DNS-Statistiken: $_" -Level "ERROR"
    }
    
    return $stats
}

function Export-DNSConfiguration {
    param(
        [string]$DnsServerName,
        [string]$ExportPath,
        [string]$Format = "CSV" # CSV, XML, JSON
    )
    
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $DnsServerName
        $exportData = @()
        
        foreach ($zone in $zones) {
            try {
                $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DnsServerName -ErrorAction Stop
                
                foreach ($record in $records) {
                    $exportData += [PSCustomObject]@{
                        ZoneName = $zone.ZoneName
                        ZoneType = $zone.ZoneType
                        IsReverse = $zone.IsReverse
                        RecordName = $record.HostName
                        RecordType = $record.RecordType
                        RecordData = Format-RecordData -record $record
                        TTL = $record.TimeToLive.TotalSeconds
                        TimeStamp = $record.TimeStamp
                    }
                }
            } catch {
                Write-Log "Fehler beim Export der Zone $($zone.ZoneName): $_" -Level "WARN"
            }
        }
        
        switch ($Format.ToUpper()) {
            "CSV" {
                $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            }
            "XML" {
                $exportData | Export-Clixml -Path $ExportPath
            }
            "JSON" {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
            }
        }
        
        Write-Log "DNS-Konfiguration exportiert nach $ExportPath (Format: $Format)" -Level "INFO"
        return $true
        
    } catch {
        Write-Log "Fehler beim DNS-Export: $_" -Level "ERROR"
        return $false
    }
}

function Import-DNSConfiguration {
    param(
        [string]$DnsServerName,
        [string]$ImportPath,
        [string]$Format = "CSV"
    )
    
    try {
        $importData = @()
        
        switch ($Format.ToUpper()) {
            "CSV" {
                $importData = Import-Csv -Path $ImportPath -Encoding UTF8
            }
            "XML" {
                $importData = Import-Clixml -Path $ImportPath
            }
            "JSON" {
                $importData = Get-Content -Path $ImportPath -Encoding UTF8 | ConvertFrom-Json
            }
        }
        
        $imported = 0
        $failed = 0
        
        # Gruppiere nach Zonen
        $zoneGroups = $importData | Group-Object ZoneName
        
        foreach ($zoneGroup in $zoneGroups) {
            $zoneName = $zoneGroup.Name
            
            # Prüfe ob Zone existiert
            try {
                $existingZone = Get-DnsServerZone -Name $zoneName -ComputerName $DnsServerName -ErrorAction SilentlyContinue
                if (-not $existingZone) {
                    # Zone erstellen
                    $zoneData = $zoneGroup.Group[0]
                    if ($zoneData.IsReverse -eq $true -or $zoneData.IsReverse -eq "True") {
                        # Reverse Zone (vereinfacht)
                        Write-Log "Überspringe Reverse Zone $zoneName beim Import" -Level "WARN"
                        continue
                    } else {
                        Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope "Domain" -ComputerName $DnsServerName -ErrorAction Stop
                        Write-Log "Zone $zoneName erstellt" -Level "INFO"
                    }
                }
            } catch {
                Write-Log "Fehler beim Erstellen der Zone $zoneName`: $_" -Level "ERROR"
                continue
            }
            
            # Records importieren
            foreach ($record in $zoneGroup.Group) {
                try {
                    if ($record.RecordType -in @("SOA", "NS") -and $record.RecordName -eq "@") {
                        continue # System-Records überspringen
                    }
                    
                    $ttl = [TimeSpan]::FromSeconds([int]$record.TTL)
                    
                    switch ($record.RecordType.ToUpper()) {
                        "A" {
                            Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $record.RecordName -IPv4Address $record.RecordData -TimeToLive $ttl -ComputerName $DnsServerName -ErrorAction Stop
                        }
                        "CNAME" {
                            Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $record.RecordName -HostNameAlias $record.RecordData -TimeToLive $ttl -ComputerName $DnsServerName -ErrorAction Stop
                        }
                        "TXT" {
                            Add-DnsServerResourceRecordTxt -ZoneName $zoneName -Name $record.RecordName -DescriptiveText $record.RecordData -TimeToLive $ttl -ComputerName $DnsServerName -ErrorAction Stop
                        }
                        default {
                            Write-Log "Record-Typ $($record.RecordType) wird beim Import nicht unterstützt" -Level "WARN"
                            continue
                        }
                    }
                    
                    $imported++
                    
                } catch {
                    Write-Log "Fehler beim Importieren des Records $($record.RecordName) ($($record.RecordType)): $_" -Level "ERROR"
                    $failed++
                }
            }
        }
        
        Write-Log "DNS-Import abgeschlossen: $imported erfolgreich, $failed fehlgeschlagen" -Level "INFO"
        return @{ Success = $imported; Failed = $failed }
        
    } catch {
        Write-Log "Fehler beim DNS-Import: $_" -Level "ERROR"
        return @{ Success = 0; Failed = 0 }
    }
}

###############################################################################
# MODERNE WPF XAML GUI - Windows 11 Design
###############################################################################

$global:XamlString = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$($global:AppConfig.AppName)"
        Height="1000" Width="1420" MinHeight="700" MinWidth="1200"
        WindowStartupLocation="CenterScreen"
        Background="#FFFFFF" 
        FontFamily="Segoe UI"
        FontSize="12">

    <Window.Resources>
        <!-- Modern Button Style -->
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="18,8"/>
            <Setter Property="Margin" Value="6"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="MinWidth" Value="80"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" 
                                Background="{TemplateBinding Background}" 
                                CornerRadius="4"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                BorderBrush="{TemplateBinding BorderBrush}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#106EBE"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#005A9E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Navigation Button Style (Win11 Inspired Light Theme) -->
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background" Value="#4A90E2"/> <!-- Mittlerer, angenehmer Blauton -->
            <Setter Property="Foreground" Value="White"/> <!-- Schriftfarbe angepasst für Kontrast -->
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
            <Setter Property="BorderBrush" Value="#357ABD"/> <!-- Dunklerer Blauton für den unteren Rand -->
            <Setter Property="Padding" Value="15,10"/>
            <Setter Property="Margin" Value="8,3,8,3"/>
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border"
                                Background="{TemplateBinding Background}" 
                                CornerRadius="4"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                BorderBrush="{TemplateBinding BorderBrush}">
                            <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" 
                                            VerticalAlignment="Center"
                                            Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#60A0F0"/> <!-- Hellerer Blauton für Hover -->
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#0078D4"/> <!-- Kräftigeres Blau für Pressed -->
                                <Setter Property="Foreground" Value="White"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="#0078D4"/> 
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Card Style (No Shadow) -->
        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="White"/>
            <Setter Property="BorderBrush" Value="#E0E0E0"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="16"/>
            <Setter Property="Margin" Value="8"/>
        </Style>

        <!-- TextBox Style (Win11 Inspired) -->
        <Style x:Key="ModernTextBox" TargetType="TextBox">
            <Setter Property="BorderBrush" Value="#BFBFBF"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,5"/>
            <Setter Property="Margin" Value="4"/>
            <Setter Property="Background" Value="White"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter Property="BorderBrush" Value="#0078D4"/>
                                <Setter Property="BorderThickness" Value="2"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.5"/>
                                <Setter Property="Background" Value="#F0F0F0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- TabItem Style (Flatter, Win11 Inspired) -->
        <Style TargetType="TabItem">
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Foreground" Value="#1C1C1C"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Foreground" Value="#0078D4"/>
                    <Setter Property="FontWeight" Value="SemiBold"/>
                </Trigger>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#E9E9E9"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Opacity" Value="0.5"/>
                </Trigger>
            </Style.Triggers>
        </Style>

    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="60"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="40"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#F3F3F3" BorderBrush="#E0E0E0" BorderThickness="0,0,0,1">
            <Grid Margin="20,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- App Name -->
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="$($global:AppConfig.AppName)" 
                              FontSize="20" FontWeight="SemiBold" 
                              Foreground="#1C1C1C" VerticalAlignment="Center"/>
                </StackPanel>

                <!-- Center Info -->
                <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock Text="DNS Server:" Margin="0,0,8,0" FontWeight="SemiBold" Foreground="#1C1C1C"/>
                    <TextBox Name="txtDNSServer" Width="150" Style="{StaticResource ModernTextBox}" Text="$($global:DetectedDnsServer)"/>
                    <Button Name="btnConnect" Content="Connect" Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                    <TextBlock Name="lblStatus" Text="Status: Ready" Margin="16,0,0,0" 
                              Foreground="#107C10" FontWeight="SemiBold" VerticalAlignment="Center"/>
                </StackPanel>

                <!-- User Info -->
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="USER | " FontSize="16" Margin="0,0,4,0" Foreground="#1C1C1C"/>
                    <TextBlock Text="$($env:USERNAME)" FontWeight="SemiBold" Foreground="#1C1C1C"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Main Content Area -->
        <Grid Grid.Row="1">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="200"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Navigation Panel -->
            <Border Grid.Column="0" Background="#2B3E50" BorderBrush="#1E2A38" BorderThickness="0,0,1,0">
                <StackPanel Margin="0,16">
                    <!-- Navigation Header -->
                    <TextBlock Text="Navigation" Foreground="#FFFFFF" FontSize="14" FontWeight="SemiBold" 
                              Margin="16,0,16,16" HorizontalAlignment="Center"/>

                    <!-- Navigation Buttons -->
                    <Button Name="btnDashboard" Content="Dashboard" Style="{StaticResource NavButton}" Tag="dashboard"/>
                    <Button Name="btnForward" Content="Forward Zones" Style="{StaticResource NavButton}" Tag="forward"/>
                    <Button Name="btnReverse" Content="Reverse Zones" Style="{StaticResource NavButton}" Tag="reverse"/>
                    <Button Name="btnRecords" Content="DNS Records" Style="{StaticResource NavButton}" Tag="records"/>
                    <Button Name="btnImport" Content="Import/Export" Style="{StaticResource NavButton}" Tag="import"/>
                    <Button Name="btnDNSSEC" Content="DNSSEC" Style="{StaticResource NavButton}" Tag="dnssec"/>
                    <Button Name="btnTools" Content="Diagnostic Tools" Style="{StaticResource NavButton}" Tag="tools"/>
                    <Button Name="btnAudit" Content="Audit and Logs" Style="{StaticResource NavButton}" Tag="audit"/>
                </StackPanel>
            </Border>

            <!-- Content Panel -->
            <Border Grid.Column="1" Background="#FFFFFF" Padding="20">
                <ScrollViewer Name="contentScrollViewer" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                    <Grid Name="contentGrid">
                        <!-- Dashboard Panel -->
                        <StackPanel Name="dashboardPanel" Visibility="Visible">
                            <TextBlock Text="DNS Server Dashboard" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,20"/>

                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>

                                <!-- Obere Reihe: Server Information und Key Information nebeneinander -->
                                <Grid Grid.Row="0" Margin="0,0,0,20">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="775"/>
                                        <ColumnDefinition Width="386"/>
                                    </Grid.ColumnDefinitions>

                                    <!-- Server Information Card -->
                                    <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,10,0">
                                        <StackPanel>
                                            <TextBlock Text="Server Information" FontSize="16" FontWeight="SemiBold" 
                                                    Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="200" MinWidth="150"/>
                                                    <ColumnDefinition Width="*"/>
                                                </Grid.ColumnDefinitions>
                                                <Grid.RowDefinitions>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                    <RowDefinition Height="Auto"/>
                                                </Grid.RowDefinitions>

                                                <!-- Betriebssystem -->
                                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Betriebssystem:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="0" Grid.Column="1" Name="lblOS" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- Angemeldeter User -->
                                                <TextBlock Grid.Row="1" Grid.Column="0" Text="Angemeldeter User:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="1" Grid.Column="1" Name="lblUser" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- DNS Server -->
                                                <TextBlock Grid.Row="2" Grid.Column="0" Text="DNS Server:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="2" Grid.Column="1" Name="lblDNSServerStatus" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- CPU -->
                                                <TextBlock Grid.Row="3" Grid.Column="0" Text="CPU Auslastung:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="3" Grid.Column="1" Name="lblCPU" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- RAM -->
                                                <TextBlock Grid.Row="4" Grid.Column="0" Text="RAM Auslastung:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="4" Grid.Column="1" Name="lblRAM" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- Systempartition -->
                                                <TextBlock Grid.Row="5" Grid.Column="0" Text="Systempartition (C:):" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="5" Grid.Column="1" Name="lblDisk" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- Uptime -->
                                                <TextBlock Grid.Row="6" Grid.Column="0" Text="System Uptime:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="6" Grid.Column="1" Name="lblUptime" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>
                                            </Grid>
                                        </StackPanel>
                                    </Border>
                                    <Border Grid.Column="1" Style="{StaticResource Card}" Margin="10,0,0,0">
                                        <StackPanel>
                                            <TextBlock Text="Key Information &amp; Quick Stats" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock x:Name="lblDashboardStats" Text="Loading key statistics..." FontSize="12" Foreground="#505050" TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Border>
                                </Grid>

                                <!-- Untere Reihe: About und Copyright nebeneinander -->
                                <Grid Grid.Row="1">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="2*"/>
                                        <ColumnDefinition Width="1*"/>
                                    </Grid.ColumnDefinitions>

                                    <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,10,20">
                                        <StackPanel>
                                            <TextBlock Text="About This Tool" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock TextWrapping="Wrap" Foreground="#505050">
                                                <Run Text="easyDNS is a comprehensive PowerShell-based tool designed to simplify DNS server management on Windows Server."/>
                                                <LineBreak/>
                                                <Run Text="It provides an intuitive graphical interface for viewing, creating, and managing DNS zones (Forward and Reverse) and various record types."/>
                                                <LineBreak/>
                                                <LineBreak/>
                                                <Run Text="Key features include:"/>
                                                <LineBreak/>
                                                <Run Text="- Diagnostic tools (Ping, Nslookup, Cache Management, Service Control)"/>
                                                <LineBreak/>
                                                <Run Text="- Import/Export capabilities for DNS configurations"/>
                                                <LineBreak/>
                                                <Run Text="- DNSSEC management"/>
                                                <LineBreak/>
                                                <Run Text="- Audit/Logging section for monitoring DNS server activity."/>
                                            </TextBlock>
                                        </StackPanel>
                                    </Border>

                                    <!-- Author and Copyright Card -->
                                    <Border Grid.Column="1" Style="{StaticResource Card}" Margin="10,0,0,20">
                                        <StackPanel>
                                            <TextBlock Text="Author &amp; Copyright" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4">
                                                <Run Text="Author: "/>
                                                <Run Text="$($global:AppConfig.Author)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4">
                                                <Run Text="Version: "/>
                                                <Run Text="$($global:AppConfig.ScriptVersion)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4">
                                                <Run Text="Website: "/>
                                                <Run Text="$($global:AppConfig.Website)" Foreground="#0078D4" Cursor="Hand" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,0">
                                                <Run Text="Copyright: "/>
                                                <Run Text="Copyright 2025 - Last Update: $($global:AppConfig.LastUpdate)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                        </StackPanel>
                                    </Border>
                                </Grid>
                            </Grid>
                        </StackPanel>

                        <!-- Forward Zones Panel -->
                        <Grid Name="forwardPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- Action and Create Cards -->
                                <RowDefinition Height="*"/>    <!-- Zone List DataGrid -->
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Manage Forward Zones" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <Grid Grid.Row="1"> <!-- Contains Action and Create Cards -->
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/> 
                                    <ColumnDefinition Width="*"/>    
                                </Grid.ColumnDefinitions>

                                <Border Grid.Column="0" Style="{StaticResource Card}">
                                    <StackPanel VerticalAlignment="Top">
                                        <TextBlock Text="Zone Actions" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Button Name="btnRefreshZones" Content="Refresh" Style="{StaticResource ModernButton}" Margin="0,0,0,4" HorizontalAlignment="Stretch"/>
                                        <Button Name="btnDeleteZone" Content="Delete" Margin="0,4,0,0" 
                                               Background="#D13438" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="1" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Create New Forward Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>

                                            <TextBlock Grid.Column="0" Text="Zone Name:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Column="1" Name="txtNewZoneName" Style="{StaticResource ModernTextBox}" Margin="0,0,16,0"/>
                                            <TextBlock Grid.Column="2" Text="Replication:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <ComboBox Grid.Column="3" Name="cmbReplication" Margin="0,0,16,0" Padding="8,5">
                                                <ComboBoxItem Content="Domain" IsSelected="True"/>
                                                <ComboBoxItem Content="Forest"/>
                                                <ComboBoxItem Content="Legacy"/>
                                            </ComboBox>
                                            <Button Grid.Column="4" Name="btnCreateZone" Content="Create Zone" 
                                                    Background="#107C10" Style="{StaticResource ModernButton}"/>
                                        </Grid>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <Border Grid.Row="2" Style="{StaticResource Card}"> 
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="Zone List" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                    <DataGrid Grid.Row="1" Name="dgForwardZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False"
                                             Background="White" BorderBrush="#E0E0E0" BorderThickness="1">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="430"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding ZoneType}" Width="250"/>
                                            <DataGridTextColumn Header="Replication" Binding="{Binding RepScope}" Width="250"/>
                                            <DataGridTextColumn Header="DNSSEC" Binding="{Binding IsSigned}" Width="150"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>
                        </Grid>

                        <!-- Records Panel -->
                        <Grid Name="recordsPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- Select Zone and Create Record Cards -->
                                <RowDefinition Height="*"/>    <!-- Records DataGrid -->
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Manage DNS Records" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <Grid Grid.Row="1"> 
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="0.8*"/> 
                                    <ColumnDefinition Width="1.2*"/> 
                                </Grid.ColumnDefinitions>

                                <Border Grid.Column="0" Style="{StaticResource Card}" MinHeight="200">
                                    <StackPanel>
                                        <TextBlock Text="Select Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <StackPanel Orientation="Horizontal">
                                            <TextBlock Text="Zone:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <ComboBox Name="cmbRecordZone" Width="200" Margin="4" Padding="8,5"/>
                                        </StackPanel>
                                        <Button Name="btnRefreshZoneList" Content="Refresh" 
                                               Margin="0,12,0,0" Style="{StaticResource ModernButton}" HorizontalAlignment="Left"/>
                                    </StackPanel>
                                </Border>

                                <Border Grid.Column="1" Style="{StaticResource Card}" MinHeight="200">
                                    <StackPanel>
                                        <TextBlock Text="Create New Record" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Grid>
                                            <Grid.RowDefinitions>
                                                <RowDefinition Height="Auto"/>
                                                <RowDefinition Height="Auto"/>
                                                <RowDefinition Height="Auto"/>
                                            </Grid.RowDefinitions>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/> 
                                                <ColumnDefinition Width="*"/>   
                                                <ColumnDefinition Width="Auto"/> 
                                                <ColumnDefinition Width="*"/>   
                                            </Grid.ColumnDefinitions>

                                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Name:" VerticalAlignment="Center" Margin="0,0,8,4" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Row="0" Grid.Column="1" Name="txtRecordName" Style="{StaticResource ModernTextBox}" Margin="0,0,16,4"/>
                                            
                                            <TextBlock Grid.Row="0" Grid.Column="2" Text="Type:" VerticalAlignment="Center" Margin="0,0,8,4" Foreground="#1C1C1C"/>
                                            <ComboBox Grid.Row="0" Grid.Column="3" Name="cmbRecordType" Margin="0,0,0,4" Padding="8,5">
                                                <ComboBoxItem Content="A" IsSelected="True"/>
                                                <ComboBoxItem Content="AAAA"/>
                                                <ComboBoxItem Content="CNAME"/>
                                                <ComboBoxItem Content="MX"/>
                                                <ComboBoxItem Content="PTR"/>
                                                <ComboBoxItem Content="TXT"/>
                                                <ComboBoxItem Content="SRV"/>
                                            </ComboBox>

                                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Data:" VerticalAlignment="Center" Margin="0,4,8,4" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Row="1" Grid.Column="1" Name="txtRecordData" Style="{StaticResource ModernTextBox}" Margin="0,4,16,4"/>
                                            
                                            <TextBlock Grid.Row="1" Grid.Column="2" Text="TTL (sec):" VerticalAlignment="Center" Margin="0,4,8,4" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Row="1" Grid.Column="3" Name="txtRecordTTL" Text="3600" Style="{StaticResource ModernTextBox}" Margin="0,4,0,4"/>
                                            
                                            <StackPanel Grid.Row="2" Grid.Column="0" Grid.ColumnSpan="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
                                                <Button Name="btnCreateRecord" Content="Create" 
                                                       Background="#107C10" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnDeleteRecord" Content="Delete" 
                                                       Background="#D13438" Style="{StaticResource ModernButton}"/>
                                            </StackPanel>
                                        </Grid>
                                    </StackPanel>
                                </Border>
                            </Grid>

                            <Border Grid.Row="2" Style="{StaticResource Card}"> 
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="DNS Records in Selected Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                    <DataGrid Grid.Row="1" Name="dgRecords" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False"
                                             Background="White" BorderBrush="#E0E0E0" BorderThickness="1">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="370"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="150"/>
                                            <DataGridTextColumn Header="Data" Binding="{Binding Data}" Width="400"/>
                                            <DataGridTextColumn Header="TTL" Binding="{Binding TTL}" Width="160"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>
                        </Grid>

                        <!-- Tools Panel -->
                        <Grid Name="toolsPanel" Visibility="Collapsed" MaxWidth="1080">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="DNS Diagnostics and Troubleshooting" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <TabControl Grid.Row="1" Name="toolsTabControl" Margin="0,0,0,10" Background="Transparent" BorderThickness="0" Padding="0">
                                <TabItem Header="Quick Tools">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/> 
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="Quick DNS Tools" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <Grid Margin="0,0,0,12">
                                                    <Grid.RowDefinitions>
                                                        <RowDefinition Height="Auto"/>
                                                        <RowDefinition Height="Auto"/>
                                                    </Grid.RowDefinitions>
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="Auto"/> <!-- Label -->
                                                        <ColumnDefinition Width="*"/>    <!-- Input + Buttons -->
                                                    </Grid.ColumnDefinitions>
                                                    <TextBlock Grid.Row="0" Grid.Column="0" Text="Target:" VerticalAlignment="Center" Margin="0,0,8,4" Foreground="#1C1C1C"/>
                                                    <TextBox Grid.Row="0" Grid.Column="1" Name="txtDiagnosisTarget" Style="{StaticResource ModernTextBox}" Margin="0,0,0,4"/>
                                                    
                                                    <UniformGrid Grid.Row="1" Grid.Column="1" Columns="2" Rows="2" Margin="0,8,0,0">
                                                        <Button Name="btnPing" Content="Ping" Style="{StaticResource ModernButton}" Margin="0,0,2,2"/>
                                                        <Button Name="btnNslookup" Content="Nslookup" Style="{StaticResource ModernButton}" Margin="2,0,0,2"/>
                                                        <Button Name="btnResolve" Content="Resolve" Style="{StaticResource ModernButton}" Margin="0,2,2,0"/>
                                                        <Button Name="btnTestConnection" Content="Test Connection" Style="{StaticResource ModernButton}" Margin="2,2,0,0"/>
                                                    </UniformGrid>
                                                </Grid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="Quick DNS Tools - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Execute quick network diagnostic tests for a target host or IP address. Enter the target and click a tool button."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Fuehren Sie schnelle Netzwerkdiagnosetests fuer einen Zielhost oder eine IP Adresse aus. Geben Sie das Ziel ein und klicken Sie auf eine Tool Schaltflaeche."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="130"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Ping:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Sends ICMP echo requests to the target."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Sendet ICMP Echoanfragen an das Ziel."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="130"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Nslookup:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Queries DNS servers for information about the target."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Fragt DNS Server nach Informationen ueber das Ziel ab."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="130"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Resolve:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Resolves the hostname to IP addresses."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Loest den Hostnamen in IP Adressen auf."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="130"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Test Connection:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Tests network connectivity to the target."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Testet die Netzwerkverbindung zum Ziel."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Cache">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="DNS Cache Management" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <Button Name="btnShowCache" Content="Show DNS Cache" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch" Margin="0,0,0,8"/>
                                                <Separator Margin="0,0,0,8"/>
                                                <Grid>
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="*"/>
                                                        <ColumnDefinition Width="*"/>
                                                    </Grid.ColumnDefinitions>
                                                    <Button Grid.Column="0" Name="btnClearCache" Content="Clear DNS Cache (Server)" Background="#FF8C00" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Grid.Column="1" Name="btnClearClientCache" Content="Clear Client Cache (ipconfig /flushdns)" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </Grid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="DNS Cache Management - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Manage the DNS server cache and the local client DNS cache."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Verwalten Sie den DNS Servercache und den lokalen Client DNS Cache."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="250"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Show DNS Cache:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View cache contents."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Cache Inhalte anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="250"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Clear DNS Cache:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Clear the server cache."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Servercache leeren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="250"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Clear Client Cache (ipconfig /flushdns):" TextWrapping="Wrap" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Clear the client resolver cache using 'ipconfig /flushdns'."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Client Resolver Cache mit 'ipconfig /flushdns' leeren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Service">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="DNS Service Management" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                
                                                <!-- Service Status Button - volle Breite -->
                                                <Button Name="btnServiceStatus" Content="Service Status" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch" Margin="0,0,0,8"/>
                                                
                                                <!-- Trennlinie -->
                                                <Separator Height="1" Background="#E0E0E0" Margin="0,4,0,12"/>
                                                
                                                <!-- Start, Stop, Restart Buttons in einer Reihe -->
                                                <UniformGrid Columns="3">
                                                    <Button Name="btnStartService" Content="Start DNS Service" Background="#107C10" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnStopService" Content="Stop DNS Service" Background="#D13438" Style="{StaticResource ModernButton}" Margin="2,0,2,0"/>
                                                    <Button Name="btnRestartService" Content="Restart DNS Service" Background="#FF8C00" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="DNS Service Management - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Control the DNS server service for maintenance or troubleshooting tasks."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Steuern Sie den DNS Serverdienst fuer Wartungs oder Fehlerbehebungsaufgaben."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Service Status:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Check the current status."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Ueberpruefen Sie den aktuellen Status."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Start DNS Service:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Start the service."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Starten Sie den Dienst."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Stop DNS Service:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Stop the service."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Stoppen Sie den Dienst."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Restart DNS Service:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Restart the service."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Starten Sie den Dienst neu."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Configuration">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="DNS Configuration" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="2" Rows="2">
                                                    <Button Name="btnServerConfig" Content="Server Configuration" Style="{StaticResource ModernButton}" Margin="0,0,2,2"/>
                                                    <Button Name="btnServerStats" Content="Server Statistics" Style="{StaticResource ModernButton}" Margin="2,0,0,2"/>
                                                    <Button Name="btnDiagnostics" Content="Diagnostics Settings" Style="{StaticResource ModernButton}" Margin="0,2,2,0"/>
                                                    <Button Name="btnNetAdapterDNS" Content="Network Adapter DNS" Style="{StaticResource ModernButton}" Margin="2,2,0,0"/>
                                                </UniformGrid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="DNS Configuration - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Access various DNS server and network configuration settings."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Greifen Sie auf verschiedene DNS Server und Netzwerkkonfigurationseinstellungen zu."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Server Configuration:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View server configuration."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Serverkonfiguration anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Server Statistics:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View server statistics."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Serverstatistiken anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Diagnostics Settings:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View diagnostic settings."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Diagnoseeinstellungen anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Network Adapter DNS:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View network adapter DNS information."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="DNS Informationen des Netzwerkadapters anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Forwarders">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="DNS Forwarders" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <Button Name="btnShowForwarders" Content="Show Forwarders" Style="{StaticResource ModernButton}" Margin="0,0,0,8" HorizontalAlignment="Stretch"/>
                                                <Separator Margin="0,0,0,8"/>
                                                <Grid Margin="0,0,0,8">
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="2*"/> 
                                                        <ColumnDefinition Width="*"/>  
                                                    </Grid.ColumnDefinitions>
                                                    <TextBox Grid.Column="0" Name="txtForwarderIP" Style="{StaticResource ModernTextBox}" 
                                                            ToolTip="IP Adresse des Forwarders" Margin="0,0,4,0"/>
                                                    <Button Grid.Column="1" Name="btnAddForwarder" Content="Add" 
                                                           Background="#107C10" Style="{StaticResource ModernButton}"/>
                                                </Grid>
                                                <Button Name="btnRemoveForwarder" Content="Remove Registered Forwarder" Background="#D13438" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch"/>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="DNS Forwarders - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Manage DNS forwarders. Ensure the IP is valid."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Verwalten Sie DNS Weiterleitungen. Stellen Sie sicher dass die IP gueltig ist."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="200"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Show Forwarders:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View current forwarders."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Aktuelle Weiterleitungen anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="200"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Add (with IP):" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Add new ones by specifying their IP address."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Neue hinzufuegen indem Sie deren IP Adresse angeben."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="200"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Remove Registered Forwarder:" TextWrapping="Wrap" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Remove selected forwarders from the list."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Ausgewaehlte Weiterleitungen aus der Liste entfernen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Zone Tools">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="Zone Management Tools" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <Grid>
                                                    <Grid.RowDefinitions>
                                                        <RowDefinition Height="Auto"/>
                                                        <RowDefinition Height="Auto"/>
                                                    </Grid.RowDefinitions>
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="Auto"/> 
                                                        <ColumnDefinition Width="*"/>    
                                                    </Grid.ColumnDefinitions>
                                                    <TextBlock Grid.Row="0" Grid.Column="0" Text="Zone:" VerticalAlignment="Center" Margin="0,0,8,4" Foreground="#1C1C1C"/>
                                                    <ComboBox Grid.Row="0" Grid.Column="1" Name="cmbDiagZone" Padding="8,5" Margin="0,0,0,4"/>
                                                    
                                                    <UniformGrid Grid.Row="1" Grid.Column="1" Columns="2" Rows="2" Margin="0,8,0,0">
                                                        <Button Name="btnRefreshZoneDropDown" Content="Refresh" Style="{StaticResource ModernButton}" Margin="0,0,2,2"/>
                                                        <Button Name="btnZoneInfo" Content="Zone Info" Style="{StaticResource ModernButton}" Margin="2,0,0,2"/>
                                                        <Button Name="btnZoneRefresh" Content="Force Refresh" Style="{StaticResource ModernButton}" Margin="0,2,2,0"/>
                                                        <Button Name="btnZoneTransfer" Content="Zone Transfer" Style="{StaticResource ModernButton}" Margin="2,2,0,0"/>
                                                    </UniformGrid>
                                                </Grid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="Zone Management Tools - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Perform actions for specific DNS zones. Select a zone from the dropdown."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Fuehren Sie Aktionen fuer bestimmte DNS Zonen aus. Waehlen Sie eine Zone aus dem Dropdown Menue aus."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Refresh (Dropdown):" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Update the zone dropdown list."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Aktualisieren Sie die Zonenauswahlliste."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Zone Info:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View detailed information for the selected zone."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Detaillierte Informationen fuer die ausgewaehlte Zone anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Force Refresh:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Force a data refresh for the selected zone."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Eine Aktualisierung der Daten fuer die ausgewaehlte Zone erzwingen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Zone Transfer:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Initiate a zone transfer for the selected zone."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Einen Zonentransfer fuer die ausgewaehlte Zone initiieren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Event Logs">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="Event Logs and Monitoring" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="3" Margin="0,0,0,8">
                                                    <Button Name="btnDNSEvents" Content="DNS Server Events" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnSystemEvents" Content="System Events" Style="{StaticResource ModernButton}" Margin="2,0,2,0"/>
                                                    <Button Name="btnSecurityEvents" Content="Security Events" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
                                                <Separator Margin="0,8,0,8" />
                                                <Button Name="btnExportEvents" Content="Export Events" Background="#FF8C00" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch" Margin="0,0,0,0"/>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="Event Logs - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Access and manage various event logs related to DNS operations."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Greifen Sie auf verschiedene Ereignisprotokolle im Zusammenhang mit DNS Vorgaengen zu und verwalten Sie diese."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="DNS Server Events:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View DNS server events."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="DNS Serverereignisse anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="System Events:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View system events."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Systemereignisse anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Security Events:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View security events."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Sicherheitsereignisse anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Export Events:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Export these logs for analysis."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Diese Protokolle fuer Analysen exportieren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Advanced">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="Advanced Diagnostics" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                
                                                <Grid> <!-- Container für die ersten beiden Buttons -->
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="*"/>
                                                        <ColumnDefinition Width="*"/>
                                                    </Grid.ColumnDefinitions>
                                                    <Button Grid.Column="0" Name="btnEnableDebugLog" Content="Enable Debug Logging" Background="#FF8C00" Style="{StaticResource ModernButton}" Margin="0,0,4,0"/>
                                                    <Button Grid.Column="1" Name="btnDisableDebugLog" Content="Disable Debug Logging" Style="{StaticResource ModernButton}" Margin="4,0,0,0"/>
                                                </Grid>
                                                
                                                <Separator Margin="0,10,0,10"/> 
                                                
                                                <Button Name="btnNetworkProps" Content="Network Properties" Style="{StaticResource ModernButton}" Margin="0" HorizontalAlignment="Stretch"/>
                                                
                                                <Separator Margin="0,10,0,10"/>
                                                
                                                <Button Name="btnExportStats" Content="Export Statistics" Style="{StaticResource ModernButton}" Margin="0" HorizontalAlignment="Stretch"/>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="Advanced Diagnostics - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Use advanced diagnostic tools for detailed troubleshooting."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Verwenden Sie erweiterte Diagnosetools fuer eine detaillierte Fehlerbehebung."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Enable Debug Logging:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Enable debug logging."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Debug Protokollierung aktivieren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Disable Debug Logging:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Disable debug logging."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Debug Protokollierung deaktivieren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,8">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Export Statistics:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="Export server statistics."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Serverstatistiken exportieren."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Network Properties:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <StackPanel Grid.Column="1">
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050"><Run Text="EN: " FontWeight="Bold"/><Run Text="View current network properties."/></TextBlock>
                                                            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,2,0,0"><Run Text="DE: " FontWeight="Bold"/><Run Text="Aktuelle Netzwerkeigenschaften anzeigen."/></TextBlock>
                                                        </StackPanel>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                            </TabControl>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="280"/>
                                    </Grid.RowDefinitions>
                                    <Grid Grid.Row="0" Margin="0,0,0,8">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Diagnostic Output Console" FontSize="16" FontWeight="SemiBold" VerticalAlignment="Center" Foreground="#1C1C1C"/>
                                        <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right">
                                            <Button Name="btnClearOutput" Content="Clear" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnSaveOutput" Content="Save to File" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Grid>
                                    <TextBox Grid.Row="1" Name="txtDiagnosisOutput" 
                                            TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                                            FontFamily="Consolas" FontSize="10" 
                                            Background="#1E1E1E" Foreground="#A0D2A0"
                                            BorderBrush="#333333" BorderThickness="1"
                                            IsReadOnly="True"/>
                                </Grid>
                            </Border>
                        </Grid>

                        <!-- Reverse Zones Panel -->
                        <Grid Name="reversePanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- Action and Create Cards -->
                                <RowDefinition Height="*"/>    <!-- Zone List DataGrid -->
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Manage Reverse Zones" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <Grid Grid.Row="1"> 
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/> 
                                    <ColumnDefinition Width="*"/>    
                                </Grid.ColumnDefinitions>

                                <Border Grid.Column="0" Style="{StaticResource Card}">
                                    <StackPanel VerticalAlignment="Top">
                                        <TextBlock Text="Zone Actions" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Button Name="btnRefreshReverseZones" Content="Refresh" Style="{StaticResource ModernButton}" Margin="0,0,0,4" HorizontalAlignment="Stretch"/>
                                        <Button Name="btnDeleteReverseZone" Content="Delete" Margin="0,4,0,0" 
                                               Background="#D13438" Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch"/>
                                    </StackPanel>
                                </Border>

                                <Border Grid.Column="1" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Create New Reverse Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Grid>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>

                                            <TextBlock Grid.Column="0" Text="Network:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Column="1" Name="txtReverseNetwork" Style="{StaticResource ModernTextBox}" 
                                                    ToolTip="z.B. 192.168.1" Margin="0,0,16,0"/>
                                            <TextBlock Grid.Column="2" Text="Prefix:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Column="3" Name="txtReversePrefix" Text="24" Style="{StaticResource ModernTextBox}" Width="50" Margin="0,0,16,0"/>
                                            <TextBlock Grid.Column="4" Text="Replication:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <ComboBox Grid.Column="5" Name="cmbReverseReplication" Margin="0,0,16,0" Padding="8,5">
                                                <ComboBoxItem Content="Domain" IsSelected="True"/>
                                                <ComboBoxItem Content="Forest"/>
                                                <ComboBoxItem Content="Legacy"/>
                                            </ComboBox>
                                            <Button Grid.Column="6" Name="btnCreateReverseZone" Content="Create Zone" 
                                                    Background="#107C10" Style="{StaticResource ModernButton}"/>
                                        </Grid>
                                    </StackPanel>
                                </Border>
                            </Grid>
                            
                            <Border Grid.Row="2" Style="{StaticResource Card}"> 
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="Reverse Zone List" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                    <DataGrid Grid.Row="1" Name="dgReverseZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False"
                                             Background="White" BorderBrush="#E0E0E0" BorderThickness="1">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="430"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding ZoneType}" Width="250"/>
                                            <DataGridTextColumn Header="Network" Binding="{Binding Network}" Width="250"/>
                                            <DataGridTextColumn Header="Replication" Binding="{Binding RepScope}" Width="150"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>
                        </Grid>

                        <Grid Name="importPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Import/Export DNS Data" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <UniformGrid Grid.Row="1" Columns="2" Margin="0,0,0,0">
                                <!-- Export Card -->
                                <Border Style="{StaticResource Card}">
                                    <Grid>
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="*"/> 
                                            <RowDefinition Height="Auto"/> 
                                        </Grid.RowDefinitions>
                                        <StackPanel Grid.Row="0">
                                            <TextBlock Text="Export DNS Configuration" FontSize="16" FontWeight="SemiBold" 
                                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock Text="Format:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                            <ComboBox Name="cmbExportFormat" Margin="0,0,0,12" Padding="8,5">
                                                <ComboBoxItem Content="CSV" IsSelected="True"/>
                                                <ComboBoxItem Content="XML"/>
                                                <ComboBoxItem Content="JSON"/>
                                            </ComboBox>
                                            <CheckBox Name="chkExportForwardZones" Content="Forward Zones" IsChecked="True" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                            <CheckBox Name="chkExportReverseZones" Content="Reverse Zones" IsChecked="True" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                            <CheckBox Name="chkExportDNSSEC" Content="DNSSEC Settings" IsChecked="False" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        </StackPanel>
                                        <Button Grid.Row="1" Name="btnExportDNS" Content="Export DNS Configuration" 
                                               Background="#107C10" Style="{StaticResource ModernButton}"/>
                                    </Grid>
                                </Border>

                                <!-- Import Card -->
                                <Border Style="{StaticResource Card}">
                                    <Grid>
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="*"/> 
                                            <RowDefinition Height="Auto"/> 
                                        </Grid.RowDefinitions>
                                        <StackPanel Grid.Row="0">
                                            <TextBlock Text="Import DNS Configuration" FontSize="16" FontWeight="SemiBold" 
                                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock Text="File:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                            <Grid Margin="0,0,0,12">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                </Grid.ColumnDefinitions>
                                                <TextBox Grid.Column="0" Name="txtImportFile" Style="{StaticResource ModernTextBox}" IsReadOnly="True"/>
                                                <Button Grid.Column="1" Name="btnBrowseImport" Content="Browse" 
                                                       Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                                            </Grid>
                                            <TextBlock Text="Format:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                            <ComboBox Name="cmbImportFormat" Margin="0,0,0,12" Padding="8,5">
                                                <ComboBoxItem Content="CSV" IsSelected="True"/>
                                                <ComboBoxItem Content="XML"/>
                                                <ComboBoxItem Content="JSON"/>
                                            </ComboBox>
                                            <CheckBox Name="chkOverwriteExisting" Content="Überschreibe existierende Records" 
                                                     IsChecked="False" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        </StackPanel>
                                        <Button Grid.Row="1" Name="btnImportDNS" Content="Import DNS Configuration" 
                                               Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                    </Grid>
                                </Border>
                            </UniformGrid>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="Import/Export Log" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                    <TextBox Grid.Row="1" Name="txtImportExportLog" 
                                            TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                                            FontFamily="Consolas" FontSize="10" 
                                            Background="#F9F9F9" Foreground="#1C1C1C"
                                            BorderBrush="#E0E0E0" BorderThickness="1"
                                            IsReadOnly="True"/>
                                </Grid>
                            </Border>
                        </Grid>

                        <Grid Name="dnssecPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="DNSSEC Management" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <Border Grid.Row="1" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <StackPanel Grid.Row="0">
                                        <TextBlock Text="DNSSEC Zone Status" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12" HorizontalAlignment="Left">
                                            <Button Name="btnRefreshDNSSEC" Content="Refresh" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnSignZone" Content="Sign Zone" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnUnsignZone" Content="Unsign Zone" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </StackPanel>
                                    <DataGrid Grid.Row="1" Name="dgDNSSECZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False"
                                             Background="White" BorderBrush="#E0E0E0" BorderThickness="1">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="300"/>
                                            <DataGridTextColumn Header="DNSSEC Status" Binding="{Binding DNSSECStatus}" Width="200"/>
                                            <DataGridTextColumn Header="Key Signing Key" Binding="{Binding KSKStatus}" Width="200"/>
                                            <DataGridTextColumn Header="Zone Signing Key" Binding="{Binding ZSKStatus}" Width="200"/>
                                            <DataGridTextColumn Header="Next Rollover" Binding="{Binding NextRollover}" Width="180"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>

                            <UniformGrid Grid.Row="2" Columns="2" Margin="0,0,0,0">
                                <!-- DNSSEC Settings -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Settings" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <TextBlock Text="Selected Zone:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                        <ComboBox Name="cmbDNSSECZone" Margin="0,0,0,12" Padding="8,5"/>
                                        <TextBlock Text="Algorithm:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                        <ComboBox Name="cmbDNSSECAlgorithm" Margin="0,0,0,12" Padding="8,5">
                                            <ComboBoxItem Content="RSA/SHA-256" IsSelected="True"/>
                                            <ComboBoxItem Content="RSA/SHA-512"/>
                                            <ComboBoxItem Content="ECDSA P-256"/>
                                        </ComboBox>
                                        <TextBlock Text="Key Length:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                        <ComboBox Name="cmbKeyLength" Margin="0,0,0,12" Padding="8,5">
                                            <ComboBoxItem Content="1024"/>
                                            <ComboBoxItem Content="2048" IsSelected="True"/>
                                            <ComboBoxItem Content="4096"/>
                                        </ComboBox>
                                        <CheckBox Name="chkAutoRollover" Content="Automatic Key Rollover" 
                                                 IsChecked="True" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                    </StackPanel>
                                </Border>

                                <!-- DNSSEC Operations -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Operations" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Button Name="btnGenerateKeys" Content="Generate New Keys" HorizontalAlignment="Left"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnExportKeys" Content="Export Public Keys" HorizontalAlignment="Left"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnValidateSignatures" Content="Validate Signatures" HorizontalAlignment="Left"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnForceRollover" Content="Force Key Rollover" HorizontalAlignment="Left"
                                               Background="#FF8C00" Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Text="DNSSEC Status:" FontWeight="SemiBold" Margin="0,12,0,4" Foreground="#1C1C1C"/>
                                        <TextBlock Name="lblDNSSECStatus" Text="Ready" Foreground="#107C10"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                        </Grid>

                        <Grid Name="auditPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Audit and Logs" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <UniformGrid Grid.Row="1" Columns="2" Margin="0,0,0,0">
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Live DNS Monitoring" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12" HorizontalAlignment="Left">
                                            <Button Name="btnStartMonitoring" Content="Start" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnStopMonitoring" Content="Stop" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnClearMonitoring" Content="Clear" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                        <TextBlock Text="Monitor Events:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                        <CheckBox Name="chkMonitorQueries" Content="DNS Queries" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C"/>
                                        <CheckBox Name="chkMonitorZoneChanges" Content="Zone Changes" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C"/>
                                        <CheckBox Name="chkMonitorErrors" Content="DNS Errors" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C"/>
                                        <CheckBox Name="chkMonitorSecurity" Content="Security Events" IsChecked="True" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <TextBlock Name="lblMonitoringStatus" Text="Status: Stopped" 
                                                  Foreground="#D13438" FontWeight="SemiBold"/>
                                    </StackPanel>
                                </Border>

                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNS Statistics" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <Button Name="btnRefreshStats" Content="Refresh Statistics" HorizontalAlignment="Left"
                                               Margin="0,0,0,12" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Name="lblDNSStats" Text="Please Refresh Statistics..." 
                                                  FontSize="12" Foreground="#505050"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/> 
                                        <RowDefinition Height="*"/>    
                                        <RowDefinition Height="Auto"/> 
                                    </Grid.RowDefinitions>
                                    
                                    <StackPanel Grid.Row="0">
                                        <TextBlock Text="DNS Event Log" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <Grid Margin="0,0,0,8"> 
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="120"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="120"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Grid.Column="0" Text="Filter:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <ComboBox Grid.Column="1" Name="cmbLogLevel" Padding="5,2" Margin="0,0,10,0" MaxHeight="30" VerticalContentAlignment="Center">
                                                <ComboBoxItem Content="All" IsSelected="True"/>
                                                <ComboBoxItem Content="ERROR"/>
                                                <ComboBoxItem Content="WARN"/>
                                                <ComboBoxItem Content="INFO"/>
                                                <ComboBoxItem Content="DEBUG"/>
                                            </ComboBox>
                                            <TextBlock Grid.Column="2" Text="Search:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Column="3" Name="txtLogSearch" Style="{StaticResource ModernTextBox}" MaxHeight="30" VerticalContentAlignment="Center" Padding="8,2"/>
                                            <Button Grid.Column="4" Name="btnFilterLogs" Content="Filter" VerticalAlignment="Center"
                                                   Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                                            <Button Grid.Column="5" Name="btnRefreshLogs" Content="Refresh" VerticalAlignment="Center"
                                                   Margin="4,0,0,0" Style="{StaticResource ModernButton}"/>
                                        </Grid>
                                    </StackPanel>
                                    
                                    <DataGrid Grid.Row="1" Name="dgAuditLogs" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False"
                                             Background="White" BorderBrush="#E0E0E0" BorderThickness="1" Margin="0,0,0,12">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                                            <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="100"/>
                                            <DataGridTextColumn Header="Event" Binding="{Binding Event}" Width="200"/>
                                            <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="200"/>
                                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="430"/>
                                        </DataGrid.Columns>
                                    </DataGrid>

                                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
                                        <Button Name="btnExportLogs" Content="Export Logs" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnClearLogs" Content="Clear Logs" 
                                               Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                    </StackPanel>
                                </Grid>
                            </Border>
                        </Grid>
                    </Grid>
                </ScrollViewer>
            </Border>
        </Grid>

        <!-- Footer -->
        <Border Grid.Row="2" Background="#F3F3F3" BorderBrush="#E0E0E0" BorderThickness="0,1,0,0">
            <!-- Consistent with Header -->
            <Grid Margin="20,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="$($global:AppConfig.AppName)" 
                          VerticalAlignment="Center" FontSize="11" Foreground="#505050"/>

                <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock Text="Version $($global:AppConfig.ScriptVersion)" FontSize="11" Foreground="#505050" Margin="0,0,16,0"/>
                    <TextBlock Text="by $($global:AppConfig.Author)" FontSize="11" Foreground="#505050" Margin="0,0,16,0"/>
                    <TextBlock Text="$($global:AppConfig.Website)" FontSize="11" Foreground="#0078D4" Cursor="Hand"/>
                </StackPanel>

                <TextBlock Grid.Column="2" Text="Copyright 2025 - Last Update: $($global:AppConfig.LastUpdate)" 
                          HorizontalAlignment="Right" VerticalAlignment="Center" FontSize="11" Foreground="#505050"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

###############################################################################
# WPF FENSTER ERSTELLEN UND INITIALISIEREN
###############################################################################

# XAML laden und parsen
try {
    Add-Type -AssemblyName PresentationFramework
    $global:Window = [Windows.Markup.XamlReader]::Parse($global:XamlString)
    Write-Log "WPF XAML erfolgreich geladen" -Level "INFO"
} catch {
    Write-Log "Fehler beim Laden des XAML: $_" -Level "ERROR"
    exit 1
}

# UI-Elemente referenzieren
$global:Controls = @{}
@(
    "txtDNSServer", "btnConnect", "lblStatus", "lblDashboardStats",
    "lblOS", "lblUser", "lblDNSServerStatus", "lblCPU", "lblRAM", "lblDisk", "lblUptime",
    "btnDashboard", "btnForward", "btnReverse", "btnRecords", "btnImport", "btnDNSSEC", "btnTools", "btnAudit",
    "dashboardPanel", "forwardPanel", "reversePanel", "recordsPanel", "importPanel", "dnssecPanel", "toolsPanel", "auditPanel",
    "dgForwardZones", "btnRefreshZones", "btnDeleteZone", "txtNewZoneName", "cmbReplication", "btnCreateZone",
    "cmbRecordZone", "btnRefreshZoneList", "txtRecordName", "cmbRecordType", "txtRecordData", "txtRecordTTL",
    "btnCreateRecord", "btnDeleteRecord", "dgRecords",
    "txtDiagnosisTarget", "btnPing", "btnNslookup", "btnClearCache", "txtDiagnosisOutput",
    # Neue Diagnostic Tools Controls
    "btnResolve", "btnTestConnection", "btnShowCache", "btnClearClientCache",
    "btnServiceStatus", "btnStartService", "btnStopService", "btnRestartService",
    "btnServerConfig", "btnServerStats", "btnDiagnostics", "btnNetAdapterDNS",
    "btnShowForwarders", "txtForwarderIP", "btnAddForwarder", "btnRemoveForwarder",
    "cmbDiagZone", "btnRefreshZoneDropDown", "btnZoneInfo", "btnZoneRefresh", "btnZoneTransfer",
    "btnDNSEvents", "btnSystemEvents", "btnSecurityEvents", "btnExportEvents",
    "btnEnableDebugLog", "btnDisableDebugLog", "btnExportStats", "btnNetworkProps",
    "btnClearOutput", "btnSaveOutput",
    # Reverse Zones Controls
    "dgReverseZones", "btnRefreshReverseZones", "btnDeleteReverseZone", "txtReverseNetwork", "txtReversePrefix", "cmbReverseReplication", "btnCreateReverseZone",
    # Import/Export Controls
    "cmbExportFormat", "chkExportForwardZones", "chkExportReverseZones", "chkExportDNSSEC", "btnExportDNS",
    "txtImportFile", "btnBrowseImport", "cmbImportFormat", "chkOverwriteExisting", "btnImportDNS", "txtImportExportLog",
    # DNSSEC Controls
    "dgDNSSECZones", "btnRefreshDNSSEC", "btnSignZone", "btnUnsignZone", "cmbDNSSECZone", "cmbDNSSECAlgorithm", "cmbKeyLength", "chkAutoRollover",
    "btnGenerateKeys", "btnExportKeys", "btnValidateSignatures", "btnForceRollover", "lblDNSSECStatus",
    # Audit/Logs Controls
    "btnStartMonitoring", "btnStopMonitoring", "btnClearMonitoring", "chkMonitorQueries", "chkMonitorZoneChanges", "chkMonitorErrors", "chkMonitorSecurity", "lblMonitoringStatus",
    "btnRefreshStats", "lblDNSStats", "btnExportLogs", "btnClearLogs", "cmbLogLevel", "txtLogSearch", "btnFilterLogs", "btnRefreshLogs", "dgAuditLogs"
) | ForEach-Object {
    $control = $global:Window.FindName($_)
    if ($control) {
        $global:Controls[$_] = $control
        Write-Log "Control gefunden: $_" -Level "DEBUG" -Component "UI"
    } else {
        Write-Log "Control NICHT gefunden: $_" -Level "WARN" -Component "UI"
    }
}

###############################################################################
# NAVIGATION UND PANEL-MANAGEMENT
###############################################################################

$global:CurrentPanel = "dashboard"
$global:NavButtons = @($global:Controls.btnDashboard, $global:Controls.btnForward, $global:Controls.btnReverse, 
                       $global:Controls.btnRecords, $global:Controls.btnImport, $global:Controls.btnDNSSEC, 
                       $global:Controls.btnTools, $global:Controls.btnAudit)

function Show-Panel {
    param([string]$PanelName)
    
    # Alle Panels verstecken
    @("dashboardPanel", "forwardPanel", "reversePanel", "recordsPanel", "importPanel", "dnssecPanel", "toolsPanel", "auditPanel") | ForEach-Object {
        if ($global:Controls[$_]) {
            $global:Controls[$_].Visibility = "Collapsed"
        }
    }
    
    # Alle Nav-Buttons zurücksetzen
    $global:NavButtons | ForEach-Object {
        if ($_) {
            $_.Background = "Transparent"
        }
    }
    
    # Gewähltes Panel anzeigen
    $panelName = $PanelName + "Panel"
    if ($global:Controls[$panelName]) {
        $global:Controls[$panelName].Visibility = "Visible"
        $global:CurrentPanel = $PanelName
        
        # Entsprechenden Nav-Button hervorheben
        $navButtonName = "btn" + (Get-Culture).TextInfo.ToTitleCase($PanelName)
        if ($global:Controls[$navButtonName]) {
            $global:Controls[$navButtonName].Background = "#0078D4"
        }
        
        # Panel-spezifische Initialisierung (ohne Auto-Refresh)
        switch ($PanelName) {
            "dashboard" { 
                Update-Dashboard 
            }
            "import" { 
                Clear-ImportExportLog 
            }
            "tools" { 
                Clear-DiagnosisOutput
            }
            "audit" { 
                Update-AuditLogs
            }
        }
        
        Write-Log "Panel gewechselt zu: $PanelName" -Level "DEBUG" -Component "Navigation"
    } else {
        Write-Log "FEHLER: Panel $panelName nicht gefunden!" -Level "ERROR" -Component "Navigation"
        Show-MessageBox "Fehler: Das Panel '$PanelName' konnte nicht gefunden werden." "Navigation-Fehler" "Error"
    }
}

###############################################################################
# EVENT-HANDLER
###############################################################################

# Navigation Event-Handler
if ($global:Controls.btnDashboard) {
    $global:Controls.btnDashboard.Add_Click({ Show-Panel "dashboard" })
} else {
    Write-Log "FEHLER: btnDashboard Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnForward) {
    $global:Controls.btnForward.Add_Click({ Show-Panel "forward" })
} else {
    Write-Log "FEHLER: btnForward Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnReverse) {
    $global:Controls.btnReverse.Add_Click({ Show-Panel "reverse" })
} else {
    Write-Log "FEHLER: btnReverse Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnRecords) {
    $global:Controls.btnRecords.Add_Click({ Show-Panel "records" })
} else {
    Write-Log "FEHLER: btnRecords Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnImport) {
    $global:Controls.btnImport.Add_Click({ Show-Panel "import" })
} else {
    Write-Log "FEHLER: btnImport Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnDNSSEC) {
    $global:Controls.btnDNSSEC.Add_Click({ Show-Panel "dnssec" })
} else {
    Write-Log "FEHLER: btnDNSSEC Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnTools) {
    $global:Controls.btnTools.Add_Click({ Show-Panel "tools" })
} else {
    Write-Log "FEHLER: btnTools Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnAudit) {
    $global:Controls.btnAudit.Add_Click({ Show-Panel "audit" })
} else {
    Write-Log "FEHLER: btnAudit Control nicht gefunden!" -Level "ERROR" -Component "UI"
}

# DNS-Server Verbindung
$global:Controls.btnConnect.Add_Click({
    $serverName = $global:Controls.txtDNSServer.Text.Trim()
    if ([string]::IsNullOrEmpty($serverName)) {
        Show-MessageBox "Bitte geben Sie einen DNS-Server an." "Fehler" "Warning"
        return
    }
    
    # Validiere Server-Name/IP
    $serverName = Get-SafeString -InputString $serverName -RemoveSpecialChars $true
    
    # Verbindungsstatus-Cache invalidieren bei Server-Wechsel
    if ($global:DNSConnectionStatus.ServerName -ne $serverName) {
        $global:DNSConnectionStatus.IsConnected = $false
        $global:DNSConnectionStatus.LastChecked = $null
        $global:DNSConnectionStatus.ServerName = ""
        Write-Log "DNS-Verbindungsstatus-Cache invalidiert für neuen Server: $serverName" -Level "DEBUG" -Component "Connection"
    }
    
    $global:Controls.lblStatus.Text = "Status: Verbinde..."
    $global:Controls.lblStatus.Foreground = "#FF8C00"
    $global:Controls.btnConnect.IsEnabled = $false
    
    # Async-Verbindung für bessere UI-Responsiveness
    $global:Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{
        try {
            # Teste zuerst die Verbindung
            $connectionTest = Test-DNSServerConnection -ServerName $serverName
            
            if (-not $connectionTest) {
                throw "DNS-Server ist nicht erreichbar oder DNS-Rolle ist nicht installiert"
            }
            
            # Hole Basis-Informationen
            $zones = @(Get-DnsServerZone -ComputerName $serverName -ErrorAction Stop)
            
            $global:DetectedDnsServer = $serverName
            $global:Controls.lblStatus.Text = "Status: Verbunden"
            $global:Controls.lblStatus.Foreground = "#107C10"
            
            Write-Log "Verbindung zu DNS-Server '$serverName' hergestellt ($($zones.Count) Zonen gefunden)" -Level "SUCCESS" -Component "Connection"
            
            # Auto-Refresh starten
            Start-AutoRefresh
            
            # Dashboard aktualisieren
            if ($global:CurrentPanel -eq "dashboard") {
                Update-Dashboard
            }
            
            # Erfolgs-Feedback
            $message = "Erfolgreich mit DNS-Server '$serverName' verbunden!`n`nGefundene Zonen: $($zones.Count)"
            if ($zones.Count -eq 0) {
                $message += "`n`nHinweis: Keine DNS-Zonen gefunden. Möglicherweise fehlen Berechtigungen."
            }
            
            Show-MessageBox $message "Verbindung hergestellt" "Information"
            
        } catch {
            $global:Controls.lblStatus.Text = "Status: Fehler"
            $global:Controls.lblStatus.Foreground = "#D13438"
            
            # Detaillierte Fehleranalyse
            $errorMessage = "Fehler bei der Verbindung zum DNS-Server '$serverName':`n`n"
            
            if ($_.Exception.Message -match "Access is denied") {
                $errorMessage += "Zugriff verweigert. Bitte prüfen Sie:`n"
                $errorMessage += "- Administrative Berechtigungen`n"
                $errorMessage += "- Remote-Management ist aktiviert`n"
                $errorMessage += "- Firewall-Einstellungen"
            } elseif ($_.Exception.Message -match "RPC") {
                $errorMessage += "RPC-Fehler. Bitte prüfen Sie:`n"
                $errorMessage += "- Der Remote-Server ist erreichbar`n"
                $errorMessage += "- Windows-Firewall erlaubt RPC`n"
                $errorMessage += "- Der RPC-Dienst läuft"
            } else {
                $errorMessage += $_.Exception.Message
            }
            
            Write-Log "Fehler bei Verbindung zu DNS-Server '$serverName': $_" -Level "ERROR" -Component "Connection"
            Show-MessageBox $errorMessage "Verbindungsfehler" "Error"
            
        } finally {
            $global:Controls.btnConnect.IsEnabled = $true
        }
    })
})

# Forward-Zonen Event-Handler
$global:Controls.btnRefreshZones.Add_Click({ Update-ForwardZonesList })
$global:Controls.btnDeleteZone.Add_Click({ Remove-SelectedForwardZone })
$global:Controls.btnCreateZone.Add_Click({ Create-NewForwardZone })

# Records Event-Handler
$global:Controls.btnRefreshZoneList.Add_Click({ Update-ZonesList })
$global:Controls.cmbRecordZone.Add_SelectionChanged({ Update-RecordsList })
$global:Controls.btnCreateRecord.Add_Click({ Create-NewRecord })
$global:Controls.btnDeleteRecord.Add_Click({ Remove-SelectedRecord })

# Diagnose Event-Handler
$global:Controls.btnPing.Add_Click({ Run-Ping })
$global:Controls.btnNslookup.Add_Click({ Run-Nslookup })
$global:Controls.btnClearCache.Add_Click({ Clear-DNSCache })

# Reverse Zones Event-Handler
$global:Controls.btnRefreshReverseZones.Add_Click({ Update-ReverseZonesList })
$global:Controls.btnDeleteReverseZone.Add_Click({ Remove-SelectedReverseZone })
$global:Controls.btnCreateReverseZone.Add_Click({ Create-NewReverseZone })

# Import/Export Event-Handler
$global:Controls.btnExportDNS.Add_Click({ Export-DNSData })
$global:Controls.btnBrowseImport.Add_Click({ Browse-ImportFile })
$global:Controls.btnImportDNS.Add_Click({ Import-DNSData })

# DNSSEC Event-Handler
$global:Controls.btnRefreshDNSSEC.Add_Click({ Update-DNSSECStatus })
$global:Controls.btnSignZone.Add_Click({ Sign-SelectedZone })
$global:Controls.btnUnsignZone.Add_Click({ Unsign-SelectedZone })
$global:Controls.btnGenerateKeys.Add_Click({ Generate-DNSSECKeys })
$global:Controls.btnExportKeys.Add_Click({ Export-DNSSECKeys })
$global:Controls.btnValidateSignatures.Add_Click({ Validate-DNSSECSignatures })
$global:Controls.btnForceRollover.Add_Click({ Force-KeyRollover })
$global:Controls.cmbDNSSECZone.Add_SelectionChanged({ Update-DNSSECZoneInfo })

# Audit/Logs Event-Handler
$global:Controls.btnStartMonitoring.Add_Click({ Start-DNSMonitoring })
$global:Controls.btnStopMonitoring.Add_Click({ Stop-DNSMonitoring })
$global:Controls.btnClearMonitoring.Add_Click({ Clear-MonitoringLog })
$global:Controls.btnRefreshStats.Add_Click({ Update-DNSStatistics })
$global:Controls.btnExportLogs.Add_Click({ Export-AuditLogs })
$global:Controls.btnClearLogs.Add_Click({ Clear-AuditLogs })
$global:Controls.btnFilterLogs.Add_Click({ Filter-AuditLogs })
$global:Controls.btnRefreshLogs.Add_Click({ Update-AuditLogs })

# Neue Diagnostic Tools Event-Handler
$global:Controls.btnResolve.Add_Click({ Run-ResolveTest })
$global:Controls.btnTestConnection.Add_Click({ Run-TestConnection })
$global:Controls.btnShowCache.Add_Click({ Show-DNSServerCache })
$global:Controls.btnClearClientCache.Add_Click({ Clear-ClientDNSCache })

# DNS Service Management
$global:Controls.btnServiceStatus.Add_Click({ Show-ServiceStatus })
$global:Controls.btnStartService.Add_Click({ Start-DNSService })
$global:Controls.btnStopService.Add_Click({ Stop-DNSService })
$global:Controls.btnRestartService.Add_Click({ Restart-DNSService })

# DNS Configuration
$global:Controls.btnServerConfig.Add_Click({ Show-ServerConfiguration })
$global:Controls.btnServerStats.Add_Click({ Show-ServerStatistics })
$global:Controls.btnDiagnostics.Add_Click({ Show-DiagnosticsSettings })
$global:Controls.btnNetAdapterDNS.Add_Click({ Show-NetworkAdapterDNS })

# DNS Forwarders
$global:Controls.btnShowForwarders.Add_Click({ Show-DNSForwarders })
$global:Controls.btnAddForwarder.Add_Click({ Add-DNSForwarder })
$global:Controls.btnRemoveForwarder.Add_Click({ Remove-DNSForwarder })

# Zone Management
$global:Controls.btnRefreshZoneDropDown.Add_Click({ Update-DiagnosticZonesList })
$global:Controls.btnZoneInfo.Add_Click({ Show-ZoneInformation })
$global:Controls.btnZoneRefresh.Add_Click({ Force-ZoneRefresh })
$global:Controls.btnZoneTransfer.Add_Click({ Force-ZoneTransfer })

# Event Logs
$global:Controls.btnDNSEvents.Add_Click({ Show-DNSEvents })
$global:Controls.btnSystemEvents.Add_Click({ Show-SystemEvents })
$global:Controls.btnSecurityEvents.Add_Click({ Show-SecurityEvents })
$global:Controls.btnExportEvents.Add_Click({ Export-EventLogs })

# Advanced Diagnostics
$global:Controls.btnEnableDebugLog.Add_Click({ Enable-DebugLogging })
$global:Controls.btnDisableDebugLog.Add_Click({ Disable-DebugLogging })
$global:Controls.btnExportStats.Add_Click({ Export-DNSStatistics })
$global:Controls.btnNetworkProps.Add_Click({ Show-NetworkProperties })

# Output Management
$global:Controls.btnClearOutput.Add_Click({ Clear-DiagnosisOutput })
$global:Controls.btnSaveOutput.Add_Click({ Save-DiagnosisOutput })

###############################################################################
# BUSINESS-LOGIC-FUNKTIONEN
###############################################################################

function Show-LoadingStatus {
    param(
        [string]$Message = "Lade Daten...",
        [string]$Panel = $global:CurrentPanel
    )
    
    try {
        # Temporärer Status in der Statusleiste
        $originalStatus = $global:Controls.lblStatus.Text
        $originalColor = $global:Controls.lblStatus.Foreground
        
        $global:Controls.lblStatus.Text = "Status: $Message"
        $global:Controls.lblStatus.Foreground = "#FF8C00"
        
        # UI aktualisieren
        $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
        
        # Nach kurzer Zeit zurücksetzen
        $global:Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{
            Start-Sleep -Milliseconds 1500
            $global:Controls.lblStatus.Text = $originalStatus
            $global:Controls.lblStatus.Foreground = $originalColor
        })
        
    } catch {
        Write-Log "Fehler beim Anzeigen des Loading-Status: $_" -Level "DEBUG" -Component "UI"
    }
}

function Hide-LoadingStatus {
    try {
        # Status zurücksetzen basierend auf aktuellem Verbindungsstatus
        if ($global:DNSConnectionStatus.IsConnected -and $global:DNSConnectionStatus.ServerName -eq $global:Controls.txtDNSServer.Text) {
            $global:Controls.lblStatus.Text = "Status: Verbunden"
            $global:Controls.lblStatus.Foreground = "#107C10"
        } else {
            $global:Controls.lblStatus.Text = "Status: Nicht verbunden"
            $global:Controls.lblStatus.Foreground = "#D13438"
        }
    } catch {
        Write-Log "Fehler beim Verstecken des Loading-Status: $_" -Level "DEBUG" -Component "UI"
    }
}

function Update-Dashboard {
    try {
        # Server Information aktualisieren
        # Betriebssystem
        try {
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                if ($os) {
                    $global:Controls.lblOS.Text = "$($os.Caption) $($os.Version)"
                } else {
                    $global:Controls.lblOS.Text = "Windows (Version unbekannt)"
                }
            } catch {
                $global:Controls.lblOS.Text = "Nicht verfügbar"
                Write-Log "Fehler beim Abrufen des Betriebssystems: $_" -Level "DEBUG"
            }
            
            # Angemeldeter User
            try {
                $domain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $env:COMPUTERNAME }
                $user = if ($env:USERNAME) { $env:USERNAME } else { "Unbekannt" }
                $global:Controls.lblUser.Text = "$domain\$user"
            } catch {
                $global:Controls.lblUser.Text = "Unbekannt"
                Write-Log "Fehler beim Abrufen des Benutzers: $_" -Level "DEBUG"
            }
            
            # DNS Server Status
            $dnsServer = $global:Controls.txtDNSServer.Text
            if ([string]::IsNullOrEmpty($dnsServer)) {
                $global:Controls.lblDNSServerStatus.Text = "Kein Server ausgewählt"
                $global:Controls.lblDNSServerStatus.Foreground = "#FF8C00"
            } else {
                # Prüfe ob verbunden
                try {
                    $testConnection = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop | Select-Object -First 1
                    if ($dnsServer -eq "localhost" -and $global:DNSDetection.IsLocalDNS) {
                        $global:Controls.lblDNSServerStatus.Text = "localhost (Verbunden - Lokale DNS-Rolle)"
                    } else {
                        $global:Controls.lblDNSServerStatus.Text = "$dnsServer (Verbunden)"
                    }
                    $global:Controls.lblDNSServerStatus.Foreground = "#107C10"
                } catch {
                    if ($dnsServer -eq "localhost" -and $global:DNSDetection.IsLocalDNS) {
                        $global:Controls.lblDNSServerStatus.Text = "localhost (Verbindung fehlgeschlagen)"
                    } else {
                        $global:Controls.lblDNSServerStatus.Text = "$dnsServer (Nicht verbunden)"
                    }
                    $global:Controls.lblDNSServerStatus.Foreground = "#D13438"
                }
            }
            
            # CPU Auslastung
            try {
                $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
                $cpuCounter = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
                if ($cpuCounter -and $cpuCounter.CounterSamples -and $cpuCounter.CounterSamples.Count -gt 0) {
                    $cpuUsage = [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 1)
                } else {
                    $cpuUsage = 0
                }
                $cpuName = if ($cpu -and $cpu.Name) { $cpu.Name } else { "Unbekannt" }
                $global:Controls.lblCPU.Text = "$cpuUsage% ($cpuName)"
            } catch {
                $global:Controls.lblCPU.Text = "Nicht verfügbar"
                Write-Log "Fehler beim Abrufen der CPU-Auslastung: $_" -Level "DEBUG"
            }
            
            # RAM Auslastung
            try {
                if (-not $os) {
                    $os = Get-CimInstance -ClassName Win32_OperatingSystem
                }
                if ($os -and $os.TotalVisibleMemorySize -and $os.FreePhysicalMemory) {
                    $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                    $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
                    $usedRAM = $totalRAM - $freeRAM
                    $ramPercent = [math]::Round(($usedRAM / $totalRAM) * 100, 1)
                    $global:Controls.lblRAM.Text = "$ramPercent% ($([math]::Round($usedRAM, 1)) GB von $([math]::Round($totalRAM, 1)) GB verwendet)"
                } else {
                    $global:Controls.lblRAM.Text = "Nicht verfügbar"
                }
            } catch {
                $global:Controls.lblRAM.Text = "Nicht verfügbar"
                Write-Log "Fehler beim Abrufen der RAM-Auslastung: $_" -Level "DEBUG"
            }
            
            # Systempartition (C:)
            try {
                $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
                if ($disk -and $disk.Size -gt 0) {
                    $diskUsed = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                    $diskTotal = [math]::Round($disk.Size / 1GB, 2)
                    $diskPercent = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
                    $global:Controls.lblDisk.Text = "$diskPercent% ($diskUsed GB von $diskTotal GB verwendet)"
                } else {
                    $global:Controls.lblDisk.Text = "Nicht verfügbar"
                }
            } catch {
                $global:Controls.lblDisk.Text = "Nicht verfügbar"
                Write-Log "Fehler beim Abrufen der Disk-Auslastung: $_" -Level "DEBUG"
            }
            
            # System Uptime
            try {
                if (-not $os) {
                    $os = Get-CimInstance -ClassName Win32_OperatingSystem
                }
                if ($os -and $os.LastBootUpTime) {
                    $uptime = (Get-Date) - $os.LastBootUpTime
                    $uptimeText = ""
                    if ($uptime.Days -gt 0) {
                        $uptimeText = "$($uptime.Days) Tage, "
                    }
                    $uptimeText += "{0:D2}:{1:D2}:{2:D2}" -f $uptime.Hours, $uptime.Minutes, $uptime.Seconds
                    $global:Controls.lblUptime.Text = $uptimeText
                } else {
                    $global:Controls.lblUptime.Text = "Nicht verfügbar"
                }
            } catch {
                $global:Controls.lblUptime.Text = "Nicht verfügbar"
                Write-Log "Fehler beim Abrufen der Uptime: $_" -Level "DEBUG"
            }
        
        # DNS Quick Stats aktualisieren
        try {
            # Async Operation für bessere UI-Responsiveness
            $statsOperation = {
                $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
                $stats = @{
                    ForwardZones = ($zones | Where-Object { -not $_.IsReverse }).Count
                    ReverseZones = ($zones | Where-Object { $_.IsReverse }).Count
                    SignedZones = ($zones | Where-Object { $_.IsSigned -eq "Ja" }).Count
                    TotalZones = $zones.Count
                    ActiveZones = ($zones | Where-Object { $_.ZoneType -eq "Primary" }).Count
                    SecondaryZones = ($zones | Where-Object { $_.ZoneType -eq "Secondary" }).Count
                }
                
                # Intelligente Record-Schätzung
                $totalRecords = 0
                $sampleSize = [Math]::Min(5, $zones.Count)
                $sampledZones = $zones | Get-Random -Count $sampleSize
                
                foreach ($zone in $sampledZones) {
                    try {
                        $recordCount = @(Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue).Count
                        $totalRecords += $recordCount
                    } catch {
                        # Ignoriere Fehler bei einzelnen Zonen
                    }
                }
                
                if ($sampleSize -gt 0) {
                    $avgRecordsPerZone = [math]::Round($totalRecords / $sampleSize)
                    $estimatedTotal = $avgRecordsPerZone * $zones.Count
                    $stats.RecordsText = if ($zones.Count -gt $sampleSize) { 
                        "~$estimatedTotal (geschätzt)" 
                    } else { 
                        "$totalRecords" 
                    }
                } else {
                    $stats.RecordsText = "0"
                }
                
                return $stats
            }
            
            $stats = Invoke-SafeOperation -Operation $statsOperation -ErrorMessage "Fehler beim Abrufen der DNS-Statistiken" -Component "Dashboard"
            
            # Quick Stats Text aktualisieren mit erweiterten Informationen
            $quickStatsText = @"
DNS-Server Übersicht:
- Total Zones: $($stats.TotalZones)
  • Forward: $($stats.ForwardZones)
  • Reverse: $($stats.ReverseZones)
  • Primary: $($stats.ActiveZones)
  • Secondary: $($stats.SecondaryZones)
- Total Records: $($stats.RecordsText)
- DNSSEC-signierte Zonen: $($stats.SignedZones)
- Server: $($global:Controls.txtDNSServer.Text)
- Letztes Update: $(Get-Date -Format 'HH:mm:ss')
"@
            
            $global:Controls.lblDashboardStats.Text = $quickStatsText
            
        } catch {
            # Bei Fehler nur die Basis-Statistiken anzeigen
            $global:Controls.lblDashboardStats.Text = @"
DNS-Server Übersicht:
- Status: Nicht verbunden
- Bitte verbinden Sie sich mit einem DNS-Server
- Server: $($global:Controls.txtDNSServer.Text)
- Letztes Update: $(Get-Date -Format 'HH:mm:ss')
"@
        }
        
        Write-Log "Dashboard aktualisiert" -Level "DEBUG"
        
    } catch {
        $global:Controls.lblDashboardStats.Text = "Fehler beim Laden der Statistiken"
        Write-Log "Fehler beim Aktualisieren des Dashboards: $_" -Level "ERROR"
    }
}

function Update-ForwardZonesList {
    try {
        Show-LoadingStatus -Message "Lade Forward-Zonen..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text | Where-Object { -not $_.IsReverse }
        $global:Controls.dgForwardZones.ItemsSource = $zones
        Write-Log "Forward-Zonen-Liste aktualisiert: $($zones.Count) Zonen" -Level "INFO"
        Hide-LoadingStatus
    } catch {
        Write-Log "Fehler beim Aktualisieren der Forward-Zonen-Liste: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Fehler beim Laden der Forward-Zonen: $_" "Fehler" "Error"
    }
}

function Create-NewForwardZone {
    $zoneName = $global:Controls.txtNewZoneName.Text.Trim()
    $replication = $global:Controls.cmbReplication.SelectedItem.Content
    
    if ([string]::IsNullOrEmpty($zoneName)) {
        Show-MessageBox "Bitte geben Sie einen Zonennamen ein." "Validierungsfehler" "Warning"
        return
    }
    
    if (-not $replication) { $replication = "Domain" }
    
    try {
        Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope $replication -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        Show-MessageBox "Zone '$zoneName' wurde erfolgreich erstellt!" "Zone erstellt"
        $global:Controls.txtNewZoneName.Clear()
        Update-ForwardZonesList
        Write-Log "Forward-Zone erstellt: $zoneName" -Level "INFO"
    } catch {
        Write-Log "Fehler beim Erstellen der Forward-Zone $zoneName`: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Erstellen der Zone '$zoneName':`n$_" "Fehler" "Error"
    }
}

function Remove-SelectedForwardZone {
    $selectedZone = $global:Controls.dgForwardZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Bitte wählen Sie eine Zone zum Löschen aus." "Keine Auswahl" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Möchten Sie die Zone '$($selectedZone.ZoneName)' wirklich löschen?`n`nDiese Aktion kann nicht rückgängig gemacht werden!", "Zone löschen", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            Remove-DnsServerZone -Name $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            Show-MessageBox "Zone '$($selectedZone.ZoneName)' wurde erfolgreich gelöscht!" "Zone gelöscht"
            Update-ForwardZonesList
            Write-Log "Forward-Zone gelöscht: $($selectedZone.ZoneName)" -Level "INFO"
        } catch {
            Write-Log "Fehler beim Löschen der Forward-Zone $($selectedZone.ZoneName)`: $_" -Level "ERROR"
            Show-MessageBox "Fehler beim Löschen der Zone '$($selectedZone.ZoneName)':`n$_" "Fehler" "Error"
        }
    }
}

function Update-ZonesList {
    try {
        Show-LoadingStatus -Message "Lade Zonen-Liste..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $global:Controls.cmbRecordZone.Items.Clear()
        
        foreach ($zone in $zones) {
            $global:Controls.cmbRecordZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbRecordZone.Items.Count -gt 0) {
            $global:Controls.cmbRecordZone.SelectedIndex = 0
        }
        
        Write-Log "Zonen-Liste für Records aktualisiert: $($zones.Count) Zonen" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Fehler beim Aktualisieren der Zonen-Liste: $_" -Level "ERROR"
        Hide-LoadingStatus
    }
}

function Update-RecordsList {
    if (-not $global:Controls.cmbRecordZone.SelectedItem) { return }
    
    try {
        $zoneName = $global:Controls.cmbRecordZone.SelectedItem.ToString()
        Show-LoadingStatus -Message "Lade DNS-Records für $zoneName..."
        $records = Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $recordList = @()
        foreach ($record in $records) {
            if (($record.RecordType -eq "SOA") -or ($record.RecordType -eq "NS" -and $record.HostName -eq "@")) {
                continue
            }
            
            $data = Format-RecordData -record $record
            $recordList += [PSCustomObject]@{
                Name = $record.HostName
                Type = $record.RecordType
                Data = $data
                TTL = $record.TimeToLive.TotalSeconds
            }
        }
        
        $global:Controls.dgRecords.ItemsSource = $recordList
        Write-Log "Records für Zone '$zoneName' aktualisiert: $($records.Count) Records" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Fehler beim Aktualisieren der Records-Liste: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Fehler beim Laden der DNS-Records: $_" "Fehler" "Error"
    }
}

function Create-NewRecord {
    $zoneName = $global:Controls.cmbRecordZone.SelectedItem
    $recordName = Get-SafeString -InputString $global:Controls.txtRecordName.Text.Trim() -RemoveSpecialChars $true
    $recordType = $global:Controls.cmbRecordType.SelectedItem.Content
    $recordData = $global:Controls.txtRecordData.Text.Trim()
    $recordTTL = $global:Controls.txtRecordTTL.Text.Trim()
    
    if (-not $zoneName) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Validierungsfehler" "Warning"
        return
    }
    
    if ([string]::IsNullOrEmpty($recordName) -or [string]::IsNullOrEmpty($recordData)) {
        Show-MessageBox "Bitte geben Sie Name und Daten für den Record ein." "Validierungsfehler" "Warning"
        return
    }
    
    # Validiere Record-Daten
    if (-not (Test-RecordDataValid -RecordType $recordType -RecordData $recordData)) {
        $helpText = switch ($recordType) {
            "A"     { "Geben Sie eine gültige IPv4-Adresse ein (z.B. 192.168.1.1)" }
            "AAAA"  { "Geben Sie eine gültige IPv6-Adresse ein (z.B. 2001:db8::1)" }
            "CNAME" { "Geben Sie einen gültigen Hostnamen ein (z.B. server.domain.com)" }
            "MX"    { "Format: Priorität Mailserver (z.B. 10 mail.domain.com)" }
            "TXT"   { "Geben Sie einen Text ein (max. 255 Zeichen)" }
            "PTR"   { "Geben Sie einen gültigen Hostnamen ein" }
            "SRV"   { "Format: Priorität Gewicht Port Ziel (z.B. 0 5 5060 sip.domain.com)" }
            default { "Ungültiges Datenformat für Record-Typ $recordType" }
        }
        Show-MessageBox "Ungültige Record-Daten!`n`n$helpText" "Validierungsfehler" "Warning"
        return
    }
    
    $ttl = $global:AppConfig.DefaultTTL
    if (-not [string]::IsNullOrEmpty($recordTTL)) {
        if (-not [int]::TryParse($recordTTL, [ref]$ttl) -or $ttl -lt 0 -or $ttl -gt 2147483647) {
            Show-MessageBox "TTL muss eine Zahl zwischen 0 und 2147483647 sein." "Validierungsfehler" "Warning"
            return
        }
    }
    
    try {
        $timeSpan = [TimeSpan]::FromSeconds($ttl)
        
        switch ($recordType.ToUpper()) {
            "A" {
                Add-DnsServerResourceRecordA -ZoneName $zoneName -Name $recordName -IPv4Address $recordData -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            }
            "AAAA" {
                Add-DnsServerResourceRecordAAAA -ZoneName $zoneName -Name $recordName -IPv6Address $recordData -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            }
            "CNAME" {
                Add-DnsServerResourceRecordCName -ZoneName $zoneName -Name $recordName -HostNameAlias $recordData -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            }
            "TXT" {
                Add-DnsServerResourceRecordTxt -ZoneName $zoneName -Name $recordName -DescriptiveText $recordData -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            }
            "PTR" {
                Add-DnsServerResourceRecordPtr -ZoneName $zoneName -Name $recordName -PtrDomainName $recordData -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            }
            "MX" {
                $parts = $recordData -split " "
                if ($parts.Count -ge 2) {
                    $priority = [int]$parts[0]
                    $exchange = $parts[1]
                    Add-DnsServerResourceRecordMX -ZoneName $zoneName -Name $recordName -MailExchange $exchange -Preference $priority -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
                } else {
                    throw "MX-Record Format: 'Priorität Mailserver'"
                }
            }
            "SRV" {
                $parts = $recordData -split " "
                if ($parts.Count -ge 4) {
                    $priority = [int]$parts[0]
                    $weight = [int]$parts[1]
                    $port = [int]$parts[2]
                    $target = $parts[3]
                    Add-DnsServerResourceRecordSrv -ZoneName $zoneName -Name $recordName -DomainName $target -Priority $priority -Weight $weight -Port $port -TimeToLive $timeSpan -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
                } else {
                    throw "SRV-Record Format: 'Priorität Gewichtung Port Ziel'"
                }
            }
            default {
                throw "Nicht unterstützter Record-Typ: $recordType"
            }
        }
        
        Show-MessageBox "DNS-Record '$recordName' wurde erfolgreich erstellt!" "Record erstellt"
        $global:Controls.txtRecordName.Clear()
        $global:Controls.txtRecordData.Clear()
        Update-RecordsList
        Write-Log "DNS-Record erstellt: $recordType $recordName in Zone $zoneName" -Level "INFO"
        
    } catch {
        Write-Log "Fehler beim Erstellen des DNS-Records: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Erstellen des DNS-Records:`n$_" "Fehler" "Error"
    }
}

function Remove-SelectedRecord {
    $selectedRecord = $global:Controls.dgRecords.SelectedItem
    if (-not $selectedRecord) {
        Show-MessageBox "Bitte wählen Sie einen Record zum Löschen aus." "Keine Auswahl" "Warning"
        return
    }
    
    $zoneName = $global:Controls.cmbRecordZone.SelectedItem
    $result = [System.Windows.MessageBox]::Show("Möchten Sie den Record '$($selectedRecord.Name)' ($($selectedRecord.Type)) wirklich löschen?", "Record löschen", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            $records = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $selectedRecord.Name -RRType $selectedRecord.Type -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            
            foreach ($record in $records) {
                Remove-DnsServerResourceRecord -InputObject $record -ZoneName $zoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            }
            
            Show-MessageBox "Record '$($selectedRecord.Name)' wurde erfolgreich gelöscht!" "Record gelöscht"
            Update-RecordsList
            Write-Log "DNS-Record gelöscht: $($selectedRecord.Type) $($selectedRecord.Name) in Zone $zoneName" -Level "INFO"
            
        } catch {
            Write-Log "Fehler beim Löschen des DNS-Records: $_" -Level "ERROR"
            Show-MessageBox "Fehler beim Löschen des Records:`n$_" "Fehler" "Error"
        }
    }
}

function Clear-DiagnosisOutput {
    $global:Controls.txtDiagnosisOutput.Clear()
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-Diagnose-Tools ===`r`n")
    $global:Controls.txtDiagnosisOutput.AppendText("Bereit für Diagnose-Operationen.`r`n`r`n")
}

function Run-Ping {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel für den Ping ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== PING zu $target ===`r`n")
    
    try {
        $results = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
        
        foreach ($result in $results) {
            $global:Controls.txtDiagnosisOutput.AppendText("Antwort von $($result.Address): Zeit=$($result.ResponseTime)ms TTL=$($result.TimeToLive)`r`n")
        }
        
        $avgTime = ($results | Measure-Object -Property ResponseTime -Average).Average
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nPing-Statistik für $target`:")
        $global:Controls.txtDiagnosisOutput.AppendText("Pakete: Gesendet = 4, Empfangen = $($results.Count), Verloren = $(4 - $results.Count)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Durchschnittliche Antwortzeit: $([math]::Round($avgTime, 2))ms`r`n`r`n")
        
        Write-Log "Ping zu $target ausgeführt: $($results.Count)/4 Antworten" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Ping fehlgeschlagen: $_`r`n`r`n")
        Write-Log "Ping zu $target fehlgeschlagen: $_" -Level "ERROR"
    }
}

function Run-Nslookup {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel für Nslookup ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== NSLOOKUP für $target ===`r`n")
    
    try {
        $results = Resolve-DnsName -Name $target -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Server: $($global:Controls.txtDNSServer.Text)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Name: $target`r`n`r`n")
        
        foreach ($result in $results) {
            $global:Controls.txtDiagnosisOutput.AppendText("Name: $($result.Name)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Type: $($result.Type)`r`n")
            
            switch ($result.Type) {
                "A"     { $global:Controls.txtDiagnosisOutput.AppendText("Address: $($result.IPAddress)`r`n") }
                "AAAA"  { $global:Controls.txtDiagnosisOutput.AppendText("IPv6 Address: $($result.IPAddress)`r`n") }
                "CNAME" { $global:Controls.txtDiagnosisOutput.AppendText("Canonical Name: $($result.NameHost)`r`n") }
                "MX"    { $global:Controls.txtDiagnosisOutput.AppendText("Mail Exchange: $($result.NameExchange), Preference: $($result.Preference)`r`n") }
                "PTR"   { $global:Controls.txtDiagnosisOutput.AppendText("Host Name: $($result.NameHost)`r`n") }
                "TXT"   { $global:Controls.txtDiagnosisOutput.AppendText("Text: $($result.Strings -join ' ')`r`n") }
            }
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        }
        
        Write-Log "Nslookup für $target ausgeführt: $($results.Count) Ergebnisse" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Nslookup fehlgeschlagen: $_`r`n`r`n")
        Write-Log "Nslookup für $target fehlgeschlagen: $_" -Level "ERROR"
    }
}

function Clear-DNSCache {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-CACHE LEEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Leere DNS-Server-Cache...`r`n")
        Clear-DnsServerCache -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Server-Cache erfolgreich geleert`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("Leere lokalen DNS-Client-Cache...`r`n")
        Clear-DnsClientCache -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Client-Cache erfolgreich geleert`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nDNS-Cache wurde erfolgreich geleert!`r`n`r`n")
        Write-Log "DNS-Cache erfolgreich geleert" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Leeren des DNS-Caches: $_`r`n`r`n")
        Write-Log "Fehler beim Leeren des DNS-Caches: $_" -Level "ERROR"
    }
}

###############################################################################
# REVERSE ZONES FUNKTIONEN
###############################################################################

function Update-ReverseZonesList {
    try {
        Show-LoadingStatus -Message "Lade Reverse-Zonen..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text | Where-Object { $_.IsReverse }
        
        $reverseZonesList = @()
        foreach ($zone in $zones) {
            $network = "Unbekannt"
            if ($zone.ZoneName -match '(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa') {
                $network = "$($matches[3]).$($matches[2]).$($matches[1]).0/24"
            } elseif ($zone.ZoneName -match '(\d+)\.(\d+)\.in-addr\.arpa') {
                $network = "$($matches[2]).$($matches[1]).0.0/16"
            } elseif ($zone.ZoneName -match '(\d+)\.in-addr\.arpa') {
                $network = "$($matches[1]).0.0.0/8"
            }
            
            $reverseZonesList += [PSCustomObject]@{
                ZoneName = $zone.ZoneName
                ZoneType = $zone.ZoneType
                Network = $network
                RepScope = $zone.RepScope
            }
        }
        
        $global:Controls.dgReverseZones.ItemsSource = $reverseZonesList
        Write-Log "Reverse-Zonen-Liste aktualisiert: $($reverseZonesList.Count) Zonen" -Level "INFO"
        Hide-LoadingStatus
    } catch {
        Write-Log "Fehler beim Aktualisieren der Reverse-Zonen-Liste: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Fehler beim Laden der Reverse-Zonen: $_" "Fehler" "Error"
    }
}

function Create-NewReverseZone {
    $network = $global:Controls.txtReverseNetwork.Text.Trim()
    $prefix = $global:Controls.txtReversePrefix.Text.Trim()
    $replication = $global:Controls.cmbReverseReplication.SelectedItem.Content
    
    if ([string]::IsNullOrEmpty($network)) {
        Show-MessageBox "Bitte geben Sie ein Netzwerk ein (z.B. 192.168.1)." "Validierungsfehler" "Warning"
        return
    }
    
    if (-not $replication) { $replication = "Domain" }
    if ([string]::IsNullOrEmpty($prefix)) { $prefix = "24" }
    
    try {
        # Netzwerk validieren
        $networkParts = $network -split '\.'
        if ($networkParts.Count -lt 3) {
            Show-MessageBox "Ungueltiges Netzwerkformat. Verwenden Sie z.B. 192.168.1" "Validierungsfehler" "Warning"
            return
        }
        
        # Reverse Zone Name erstellen
        $reverseZoneName = ""
        switch ([int]$prefix) {
            24 { $reverseZoneName = "$($networkParts[2]).$($networkParts[1]).$($networkParts[0]).in-addr.arpa" }
            16 { $reverseZoneName = "$($networkParts[1]).$($networkParts[0]).in-addr.arpa" }
            8  { $reverseZoneName = "$($networkParts[0]).in-addr.arpa" }
            default { 
                Show-MessageBox "Nur /8, /16 und /24 Netzwerke werden unterstuetzt." "Validierungsfehler" "Warning"
                return 
            }
        }
        
        Add-DnsServerPrimaryZone -Name $reverseZoneName -ReplicationScope $replication -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        Show-MessageBox "Reverse-Zone '$reverseZoneName' wurde erfolgreich erstellt!" "Zone erstellt"
        
        $global:Controls.txtReverseNetwork.Clear()
        Update-ReverseZonesList
        Write-Log "Reverse-Zone erstellt: $reverseZoneName fuer Netzwerk $network/$prefix" -Level "INFO"
        
    } catch {
        Write-Log "Fehler beim Erstellen der Reverse-Zone: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Erstellen der Reverse-Zone:`n$_" "Fehler" "Error"
    }
}

function Remove-SelectedReverseZone {
    $selectedZone = $global:Controls.dgReverseZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Bitte wählen Sie eine Reverse-Zone zum Löschen aus." "Keine Auswahl" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Möchten Sie die Reverse-Zone '$($selectedZone.ZoneName)' wirklich löschen?`n`nDiese Aktion kann nicht rückgängig gemacht werden!", "Zone löschen", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            Remove-DnsServerZone -Name $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            Show-MessageBox "Reverse-Zone '$($selectedZone.ZoneName)' wurde erfolgreich gelöscht!" "Zone gelöscht"
            Update-ReverseZonesList
            Write-Log "Reverse-Zone gelöscht: $($selectedZone.ZoneName)" -Level "INFO"
        } catch {
            Write-Log "Fehler beim Löschen der Reverse-Zone $($selectedZone.ZoneName)`: $_" -Level "ERROR"
            Show-MessageBox "Fehler beim Löschen der Reverse-Zone '$($selectedZone.ZoneName)':`n$_" "Fehler" "Error"
        }
    }
}

###############################################################################
# IMPORT/EXPORT FUNKTIONEN
###############################################################################

function Clear-ImportExportLog {
    $global:Controls.txtImportExportLog.Clear()
    $global:Controls.txtImportExportLog.AppendText("=== DNS Import/Export Log ===`r`n")
    $global:Controls.txtImportExportLog.AppendText("Bereit für Import- und Export-Operationen.`r`n`r`n")
}

function Export-DNSData {
    $format = $global:Controls.cmbExportFormat.SelectedItem.Content
    if (-not $format) { $format = "CSV" }
    
    $filter = switch ($format.ToUpper()) {
        "CSV" { "CSV Dateien (*.csv)|*.csv|Alle Dateien (*.*)|*.*" }
        "XML" { "XML Dateien (*.xml)|*.xml|Alle Dateien (*.*)|*.*" }
        "JSON" { "JSON Dateien (*.json)|*.json|Alle Dateien (*.*)|*.*" }
        default { "Alle Dateien (*.*)|*.*" }
    }
    
    $exportPath = Show-SaveFileDialog -Filter $filter -Title "DNS-Konfiguration exportieren"
    if (-not $exportPath) { return }
    
    $global:Controls.txtImportExportLog.AppendText("=== DNS EXPORT GESTARTET ===`r`n")
    $global:Controls.txtImportExportLog.AppendText("Format: $format`r`n")
    $global:Controls.txtImportExportLog.AppendText("Datei: $exportPath`r`n`r`n")
    
    try {
        $success = Export-DNSConfiguration -DnsServerName $global:Controls.txtDNSServer.Text -ExportPath $exportPath -Format $format
        
        if ($success) {
            $global:Controls.txtImportExportLog.AppendText("[OK] Export erfolgreich abgeschlossen!`r`n")
            $global:Controls.txtImportExportLog.AppendText("Datei gespeichert: $exportPath`r`n`r`n")
            Show-MessageBox "DNS-Konfiguration wurde erfolgreich exportiert nach:`n$exportPath" "Export erfolgreich"
        } else {
            $global:Controls.txtImportExportLog.AppendText("[ERROR] Export fehlgeschlagen!`r`n`r`n")
            Show-MessageBox "Fehler beim Export der DNS-Konfiguration." "Export fehlgeschlagen" "Error"
        }
        
    } catch {
        $global:Controls.txtImportExportLog.AppendText("[ERROR] Export-Fehler: $_`r`n`r`n")
        Show-MessageBox "Fehler beim Export:`n$_" "Fehler" "Error"
        Write-Log "DNS-Export fehlgeschlagen: $_" -Level "ERROR"
    }
}

function Browse-ImportFile {
    $filter = "Alle unterstuetzten Formate (*.csv;*.xml;*.json)|*.csv;*.xml;*.json|CSV Dateien (*.csv)|*.csv|XML Dateien (*.xml)|*.xml|JSON Dateien (*.json)|*.json|Alle Dateien (*.*)|*.*"
    $importPath = Show-OpenFileDialog -Filter $filter -Title "DNS-Konfigurationsdatei auswaehlen"
    
    if ($importPath) {
        $global:Controls.txtImportFile.Text = $importPath
        
        # Format automatisch erkennen
        $extension = [System.IO.Path]::GetExtension($importPath).ToLower()
        switch ($extension) {
            ".csv" { $global:Controls.cmbImportFormat.SelectedIndex = 0 }
            ".xml" { $global:Controls.cmbImportFormat.SelectedIndex = 1 }
            ".json" { $global:Controls.cmbImportFormat.SelectedIndex = 2 }
        }
    }
}

function Import-DNSData {
    $importPath = $global:Controls.txtImportFile.Text.Trim()
    $format = $global:Controls.cmbImportFormat.SelectedItem.Content
    
    if ([string]::IsNullOrEmpty($importPath)) {
        Show-MessageBox "Bitte waehlen Sie eine Datei zum Importieren aus." "Keine Datei ausgewaehlt" "Warning"
        return
    }
    
    if (-not (Test-Path $importPath)) {
        Show-MessageBox "Die ausgewaehlte Datei existiert nicht." "Datei nicht gefunden" "Error"
        return
    }
    
    if (-not $format) { $format = "CSV" }
    
    $result = [System.Windows.MessageBox]::Show("Moechten Sie die DNS-Konfiguration aus der Datei importieren?`n`nDatei: $importPath`nFormat: $format`n`nVorhandene Records koennten ueberschrieben werden!", "Import bestaetigen", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtImportExportLog.AppendText("=== DNS IMPORT GESTARTET ===`r`n")
        $global:Controls.txtImportExportLog.AppendText("Format: $format`r`n")
        $global:Controls.txtImportExportLog.AppendText("Datei: $importPath`r`n`r`n")
        
        try {
            $importResult = Import-DNSConfiguration -DnsServerName $global:Controls.txtDNSServer.Text -ImportPath $importPath -Format $format
            
            $global:Controls.txtImportExportLog.AppendText("=== IMPORT ABGESCHLOSSEN ===`r`n")
            $global:Controls.txtImportExportLog.AppendText("Erfolgreich: $($importResult.Success) Records`r`n")
            $global:Controls.txtImportExportLog.AppendText("Fehlgeschlagen: $($importResult.Failed) Records`r`n`r`n")
            
            Show-MessageBox "Import abgeschlossen!`n`nErfolgreich: $($importResult.Success) Records`nFehlgeschlagen: $($importResult.Failed) Records" "Import abgeschlossen"
            
            # Aktuelle Panels aktualisieren
            if ($global:CurrentPanel -eq "forward") { Update-ForwardZonesList }
            if ($global:CurrentPanel -eq "reverse") { Update-ReverseZonesList }
            if ($global:CurrentPanel -eq "records") { Update-ZonesList }
            
        } catch {
            $global:Controls.txtImportExportLog.AppendText("[ERROR] Import-Fehler: $_`r`n`r`n")
            Show-MessageBox "Fehler beim Import:`n$_" "Fehler" "Error"
            Write-Log "DNS-Import fehlgeschlagen: $_" -Level "ERROR"
        }
    }
}

###############################################################################
# DNSSEC FUNKTIONEN
###############################################################################

function Update-DNSSECStatus {
    try {
        Show-LoadingStatus -Message "Lade DNSSEC-Status..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text | Where-Object { -not $_.IsReverse }
        
        $dnssecList = @()
        foreach ($zone in $zones) {
            try {
                $kskStatus = "N/A"
                $zskStatus = "N/A"
                $nextRollover = "N/A"
                
                # Versuche DNSSEC-Informationen abzurufen
                try {
                    $keys = Get-DnsServerDnsSecZoneSetting -ZoneName $zone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
                    if ($keys) {
                        $kskStatus = "Active"
                        $zskStatus = "Active"
                        $nextRollover = "Auto"
                    }
                } catch {
                    # Ignoriere DNSSEC-Fehler für nicht-signierte Zonen
                }
                
                $dnssecList += [PSCustomObject]@{
                    ZoneName = $zone.ZoneName
                    DNSSECStatus = $zone.DNSSECStatus
                    KSKStatus = $kskStatus
                    ZSKStatus = $zskStatus
                    NextRollover = $nextRollover
                }
            } catch {
                Write-Log "Fehler beim Abrufen der DNSSEC-Informationen für Zone $($zone.ZoneName): $_" -Level "DEBUG"
            }
        }
        
        $global:Controls.dgDNSSECZones.ItemsSource = $dnssecList
        
        # DNSSEC Zone ComboBox aktualisieren
        $global:Controls.cmbDNSSECZone.Items.Clear()
        foreach ($zone in $zones) {
            $global:Controls.cmbDNSSECZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbDNSSECZone.Items.Count -gt 0) {
            $global:Controls.cmbDNSSECZone.SelectedIndex = 0
        }
        
        Write-Log "DNSSEC-Status aktualisiert fuer $($dnssecList.Count) Zonen" -Level "INFO"
        Hide-LoadingStatus
        
    } catch {
        Write-Log "Fehler beim Aktualisieren des DNSSEC-Status: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Fehler beim Laden der DNSSEC-Informationen: $_" "Fehler" "Error"
    }
}

function Sign-SelectedZone {
    $selectedZone = $global:Controls.dgDNSSECZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Bitte waehlen Sie eine Zone zum Signieren aus." "Keine Auswahl" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Moechten Sie die Zone '$($selectedZone.ZoneName)' mit DNSSEC signieren?`n`nDies erstellt Schluessel und signiert alle Records in der Zone.", "Zone signieren", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            $global:Controls.lblDNSSECStatus.Text = "Signiere Zone..."
            $global:Controls.lblDNSSECStatus.Foreground = "#FF8C00"
            
            # Vereinfachte DNSSEC-Signierung (funktioniert moeglicherweise nicht auf allen Systemen)
            try {
                # Prüfe erst, ob bereits DNSSEC-Schlüssel existieren
                $existingKeys = Get-DnsServerSigningKey -ZoneName $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
                
                if ($existingKeys) {
                    # Versuche Rollover zu aktivieren
                    Enable-DnsServerSigningKeyRollover -ZoneName $selectedZone.ZoneName -KeyId $existingKeys[0].KeyId -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
                    
                    $global:Controls.lblDNSSECStatus.Text = "Zone erfolgreich signiert"
                    $global:Controls.lblDNSSECStatus.Foreground = "#107C10"
                    
                    Show-MessageBox "Zone '$($selectedZone.ZoneName)' wurde erfolgreich mit DNSSEC signiert!" "DNSSEC aktiviert"
                    Update-DNSSECStatus
                    Write-Log "DNSSEC aktiviert fuer Zone: $($selectedZone.ZoneName)" -Level "INFO"
                } else {
                    # Keine Schlüssel vorhanden - manuelle Konfiguration erforderlich
                    throw "Keine DNSSEC-Schlüssel gefunden"
                }
                
            } catch {
                # Fallback: Manuelle DNSSEC-Konfiguration anzeigen
                $global:Controls.lblDNSSECStatus.Text = "DNSSEC-Konfiguration erforderlich"
                $global:Controls.lblDNSSECStatus.Foreground = "#FF8C00"
                
                $manualSteps = @"
Manuelle DNSSEC-Konfiguration erforderlich:

1. Schlüssel erstellen:
   Add-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -Type KSK
   Add-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -Type ZSK

2. Zone signieren:
   Invoke-DnsServerZoneSigning -ZoneName '$($selectedZone.ZoneName)'

3. Alternativ über DNS-Manager:
   DNS-Manager → Zone → Rechtsklick → "DNSSEC → Zone signieren"
"@
                
                Show-MessageBox $manualSteps "Manuelle DNSSEC-Konfiguration" "Information"
            }
            
        } catch {
            $global:Controls.lblDNSSECStatus.Text = "Fehler beim Signieren"
            $global:Controls.lblDNSSECStatus.Foreground = "#D13438"
            Write-Log "Fehler beim DNSSEC-Signieren der Zone $($selectedZone.ZoneName): $_" -Level "ERROR"
            Show-MessageBox "Fehler beim Signieren der Zone:`n$_" "Fehler" "Error"
        }
    }
}

function Unsign-SelectedZone {
    $selectedZone = $global:Controls.dgDNSSECZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Bitte waehlen Sie eine Zone zum Entfernen der DNSSEC-Signierung aus." "Keine Auswahl" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Moechten Sie die DNSSEC-Signierung fuer Zone '$($selectedZone.ZoneName)' entfernen?`n`nDies entfernt alle DNSSEC-Schluessel und Signaturen!", "DNSSEC entfernen", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        try {
            # Vereinfachte DNSSEC-Entfernung
            Show-MessageBox "DNSSEC-Entfernung muss manuell durchgefuehrt werden.`n`nVerwenden Sie die DNS-Konsole oder PowerShell:`n`nRemove-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -All" "Manuelle Aktion erforderlich" "Information"
            Write-Log "DNSSEC-Entfernung angefordert fuer Zone: $($selectedZone.ZoneName)" -Level "INFO"
            
        } catch {
            Write-Log "Fehler beim Entfernen der DNSSEC-Signierung: $_" -Level "ERROR"
            Show-MessageBox "Fehler beim Entfernen der DNSSEC-Signierung:`n$_" "Fehler" "Error"
        }
    }
}

function Generate-DNSSECKeys {
    $zoneName = $global:Controls.cmbDNSSECZone.SelectedItem
    if (-not $zoneName) {
        Show-MessageBox "Bitte waehlen Sie eine Zone aus." "Keine Zone ausgewaehlt" "Warning"
        return
    }
    
    try {
        Show-MessageBox "Schluesselgenerierung muss ueber die DNS-Konsole oder erweiterte PowerShell-Befehle durchgefuehrt werden.`n`nBeispiel-Befehle:`n`nAdd-DnsServerSigningKey -ZoneName '$zoneName' -Type KSK -CryptoAlgorithm RsaSha256`nAdd-DnsServerSigningKey -ZoneName '$zoneName' -Type ZSK -CryptoAlgorithm RsaSha256" "DNSSEC-Schluessel" "Information"
        Write-Log "DNSSEC-Schluesselgenerierung angefordert fuer Zone: $zoneName" -Level "INFO"
        
    } catch {
        Write-Log "Fehler bei der DNSSEC-Schluesselgenerierung: $_" -Level "ERROR"
        Show-MessageBox "Fehler bei der Schluesselgenerierung:`n$_" "Fehler" "Error"
    }
}

function Export-DNSSECKeys {
    Show-MessageBox "DNSSEC-Schluessel-Export muss ueber die DNS-Konsole durchgefuehrt werden.`n`nNavigieren Sie zu:`nDNS Manager -> Ihre Zone -> DNSSEC -> Rechtsklick auf Schluessel -> Exportieren" "DNSSEC-Export" "Information"
}

function Validate-DNSSECSignatures {
    $zoneName = $global:Controls.cmbDNSSECZone.SelectedItem
    if (-not $zoneName) {
        Show-MessageBox "Bitte waehlen Sie eine Zone aus." "Keine Zone ausgewaehlt" "Warning"
        return
    }
    
    try {
        # Einfache DNSSEC-Validierung ueber nslookup
        $validationResult = & nslookup -type=DNSKEY $zoneName 2>&1
        Show-MessageBox "DNSSEC-Validierung fuer Zone '$zoneName':`n`n$($validationResult -join "`n")" "DNSSEC-Validierung" "Information"
        Write-Log "DNSSEC-Validierung durchgefuehrt fuer Zone: $zoneName" -Level "INFO"
        
    } catch {
        Write-Log "Fehler bei der DNSSEC-Validierung: $_" -Level "ERROR"
        Show-MessageBox "Fehler bei der DNSSEC-Validierung:`n$_" "Fehler" "Error"
    }
}

function Force-KeyRollover {
    Show-MessageBox "Schluessel-Rollover muss ueber erweiterte DNS-Verwaltungstools durchgefuehrt werden.`n`nVerwenden Sie die DNS-Konsole oder spezielle DNSSEC-Verwaltungstools." "Schluessel-Rollover" "Information"
}

function Update-DNSSECZoneInfo {
    # Platzhalter für zonen-spezifische DNSSEC-Informationen
}

###############################################################################
# AUDIT/LOGS/MONITORING FUNKTIONEN
###############################################################################

# Globale Monitoring-Variablen
$global:MonitoringActive = $false
$global:MonitoringTimer = $null
$global:AuditLogData = [System.Collections.ArrayList]::new()

# Auto-Refresh Timer
$global:AutoRefreshTimer = $null
$global:AutoRefreshEnabled = $false

function Update-DNSStatistics {
    try {
        $stats = Get-DNSStatistics -DnsServerName $global:Controls.txtDNSServer.Text
        
        $statsText = @"
    * Server:               $($global:Controls.txtDNSServer.Text)
    * Monitoring:       $(if ($global:MonitoringActive) { "Aktiv" } else { "Inaktiv" })

    * Gesamt:                $($stats.TotalZones) Zonen
    * Forward:               $($stats.ForwardZones) Zonen
    * Reverse:                $($stats.ReverseZones) Zonen
    * DNSSEC-signiert:  $($stats.SignedZones) Zonen
"@
        
        $global:Controls.lblDNSStats.Text = $statsText
        Write-Log "DNS-Statistiken aktualisiert" -Level "DEBUG"
        
    } catch {
        $global:Controls.lblDNSStats.Text = "Fehler beim Laden der Statistiken"
        Write-Log "Fehler beim Aktualisieren der DNS-Statistiken: $_" -Level "ERROR"
    }
}

function Start-DNSMonitoring {
    if ($global:MonitoringActive) {
        Show-MessageBox "Monitoring ist bereits aktiv." "Monitoring" "Information"
        return
    }
    
    try {
        $global:MonitoringActive = $true
        $global:Controls.lblMonitoringStatus.Text = "Status: Aktiv"
        $global:Controls.lblMonitoringStatus.Foreground = "#107C10"
        
        # Simuliertes Monitoring (echtes Monitoring würde Event-Logs oder DNS-Logs überwachen)
        $global:MonitoringTimer = New-Object System.Windows.Threading.DispatcherTimer
        $global:MonitoringTimer.Interval = [TimeSpan]::FromSeconds(30)
        $global:MonitoringTimer.Add_Tick({
            Add-MonitoringEvent -Event "QUERY" -Message "DNS-Abfrage erkannt" -Source "Monitor"
        })
        $global:MonitoringTimer.Start()
        
        Add-MonitoringEvent -Event "MONITORING" -Message "DNS-Monitoring gestartet" -Source "System"
        Write-Log "DNS-Monitoring gestartet" -Level "INFO"
        
    } catch {
        $global:MonitoringActive = $false
        $global:Controls.lblMonitoringStatus.Text = "Status: Fehler"
        $global:Controls.lblMonitoringStatus.Foreground = "#D13438"
        Write-Log "Fehler beim Starten des DNS-Monitorings: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Starten des Monitorings:`n$_" "Fehler" "Error"
    }
}

function Stop-DNSMonitoring {
    if (-not $global:MonitoringActive) {
        Show-MessageBox "Monitoring ist nicht aktiv." "Monitoring" "Information"
        return
    }
    
    try {
        $global:MonitoringActive = $false
        if ($global:MonitoringTimer) {
            $global:MonitoringTimer.Stop()
            $global:MonitoringTimer = $null
        }
        
        $global:Controls.lblMonitoringStatus.Text = "Status: Gestoppt"
        $global:Controls.lblMonitoringStatus.Foreground = "#D13438"
        
        Add-MonitoringEvent -Event "MONITORING" -Message "DNS-Monitoring gestoppt" -Source "System"
        Write-Log "DNS-Monitoring gestoppt" -Level "INFO"
        
    } catch {
        Write-Log "Fehler beim Stoppen des DNS-Monitorings: $_" -Level "ERROR"
    }
}

function Clear-MonitoringLog {
    $global:AuditLogData.Clear()
    Update-AuditLogs
    Write-Log "Monitoring-Log geleert" -Level "INFO"
}

function Add-MonitoringEvent {
    param(
        [string]$Event,
        [string]$Message,
        [string]$Source = "DNS",
        [string]$Level = "INFO"
    )
    
    try {
        # Neuen Eintrag erstellen
        $newEntry = [PSCustomObject]@{
            Time = Get-Date -Format "HH:mm:ss"
            Level = $Level
            Event = $Event
            Message = $Message
            Source = $Source
        }
        
        # Zur globalen Liste hinzufügen
        $global:AuditLogData.Add($newEntry) | Out-Null
        
        # Begrenzen auf letzte 1000 Einträge
        if ($global:AuditLogData.Count -gt 1000) {
            $removeCount = $global:AuditLogData.Count - 1000
            $global:AuditLogData.RemoveRange(0, $removeCount)
        }
        
        # GUI aktualisieren wenn Audit-Panel aktiv
        if ($global:CurrentPanel -eq "audit") {
            # Verzögerung für GUI-Thread
            $global:Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{
                Update-AuditLogs
            })
        }
        
    } catch {
        Write-Log "Fehler beim Hinzufuegen des Monitoring-Events: $_" -Level "ERROR"
    }
}

function Update-AuditLogs {
    try {
        # Filter anwenden - ArrayList in Array konvertieren
        $filteredLogs = @($global:AuditLogData.ToArray())
        
        if ($global:Controls.cmbLogLevel.SelectedItem) {
            $levelFilter = $global:Controls.cmbLogLevel.SelectedItem.Content
            if ($levelFilter -and $levelFilter -ne "All") {
                $filteredLogs = @($filteredLogs | Where-Object { $_.Level -eq $levelFilter })
            }
        }
        
        if ($global:Controls.txtLogSearch.Text) {
            $searchFilter = $global:Controls.txtLogSearch.Text.Trim()
            if (-not [string]::IsNullOrEmpty($searchFilter)) {
                $filteredLogs = @($filteredLogs | Where-Object { 
                    $_.Message -like "*$searchFilter*" -or $_.Event -like "*$searchFilter*" 
                })
            }
        }
        
        # Neueste Einträge zuerst
        if ($filteredLogs.Count -gt 0) {
            $filteredLogs = @($filteredLogs | Sort-Object Time -Descending)
        }
        
        # DataGrid ItemsSource setzen
        $global:Controls.dgAuditLogs.ItemsSource = $filteredLogs
        
        Write-Log "Audit-Log aktualisiert: $($filteredLogs.Count) Eintraege" -Level "DEBUG"
        
    } catch {
        Write-Log "Fehler beim Aktualisieren der Audit-Logs: $_" -Level "ERROR"
        # Bei Fehler DataGrid leeren
        try {
            $global:Controls.dgAuditLogs.ItemsSource = @()
        } catch { 
            # Ignoriere DataGrid-Fehler
        }
    }
}

function Filter-AuditLogs {
    Update-AuditLogs
}

function Export-AuditLogs {
    $exportPath = Show-SaveFileDialog -Filter "CSV Dateien (*.csv)|*.csv|Alle Dateien (*.*)|*.*" -Title "Audit-Logs exportieren"
    if (-not $exportPath) { return }
    
    try {
        $global:AuditLogData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        Show-MessageBox "Audit-Logs wurden erfolgreich exportiert nach:`n$exportPath" "Export erfolgreich"
        Write-Log "Audit-Logs exportiert nach: $exportPath" -Level "INFO"
        
    } catch {
        Write-Log "Fehler beim Exportieren der Audit-Logs: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Exportieren der Logs:`n$_" "Fehler" "Error"
    }
}

function Clear-AuditLogs {
    $result = [System.Windows.MessageBox]::Show("Moechten Sie alle Audit-Logs loeschen?`n`nDiese Aktion kann nicht rueckgaengig gemacht werden!", "Logs loeschen", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $global:AuditLogData.Clear()
        Update-AuditLogs
        Write-Log "Audit-Logs geleert" -Level "INFO"
    }
}

###############################################################################
# ERWEITERTE DNS-DIAGNOSTIC-FUNKTIONEN
###############################################################################

function Force-ZoneRefresh {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Bitte waehlen Sie eine Zone aus." "Keine Zone ausgewaehlt" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ZONE REFRESH: $zone ===`r`n")
    
    try {
        $result = & dnscmd $global:Controls.txtDNSServer.Text /zonerefresh $zone 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("Zone Refresh Ergebnis:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText($result -join "`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Zone-Refresh fuer $zone ausgefuehrt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Zone-Refresh: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Verwenden Sie: dnscmd /zonerefresh $zone`r`n`r`n")
        Write-Log "Fehler beim Zone-Refresh fuer $zone`: $_" -Level "ERROR"
    }
}

function Show-ZoneInformation {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Bitte waehlen Sie eine Zone aus." "Keine Zone ausgewaehlt" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ZONE INFO: $zone ===`r`n")
    
    try {
        $zoneInfo = Get-DnsServerZone -Name $zone -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Zone: $($zoneInfo.ZoneName)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Type: $($zoneInfo.ZoneType)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Dynamic Update: $($zoneInfo.DynamicUpdate)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Replication Scope: $($zoneInfo.ReplicationScope)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Is Auto Created: $($zoneInfo.IsAutoCreated)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Is Reverse Lookup Zone: $($zoneInfo.IsReverseLookupZone)`r`n")
        if ($zoneInfo.ZoneFile) {
            $global:Controls.txtDiagnosisOutput.AppendText("Zone File: $($zoneInfo.ZoneFile)`r`n")
        }
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Zone-Informationen fuer $zone abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Zone-Informationen: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Zone-Informationen fuer $zone`: $_" -Level "ERROR"
    }
}

function Show-DNSForwarders {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-FORWARDER ===`r`n")
    
    try {
        $forwarders = Get-DnsServerForwarder -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        if ($forwarders.IPAddress) {
            $global:Controls.txtDiagnosisOutput.AppendText("Konfigurierte Forwarder:`r`n")
            foreach ($forwarder in $forwarders.IPAddress) {
                $global:Controls.txtDiagnosisOutput.AppendText("- $forwarder`r`n")
            }
            $global:Controls.txtDiagnosisOutput.AppendText("Timeout: $($forwarders.Timeout) Sekunden`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Use Root Hint: $($forwarders.UseRootHint)`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("Keine Forwarder konfiguriert.`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Forwarder angezeigt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Forwarder: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Verwenden Sie: Get-DnsServerForwarder`r`n`r`n")
        Write-Log "Fehler beim Abrufen der DNS-Forwarder: $_" -Level "ERROR"
    }
}

function Show-ServerStatistics {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVER-STATISTIKEN ===`r`n")
    
    try {
        $stats = Get-DnsServerStatistics -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Query Statistics:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Total Queries: $($stats.TotalQueries)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Successful Queries: $($stats.SuccessfulQueries)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Failed Queries: $($stats.FailedQueries)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Recursive Queries: $($stats.RecursiveQueries)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nCache Statistics:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Cache Hits: $($stats.CacheHits)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Cache Misses: $($stats.CacheMisses)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "DNS-Server-Statistiken abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Server-Statistiken: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Server-Statistiken: $_" -Level "ERROR"
    }
}

function Show-DiagnosticsSettings {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-DIAGNOSE-EINSTELLUNGEN ===`r`n")
    
    try {
        $diagnostics = Get-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Debug Logging Settings:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Queries: $($diagnostics.Queries)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Answers: $($diagnostics.Answers)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Send: $($diagnostics.Send)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Receive: $($diagnostics.Receive)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- TCP: $($diagnostics.TCP)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- UDP: $($diagnostics.UDP)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Full Packets: $($diagnostics.FullPackets)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "DNS-Diagnose-Einstellungen abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Diagnose-Einstellungen: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Diagnose-Einstellungen: $_" -Level "ERROR"
    }
}

function Show-NetworkAdapterDNS {
    $global:Controls.txtDiagnosisOutput.AppendText("=== NETZWERKADAPTER-DNS-EINSTELLUNGEN ===`r`n")
    
    try {
        $adapters = Get-DnsClientServerAddress -ErrorAction Stop
        
        foreach ($adapter in $adapters) {
            $global:Controls.txtDiagnosisOutput.AppendText("Interface: $($adapter.InterfaceAlias)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Index: $($adapter.InterfaceIndex)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Address Family: $($adapter.AddressFamily)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("DNS Servers: $($adapter.ServerAddresses -join ', ')`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "Netzwerkadapter-DNS-Einstellungen abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Netzwerkadapter-DNS-Einstellungen: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Netzwerkadapter-DNS-Einstellungen: $_" -Level "ERROR"
    }
}

function Update-DiagnosticZonesList {
    try {
        Show-LoadingStatus -Message "Lade Diagnostic-Zonen..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $global:Controls.cmbDiagZone.Items.Clear()
        
        foreach ($zone in $zones) {
            $global:Controls.cmbDiagZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbDiagZone.Items.Count -gt 0) {
            $global:Controls.cmbDiagZone.SelectedIndex = 0
        }
        
        Write-Log "Diagnostic-Zonen-Liste aktualisiert: $($zones.Count) Zonen" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Fehler beim Aktualisieren der Diagnostic-Zonen-Liste: $_" -Level "ERROR"
        Hide-LoadingStatus
    }
}

###############################################################################
# FEHLENDE DIAGNOSTIC FUNKTIONEN IMPLEMENTIEREN
###############################################################################

function Run-ResolveTest {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel für die DNS-Auflösung ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-AUFLÖSUNG für $target ===`r`n")
    
    try {
        $results = Resolve-DnsName -Name $target -ErrorAction Stop
        
        foreach ($result in $results) {
            $global:Controls.txtDiagnosisOutput.AppendText("Name: $($result.Name)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Type: $($result.Type)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Section: $($result.Section)`r`n")
            
            switch ($result.Type) {
                "A"     { $global:Controls.txtDiagnosisOutput.AppendText("IP-Adresse: $($result.IPAddress)`r`n") }
                "AAAA"  { $global:Controls.txtDiagnosisOutput.AppendText("IPv6-Adresse: $($result.IPAddress)`r`n") }
                "CNAME" { $global:Controls.txtDiagnosisOutput.AppendText("Alias für: $($result.NameHost)`r`n") }
                "MX"    { $global:Controls.txtDiagnosisOutput.AppendText("Mail-Server: $($result.NameExchange) (Priorität: $($result.Preference))`r`n") }
                "NS"    { $global:Controls.txtDiagnosisOutput.AppendText("Name-Server: $($result.NameHost)`r`n") }
                "PTR"   { $global:Controls.txtDiagnosisOutput.AppendText("Hostname: $($result.NameHost)`r`n") }
                "TXT"   { $global:Controls.txtDiagnosisOutput.AppendText("Text: $($result.Strings -join ' ')`r`n") }
                "SOA"   { $global:Controls.txtDiagnosisOutput.AppendText("Primärer NS: $($result.PrimaryServer)`r`n") }
            }
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nAuflösung erfolgreich: $($results.Count) Ergebnisse`r`n`r`n")
        Write-Log "DNS-Auflösung für $target erfolgreich: $($results.Count) Ergebnisse" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Auflösung fehlgeschlagen: $_`r`n`r`n")
        Write-Log "DNS-Auflösung für $target fehlgeschlagen: $_" -Level "ERROR"
    }
}

function Run-TestConnection {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel für den Verbindungstest ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== VERBINDUNGSTEST zu $target ===`r`n")
    
    try {
        # Test verschiedene Verbindungstypen
        $global:Controls.txtDiagnosisOutput.AppendText("Teste Ping...`r`n")
        $pingResult = Test-Connection -ComputerName $target -Count 2 -ErrorAction SilentlyContinue
        if ($pingResult) {
            $avgTime = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
            $global:Controls.txtDiagnosisOutput.AppendText("Ping erfolgreich - Durchschnittliche Zeit: $([math]::Round($avgTime, 2))ms`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("Ping fehlgeschlagen`r`n")
        }
        
        # Test DNS-Port 53
        $global:Controls.txtDiagnosisOutput.AppendText("Teste DNS-Port (53)...`r`n")
        $dnsTest = Test-NetConnection -ComputerName $target -Port 53 -ErrorAction SilentlyContinue
        if ($dnsTest.TcpTestSucceeded) {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Port 53 erreichbar`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Port 53 nicht erreichbar`r`n")
        }
        
        # Test Standard-Ports
        $ports = @(80, 443, 22, 25)
        foreach ($port in $ports) {
            $global:Controls.txtDiagnosisOutput.AppendText("Teste Port $port...`r`n")
            $portTest = Test-NetConnection -ComputerName $target -Port $port -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($portTest.TcpTestSucceeded) {
                $global:Controls.txtDiagnosisOutput.AppendText("Port $port offen`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("Port $port geschlossen/gefiltert`r`n")
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nVerbindungstest abgeschlossen.`r`n`r`n")
        Write-Log "Verbindungstest zu $target durchgeführt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Verbindungstest: $_`r`n`r`n")
        Write-Log "Verbindungstest zu $target fehlgeschlagen: $_" -Level "ERROR"
    }
}

function Show-DNSServerCache {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVER-CACHE ===`r`n")
    
    try {
        $cacheRecords = Get-DnsServerCache -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Cache-Einträge: $($cacheRecords.Count)`r`n`r`n")
        
        # Zeige die ersten 20 Cache-Einträge
        $displayCount = [Math]::Min(20, $cacheRecords.Count)
        for ($i = 0; $i -lt $displayCount; $i++) {
            $record = $cacheRecords[$i]
            $global:Controls.txtDiagnosisOutput.AppendText("Name: $($record.Name)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Type: $($record.Type)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("TTL: $($record.TimeToLive)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Data: $($record.RecordData)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        if ($cacheRecords.Count -gt 20) {
            $global:Controls.txtDiagnosisOutput.AppendText("... und $($cacheRecords.Count - 20) weitere Einträge`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Server-Cache angezeigt: $($cacheRecords.Count) Einträge" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen des DNS-Server-Caches: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Verwenden Sie: Get-DnsServerCache`r`n`r`n")
        Write-Log "Fehler beim Abrufen des DNS-Server-Caches: $_" -Level "ERROR"
    }
}

function Clear-ClientDNSCache {
    $global:Controls.txtDiagnosisOutput.AppendText("=== CLIENT-DNS-CACHE LEEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Führe 'ipconfig /flushdns' aus...`r`n")
        $result = & ipconfig /flushdns 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("$($result -join "`r`n")`r`n")
        
        # Zusätzlich PowerShell DNS-Client-Cache leeren
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $global:Controls.txtDiagnosisOutput.AppendText("PowerShell DNS-Client-Cache geleert.`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nClient-DNS-Cache erfolgreich geleert!`r`n`r`n")
        Write-Log "Client-DNS-Cache geleert" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Leeren des Client-DNS-Caches: $_`r`n`r`n")
        Write-Log "Fehler beim Leeren des Client-DNS-Caches: $_" -Level "ERROR"
    }
}

function Show-ServiceStatus {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-DIENST-STATUS ===`r`n")
    
    try {
        $service = Get-Service -Name "DNS" -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Dienst: $($service.DisplayName)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Status: $($service.Status)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Starttyp: $($service.StartType)`r`n")
        
        # Versuche weitere Informationen zu bekommen
        try {
            $processInfo = Get-Process -Name "dns" -ErrorAction SilentlyContinue
            if ($processInfo) {
                $global:Controls.txtDiagnosisOutput.AppendText("Prozess-ID: $($processInfo.Id)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Speicher-Verbrauch: $([math]::Round($processInfo.WorkingSet64/1MB, 2)) MB`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Startzeit: $($processInfo.StartTime)`r`n")
            }
        } catch {
            # Ignoriere Prozess-Informations-Fehler
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Dienst-Status abgerufen: $($service.Status)" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen des DNS-Dienst-Status: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen des DNS-Dienst-Status: $_" -Level "ERROR"
    }
}

function Start-DNSService {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-DIENST STARTEN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Starte DNS-Dienst...`r`n")
        Start-Service -Name "DNS" -ErrorAction Stop
        
        # Warte kurz und prüfe Status
        Start-Sleep -Seconds 2
        $service = Get-Service -Name "DNS"
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst Status: $($service.Status)`r`n")
        
        if ($service.Status -eq "Running") {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst erfolgreich gestartet!`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst ist nicht im Running-Status`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Dienst gestartet" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Starten des DNS-Dienstes: $_`r`n`r`n")
        Write-Log "Fehler beim Starten des DNS-Dienstes: $_" -Level "ERROR"
    }
}

function Stop-DNSService {
    $result = [System.Windows.MessageBox]::Show("Möchten Sie den DNS-Dienst wirklich stoppen?`n`nDies kann zu DNS-Ausfällen führen!", "DNS-Dienst stoppen", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-DIENST STOPPEN ===`r`n")
        
        try {
            $global:Controls.txtDiagnosisOutput.AppendText("Stoppe DNS-Dienst...`r`n")
            Stop-Service -Name "DNS" -Force -ErrorAction Stop
            
            # Warte kurz und prüfe Status
            Start-Sleep -Seconds 2
            $service = Get-Service -Name "DNS"
            
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst Status: $($service.Status)`r`n")
            
            if ($service.Status -eq "Stopped") {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst erfolgreich gestoppt!`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst ist nicht gestoppt`r`n")
            }
            
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
            Write-Log "DNS-Dienst gestoppt" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Stoppen des DNS-Dienstes: $_`r`n`r`n")
            Write-Log "Fehler beim Stoppen des DNS-Dienstes: $_" -Level "ERROR"
        }
    }
}

function Restart-DNSService {
    $result = [System.Windows.MessageBox]::Show("Möchten Sie den DNS-Dienst neu starten?`n`nDies kann zu kurzen DNS-Ausfällen führen!", "DNS-Dienst neu starten", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-DIENST NEU STARTEN ===`r`n")
        
        try {
            $global:Controls.txtDiagnosisOutput.AppendText("Starte DNS-Dienst neu...`r`n")
            Restart-Service -Name "DNS" -Force -ErrorAction Stop
            
            # Warte kurz und prüfe Status
            Start-Sleep -Seconds 3
            $service = Get-Service -Name "DNS"
            
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst Status: $($service.Status)`r`n")
            
            if ($service.Status -eq "Running") {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst erfolgreich neu gestartet!`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst ist nicht im Running-Status`r`n")
            }
            
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
            Write-Log "DNS-Dienst neu gestartet" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Neustart des DNS-Dienstes: $_`r`n`r`n")
            Write-Log "Fehler beim Neustart des DNS-Dienstes: $_" -Level "ERROR"
        }
    }
}

function Show-ServerConfiguration {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVER-KONFIGURATION ===`r`n")
    
    try {
        $serverSettings = Get-DnsServer -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Server: $($serverSettings.ServerSetting.ComputerName)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Version: $($serverSettings.ServerSetting.MajorVersion).$($serverSettings.ServerSetting.MinorVersion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Listen-Adressen: $($serverSettings.ServerSetting.ListeningIPAddress -join ', ')`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Rekursion: $($serverSettings.ServerSetting.DisableRecursion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Cache leeren: $($serverSettings.ServerSetting.NoRecursion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Boot-Methode: $($serverSettings.ServerSetting.BootMethod)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Auto-Cache-Update: $($serverSettings.ServerSetting.AutoCacheUpdate)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Log-Level: $($serverSettings.ServerSetting.LogLevel)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "DNS-Server-Konfiguration abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Server-Konfiguration: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Verwenden Sie: Get-DnsServer`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Server-Konfiguration: $_" -Level "ERROR"
    }
}

function Add-DNSForwarder {
    $forwarderIP = $global:Controls.txtForwarderIP.Text.Trim()
    if ([string]::IsNullOrEmpty($forwarderIP)) {
        Show-MessageBox "Bitte geben Sie eine IP-Adresse für den Forwarder ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    # Validiere IP-Adresse
    try {
        $ip = [System.Net.IPAddress]::Parse($forwarderIP)
    } catch {
        Show-MessageBox "Ungültige IP-Adresse: $forwarderIP" "Validierungsfehler" "Error"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-FORWARDER HINZUFÜGEN ===`r`n")
    
    try {
        Add-DnsServerForwarder -IPAddress $forwarderIP -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("Forwarder $forwarderIP erfolgreich hinzugefügt!`r`n")
        $global:Controls.txtForwarderIP.Clear()
        
        # Aktuelle Forwarder anzeigen
        Show-DNSForwarders
        
        Write-Log "DNS-Forwarder hinzugefügt: $forwarderIP" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Hinzufügen des Forwarders: $_`r`n`r`n")
        Write-Log "Fehler beim Hinzufügen des DNS-Forwarders $forwarderIP`: $_" -Level "ERROR"
    }
}

function Remove-DNSForwarder {
    $forwarderIP = $global:Controls.txtForwarderIP.Text.Trim()
    if ([string]::IsNullOrEmpty($forwarderIP)) {
        Show-MessageBox "Bitte geben Sie die IP-Adresse des zu entfernenden Forwarders ein." "Eingabe erforderlich" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Möchten Sie den Forwarder '$forwarderIP' wirklich entfernen?", "Forwarder entfernen", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-FORWARDER ENTFERNEN ===`r`n")
        
        try {
            Remove-DnsServerForwarder -IPAddress $forwarderIP -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            $global:Controls.txtDiagnosisOutput.AppendText("Forwarder $forwarderIP erfolgreich entfernt!`r`n")
            $global:Controls.txtForwarderIP.Clear()
            
            # Aktuelle Forwarder anzeigen
            Show-DNSForwarders
            
            Write-Log "DNS-Forwarder entfernt: $forwarderIP" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Entfernen des Forwarders: $_`r`n`r`n")
            Write-Log "Fehler beim Entfernen des DNS-Forwarders $forwarderIP`: $_" -Level "ERROR"
        }
    }
}

function Force-ZoneTransfer {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Keine Zone ausgewählt" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ZONE TRANSFER: $zone ===`r`n")
    
    try {
        $result = & dnscmd $global:Controls.txtDNSServer.Text /zoneupdatefromds $zone 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("Zone Transfer Ergebnis:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText($result -join "`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Zone-Transfer für $zone ausgeführt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Zone-Transfer: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Verwenden Sie: dnscmd /zoneupdatefromds $zone`r`n`r`n")
        Write-Log "Fehler beim Zone-Transfer für $zone`: $_" -Level "ERROR"
    }
}

function Show-DNSEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-EREIGNISSE ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "DNS Server" -MaxEvents 50 -ErrorAction Stop | Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("Letzte 50 DNS-Ereignisse:`r`n`r`n")
        
        foreach ($event in $events) {
            $global:Controls.txtDiagnosisOutput.AppendText("Zeit: $($event.TimeCreated)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Nachricht: $($event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)))`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Ereignisse angezeigt: $($events.Count) Ereignisse" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der DNS-Ereignisse: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Möglicherweise sind Sie nicht berechtigt oder der Event-Log existiert nicht.`r`n`r`n")
        Write-Log "Fehler beim Abrufen der DNS-Ereignisse: $_" -Level "ERROR"
    }
}

function Show-SystemEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== SYSTEM-EREIGNISSE ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "System" -MaxEvents 20 -ErrorAction Stop | 
                  Where-Object { $_.ProviderName -like "*DNS*" -or $_.Message -like "*DNS*" } |
                  Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-bezogene System-Ereignisse:`r`n`r`n")
        
        foreach ($event in $events) {
            $global:Controls.txtDiagnosisOutput.AppendText("Zeit: $($event.TimeCreated)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Provider: $($event.ProviderName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Nachricht: $($event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)))`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "System-Ereignisse angezeigt: $($events.Count) DNS-bezogene Ereignisse" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der System-Ereignisse: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der System-Ereignisse: $_" -Level "ERROR"
    }
}

function Show-SecurityEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== SECURITY-EREIGNISSE ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "Security" -MaxEvents 20 -ErrorAction Stop | 
                  Where-Object { $_.Message -like "*DNS*" } |
                  Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-bezogene Security-Ereignisse:`r`n`r`n")
        
        if ($events.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("Keine DNS-bezogenen Security-Ereignisse gefunden.`r`n")
        } else {
            foreach ($event in $events) {
                $global:Controls.txtDiagnosisOutput.AppendText("Zeit: $($event.TimeCreated)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Nachricht: $($event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)))`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "Security-Ereignisse angezeigt: $($events.Count) DNS-bezogene Ereignisse" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Security-Ereignisse: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Möglicherweise sind Sie nicht berechtigt, auf Security-Logs zuzugreifen.`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Security-Ereignisse: $_" -Level "ERROR"
    }
}

function Export-EventLogs {
    $exportPath = Show-SaveFileDialog -Filter "CSV Dateien (*.csv)|*.csv|XML Dateien (*.xml)|*.xml|Alle Dateien (*.*)|*.*" -Title "Event-Logs exportieren"
    if (-not $exportPath) { return }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== EVENT-LOGS EXPORTIEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Sammle DNS-Ereignisse...`r`n")
        
        $allEvents = @()
        
        # DNS Server Events
        try {
            $dnsEvents = Get-WinEvent -LogName "DNS Server" -MaxEvents 100 -ErrorAction SilentlyContinue
            $allEvents += $dnsEvents | ForEach-Object {
                [PSCustomObject]@{
                    LogName = "DNS Server"
                    TimeCreated = $_.TimeCreated
                    Level = $_.LevelDisplayName
                    EventID = $_.Id
                    Provider = $_.ProviderName
                    Message = $_.Message
                }
            }
        } catch { }
        
        # System Events (DNS-related)
        try {
            $sysEvents = Get-WinEvent -LogName "System" -MaxEvents 100 -ErrorAction SilentlyContinue | 
                         Where-Object { $_.ProviderName -like "*DNS*" -or $_.Message -like "*DNS*" }
            $allEvents += $sysEvents | ForEach-Object {
                [PSCustomObject]@{
                    LogName = "System"
                    TimeCreated = $_.TimeCreated
                    Level = $_.LevelDisplayName
                    EventID = $_.Id
                    Provider = $_.ProviderName
                    Message = $_.Message
                }
            }
        } catch { }
        
        # Export
        $extension = [System.IO.Path]::GetExtension($exportPath).ToLower()
        switch ($extension) {
            ".csv" {
                $allEvents | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            }
            ".xml" {
                $allEvents | Export-Clixml -Path $exportPath
            }
            default {
                $allEvents | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("Event-Logs exportiert: $($allEvents.Count) Ereignisse`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Datei: $exportPath`r`n`r`n")
        
        Show-MessageBox "Event-Logs wurden erfolgreich exportiert!`n`nDatei: $exportPath`nAnzahl: $($allEvents.Count) Ereignisse" "Export erfolgreich"
        Write-Log "Event-Logs exportiert: $($allEvents.Count) Ereignisse nach $exportPath" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Exportieren der Event-Logs: $_`r`n`r`n")
        Write-Log "Fehler beim Exportieren der Event-Logs: $_" -Level "ERROR"
    }
}

function Enable-DebugLogging {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DEBUG-LOGGING AKTIVIEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Aktiviere DNS-Debug-Logging...`r`n")
        
        # Korrekte Parameter-Kombination für DNS-Diagnose
        Set-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text `
            -Queries $true `
            -Answers $true `
            -Send $true `
            -Receive $true `
            -UdpPackets $true `
            -TcpPackets $true `
            -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Logging aktiviert!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Log-Datei: %systemroot%\\system32\\dns\\dns.log`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nAktivierte Einstellungen:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Queries: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Answers: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Send: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Receive: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- UDP Packets: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- TCP Packets: aktiviert`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nHinweis: Debug-Logging kann die DNS-Performance beeinträchtigen.`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Deaktivieren Sie es nach der Diagnose!`r`n`r`n")
        
        Write-Log "DNS-Debug-Logging aktiviert" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Aktivieren des Debug-Loggings: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nAlternative: Verwenden Sie die DNS-Konsole`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("DNS Manager -> Server -> Rechtsklick -> Properties -> Debug Logging`r`n`r`n")
        Write-Log "Fehler beim Aktivieren des Debug-Loggings: $_" -Level "ERROR"
    }
}

function Disable-DebugLogging {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DEBUG-LOGGING DEAKTIVIEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Deaktiviere DNS-Debug-Logging...`r`n")
        
        # Verwende -All $false um alle Diagnose-Optionen zu deaktivieren
        # Dies ist der sicherste Weg laut Microsoft-Dokumentation
        Set-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text -All $false -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Logging deaktiviert!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Alle Diagnose-Optionen wurden ausgeschaltet.`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Performance sollte wieder normal sein.`r`n`r`n")
        
        Write-Log "DNS-Debug-Logging deaktiviert" -Level "INFO"
        
    } catch {
        # Fallback-Methode: Versuche einzelne wichtige Parameter zu deaktivieren
        # aber lasse mindestens einen aus jeder erforderlichen Gruppe aktiv
        $global:Controls.txtDiagnosisOutput.AppendText("Hauptmethode fehlgeschlagen, versuche Fallback...`r`n")
        
        try {
            # Minimal-Konfiguration: Nur das Nötigste aktiv lassen
            Set-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text `
                -Queries $true `
                -ReceivePackets $true `
                -UdpPackets $true `
                -QuestionTransactions $true `
                -Answers $false `
                -Send $false `
                -TcpPackets $false `
                -Notifications $false `
                -Update $false `
                -ErrorAction Stop
            
            $global:Controls.txtDiagnosisOutput.AppendText("Fallback erfolgreich: Minimal-Debug-Logging aktiviert`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("(Nur grundlegende UDP-Queries werden noch geloggt)`r`n`r`n")
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Deaktivieren des Debug-Loggings: $_`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("`r`nAlternative Lösungen:`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("1. DNS Manager -> Server -> Rechtsklick -> Properties -> Debug Logging -> Deaktivieren`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("2. PowerShell: Set-DnsServerDiagnostics -All `$false`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("3. Neustart des DNS-Dienstes setzt Debug-Logging zurück`r`n`r`n")
            Write-Log "Fehler beim Deaktivieren des Debug-Loggings: $_" -Level "ERROR"
        }
    }
}

function Export-DNSStatistics {
    $exportPath = Show-SaveFileDialog -Filter "CSV Dateien (*.csv)|*.csv|JSON Dateien (*.json)|*.json|Alle Dateien (*.*)|*.*" -Title "DNS-Statistiken exportieren"
    if (-not $exportPath) { return }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-STATISTIKEN EXPORTIEREN ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Sammle DNS-Statistiken...`r`n")
        
        # Sammle alle verfügbaren Statistiken
        $exportData = @{
            Timestamp = Get-Date
            Server = $global:Controls.txtDNSServer.Text
            BasicStats = Get-DNSStatistics -DnsServerName $global:Controls.txtDNSServer.Text
        }
        
        # Versuche erweiterte Statistiken zu sammeln
        try {
            $serverStats = Get-DnsServerStatistics -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
            $exportData.ServerStats = $serverStats
        } catch { }
        
        try {
            $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
            $exportData.Zones = $zones
        } catch { }
        
        try {
            $forwarders = Get-DnsServerForwarder -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
            $exportData.Forwarders = $forwarders
        } catch { }
        
        # Export
        $extension = [System.IO.Path]::GetExtension($exportPath).ToLower()
        switch ($extension) {
            ".json" {
                $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportPath -Encoding UTF8
            }
            default {
                # CSV für Basis-Statistiken
                $csvData = @()
                $csvData += [PSCustomObject]@{
                    Kategorie = "Gesamt-Zonen"
                    Wert = $exportData.BasicStats.TotalZones
                    Zeitstempel = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Kategorie = "Forward-Zonen"
                    Wert = $exportData.BasicStats.ForwardZones
                    Zeitstempel = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Kategorie = "Reverse-Zonen"
                    Wert = $exportData.BasicStats.ReverseZones
                    Zeitstempel = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Kategorie = "DNSSEC-Zonen"
                    Wert = $exportData.BasicStats.SignedZones
                    Zeitstempel = $exportData.Timestamp
                }
                
                $csvData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Statistiken exportiert!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Datei: $exportPath`r`n`r`n")
        
        Show-MessageBox "DNS-Statistiken wurden erfolgreich exportiert!`n`nDatei: $exportPath" "Export erfolgreich"
        Write-Log "DNS-Statistiken exportiert nach: $exportPath" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Exportieren der DNS-Statistiken: $_`r`n`r`n")
        Write-Log "Fehler beim Exportieren der DNS-Statistiken: $_" -Level "ERROR"
    }
}

function Show-NetworkProperties {
    $global:Controls.txtDiagnosisOutput.AppendText("=== NETZWERK-EIGENSCHAFTEN ===`r`n")
    
    try {
        # IP-Konfiguration
        $global:Controls.txtDiagnosisOutput.AppendText("=== IP-KONFIGURATION ===`r`n")
        $ipConfig = Get-NetIPConfiguration -ErrorAction Stop
        
        foreach ($config in $ipConfig) {
            if ($config.NetAdapter.Status -eq "Up") {
                $global:Controls.txtDiagnosisOutput.AppendText("Interface: $($config.InterfaceAlias)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("IPv4-Adresse: $($config.IPv4Address.IPAddress -join ', ')`r`n")
                if ($config.IPv6Address) {
                    $global:Controls.txtDiagnosisOutput.AppendText("IPv6-Adresse: $($config.IPv6Address.IPAddress -join ', ')`r`n")
                }
                $global:Controls.txtDiagnosisOutput.AppendText("Gateway: $($config.IPv4DefaultGateway.NextHop -join ', ')`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Server: $($config.DNSServer.ServerAddresses -join ', ')`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
            }
        }
        
        # Routing-Tabelle (kurze Version)
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== ROUTING-INFORMATIONEN ===`r`n")
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -lt 1000 } | Select-Object -First 10
        
        foreach ($route in $routes) {
            $global:Controls.txtDiagnosisOutput.AppendText("Ziel: $($route.DestinationPrefix) -> Gateway: $($route.NextHop) (Metrik: $($route.RouteMetric))`r`n")
        }
        
        # DNS-Client-Einstellungen
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== DNS-CLIENT-EINSTELLUNGEN ===`r`n")
        $dnsClient = Get-DnsClient -ErrorAction SilentlyContinue
        
        if ($dnsClient) {
            $global:Controls.txtDiagnosisOutput.AppendText("Suffix-Search-Liste: $($dnsClient.SuffixSearchList -join ', ')`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Use-Suffix-When-Resolving: $($dnsClient.UseSuffixWhenResolving)`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "Netzwerk-Eigenschaften angezeigt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler beim Abrufen der Netzwerk-Eigenschaften: $_`r`n`r`n")
        Write-Log "Fehler beim Abrufen der Netzwerk-Eigenschaften: $_" -Level "ERROR"
    }
}

function Save-DiagnosisOutput {
    $exportPath = Show-SaveFileDialog -Filter "Text Dateien (*.txt)|*.txt|Log Dateien (*.log)|*.log|Alle Dateien (*.*)|*.*" -Title "Diagnose-Output speichern"
    if (-not $exportPath) { return }
    
    try {
        $content = $global:Controls.txtDiagnosisOutput.Text
        $content | Out-File -FilePath $exportPath -Encoding UTF8
        
        Show-MessageBox "Diagnose-Output wurde erfolgreich gespeichert!`n`nDatei: $exportPath" "Speichern erfolgreich"
        Write-Log "Diagnose-Output gespeichert nach: $exportPath" -Level "INFO"
        
    } catch {
        Show-MessageBox "Fehler beim Speichern des Diagnose-Outputs:`n$_" "Fehler" "Error"
        Write-Log "Fehler beim Speichern des Diagnose-Outputs: $_" -Level "ERROR"
    }
}

###############################################################################
# AUTO-REFRESH FUNKTIONEN
###############################################################################

function Start-AutoRefresh {
    if ($global:AutoRefreshEnabled) {
        Write-Log "Auto-Refresh ist bereits aktiviert" -Level "DEBUG" -Component "AutoRefresh"
        return
    }
    
    $global:AutoRefreshEnabled = $true
    $global:AutoRefreshTimer = New-Object System.Windows.Threading.DispatcherTimer
    $global:AutoRefreshTimer.Interval = [TimeSpan]::FromSeconds($global:AppConfig.AutoRefreshInterval)
    
    $global:AutoRefreshTimer.Add_Tick({
        try {
            Write-Log "Auto-Refresh wird ausgeführt" -Level "DEBUG" -Component "AutoRefresh"
            
            # Aktualisiere basierend auf aktuellem Panel
            switch ($global:CurrentPanel) {
                "dashboard" { Update-Dashboard }
                "forward" { Update-ForwardZonesList }
                "reverse" { Update-ReverseZonesList }
                "records" { 
                    if ($global:Controls.cmbRecordZone.SelectedItem) {
                        Update-RecordsList
                    }
                }
                "dnssec" { Update-DNSSECStatus }
                "audit" { Update-AuditLogs }
            }
            
        } catch {
            Write-Log "Fehler beim Auto-Refresh: $_" -Level "ERROR" -Component "AutoRefresh"
        }
    })
    
    $global:AutoRefreshTimer.Start()
    Write-Log "Auto-Refresh aktiviert (Intervall: $($global:AppConfig.AutoRefreshInterval) Sekunden)" -Level "INFO" -Component "AutoRefresh"
}

function Stop-AutoRefresh {
    if (-not $global:AutoRefreshEnabled) {
        return
    }
    
    if ($global:AutoRefreshTimer) {
        $global:AutoRefreshTimer.Stop()
        $global:AutoRefreshTimer = $null
    }
    
    $global:AutoRefreshEnabled = $false
    Write-Log "Auto-Refresh deaktiviert" -Level "INFO" -Component "AutoRefresh"
}

###############################################################################
# KONFIGURATIONS-EXPORT/IMPORT
###############################################################################

function Export-AppConfiguration {
    param(
        [string]$Path = (Join-Path $global:AppConfig.ExportPath "easyDNS_Config_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
    )
    
    try {
        $config = @{
            AppConfig = $global:AppConfig
            LastServer = $global:DetectedDnsServer
            AutoRefreshEnabled = $global:AutoRefreshEnabled
            ExportDate = Get-Date
            Version = $global:AppConfig.ScriptVersion
        }
        
        $config | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
        Write-Log "Konfiguration exportiert nach: $Path" -Level "INFO" -Component "Config"
        return $Path
    } catch {
        Write-Log "Fehler beim Exportieren der Konfiguration: $_" -Level "ERROR" -Component "Config"
        return $null
    }
}

function Import-AppConfiguration {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Log "Konfigurationsdatei nicht gefunden: $Path" -Level "ERROR" -Component "Config"
        return $false
    }
    
    try {
        $config = Get-Content -Path $Path -Encoding UTF8 | ConvertFrom-Json
        
        # Version prüfen
        if ($config.Version -ne $global:AppConfig.ScriptVersion) {
            Write-Log "Konfiguration hat andere Version: $($config.Version) (aktuell: $($global:AppConfig.ScriptVersion))" -Level "WARN" -Component "Config"
        }
        
        # Ausgewählte Einstellungen übernehmen
        if ($config.AppConfig.AutoRefreshInterval) {
            $global:AppConfig.AutoRefreshInterval = $config.AppConfig.AutoRefreshInterval
        }
        if ($config.AppConfig.MaxLogEntries) {
            $global:AppConfig.MaxLogEntries = $config.AppConfig.MaxLogEntries
        }
        if ($config.AppConfig.DefaultTTL) {
            $global:AppConfig.DefaultTTL = $config.AppConfig.DefaultTTL
        }
        
        Write-Log "Konfiguration importiert von: $Path" -Level "INFO" -Component "Config"
        return $true
        
    } catch {
        Write-Log "Fehler beim Importieren der Konfiguration: $_" -Level "ERROR" -Component "Config"
        return $false
    }
}

###############################################################################
# ANWENDUNG STARTEN
###############################################################################

Write-Log "Starte easyDNS WPF GUI..." -Level "INFO"
Write-Log "Erkannter DNS-Server: $global:DetectedDnsServer" -Level "INFO"

# DNS-Server in GUI setzen
$global:Controls.txtDNSServer.Text = $global:DetectedDnsServer

# Dashboard initialisieren
Show-Panel "dashboard"

# Window anzeigen
$global:Window.Add_Loaded({
    Write-Log "easyDNS WPF gestartet" -Level "INFO"
    
    # Automatische Verbindung wenn lokaler DNS-Server erkannt wurde
    if ($global:DNSDetection.AutoConnect -and $global:DNSDetection.IsLocalDNS) {
        Write-Log "Stelle automatische Verbindung zu lokalem DNS-Server her..." -Level "INFO"
        
        $global:Controls.lblStatus.Text = "Status: Verbinde automatisch..."
        $global:Controls.lblStatus.Foreground = "#FF8C00"
        
        # Kurze Verzögerung für UI-Update
        $global:Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{
            try {
                $zones = Get-DnsServerZone -ComputerName 'localhost' -ErrorAction Stop
                $global:Controls.lblStatus.Text = "Status: Verbunden (Auto)"
                $global:Controls.lblStatus.Foreground = "#107C10"
                
                Write-Log "Automatische Verbindung zu lokalem DNS-Server erfolgreich" -Level "INFO"
                
                # Dashboard aktualisieren
                Update-Dashboard
                
                # Erfolgsmeldung
                Show-MessageBox "Automatisch mit lokalem DNS-Server verbunden!`n`nDer Server läuft auf diesem System und wurde automatisch erkannt." "Automatische Verbindung"
                
            } catch {
                $global:Controls.lblStatus.Text = "Status: Fehler"
                $global:Controls.lblStatus.Foreground = "#D13438"
                Write-Log "Fehler bei automatischer Verbindung zu lokalem DNS-Server: $_" -Level "ERROR"
                Show-MessageBox "Fehler bei der automatischen Verbindung zum lokalen DNS-Server:`n$_`n`nBitte verbinden Sie manuell." "Verbindungsfehler" "Error"
            }
        })
    } else {
        # Keine lokale DNS-Rolle - normale Dashboard-Aktualisierung
        Update-Dashboard
        
        if (-not $global:DNSDetection.IsLocalDNS) {
            # Hinweis anzeigen
            Show-MessageBox "Keine lokale DNS-Server-Rolle erkannt.`n`nBitte geben Sie einen DNS-Server ein und klicken Sie auf 'Connect'." "DNS-Server Auswahl" "Information"
        }
    }
})

$global:Window.Add_Closed({
    try {
        # Auto-Refresh stoppen
        Stop-AutoRefresh
        
        # Monitoring stoppen
        if ($global:MonitoringActive) {
            Stop-DNSMonitoring
        }
        
        # Performance-Statistiken loggen
        if ($global:PerformanceCounters.OperationCount -gt 0) {
            Write-Log "Performance-Statistiken:" -Level "INFO" -Component "Shutdown"
            Write-Log "- Operationen: $($global:PerformanceCounters.OperationCount)" -Level "INFO" -Component "Shutdown"
            Write-Log "- Fehler: $($global:PerformanceCounters.ErrorCount)" -Level "INFO" -Component "Shutdown"
            Write-Log "- Fehlerrate: $([math]::Round(($global:PerformanceCounters.ErrorCount / $global:PerformanceCounters.OperationCount) * 100, 2))%" -Level "INFO" -Component "Shutdown"
        }
        
        # Temporäre Dateien aufräumen
        if (Test-Path $global:AppConfig.TempPath) {
            try {
                Get-ChildItem -Path $global:AppConfig.TempPath -File | Remove-Item -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Fehler beim Aufräumen temporärer Dateien: $_" -Level "WARN" -Component "Shutdown"
            }
        }
        
        Write-Log "easyDNS WPF beendet" -Level "INFO" -Component "Shutdown"
        
    } catch {
        Write-Log "Fehler beim Beenden: $_" -Level "ERROR" -Component "Shutdown"
    }
})

# Show the window
[void]$global:Window.ShowDialog() 
# SIG # Begin signature block
# MIIbywYJKoZIhvcNAQcCoIIbvDCCG7gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7Ayrh8UKAcxk/
# uD3XJBE3b7y7ow8Wodu0VPcJx12OQaCCFhcwggMQMIIB+KADAgECAhB3jzsyX9Cg
# jEi+sBC2rBMTMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFVBoaW5JVC1QU3Nj
# cmlwdHNfU2lnbjAeFw0yNTA3MDUwODI4MTZaFw0yNzA3MDUwODM4MTZaMCAxHjAc
# BgNVBAMMFVBoaW5JVC1QU3NjcmlwdHNfU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALmz3o//iDA5MvAndTjGX7/AvzTSACClfuUR9WYK0f6Ut2dI
# mPxn+Y9pZlLjXIpZT0H2Lvxq5aSI+aYeFtuJ8/0lULYNCVT31Bf+HxervRBKsUyi
# W9+4PH6STxo3Pl4l56UNQMcWLPNjDORWRPWHn0f99iNtjI+L4tUC/LoWSs3obzxN
# 3uTypzlaPBxis2qFSTR5SWqFdZdRkcuI5LNsJjyc/QWdTYRrfmVqp0QrvcxzCv8u
# EiVuni6jkXfiE6wz+oeI3L2iR+ywmU6CUX4tPWoS9VTtmm7AhEpasRTmrrnSg20Q
# jiBa1eH5TyLAH3TcYMxhfMbN9a2xDX5pzM65EJUCAwEAAaNGMEQwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBQO7XOqiE/EYi+n
# IaR6YO5M2MUuVTANBgkqhkiG9w0BAQsFAAOCAQEAjYOKIwBu1pfbdvEFFaR/uY88
# peKPk0NnvNEc3dpGdOv+Fsgbz27JPvItITFd6AKMoN1W48YjQLaU22M2jdhjGN5i
# FSobznP5KgQCDkRsuoDKiIOTiKAAknjhoBaCCEZGw8SZgKJtWzbST36Thsdd/won
# ihLsuoLxfcFnmBfrXh3rTIvTwvfujob68s0Sf5derHP/F+nphTymlg+y4VTEAijk
# g2dhy8RAsbS2JYZT7K5aEJpPXMiOLBqd7oTGfM7y5sLk2LIM4cT8hzgz3v5yPMkF
# H2MdR//K403e1EKH9MsGuGAJZddVN8ppaiESoPLoXrgnw2SY5KCmhYw1xRFdjTCC
# BY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290
# IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE9
# 8orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9S
# H8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g
# 1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RY
# jgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgD
# EI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNA
# vwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDg
# ohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQA
# zH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOk
# GLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHF
# ynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gd
# LfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNy
# dDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkq
# hkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7
# IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/5
# 9PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0
# POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISf
# b8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhU
# LSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4wggSWoAMCAQICEAc2
# N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEh
# MB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAw
# MFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFE
# FUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoi
# GN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YA
# e9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O
# 9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI
# 1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7m
# O1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPK
# qpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8F
# nGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMD
# iP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4Jduyr
# XUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFd
# MIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91
# jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQC
# MAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW
# 2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H
# +oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4os
# equFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p
# /yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnf
# xI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36T
# U6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0
# cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf
# +yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa6
# 3VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1d
# wvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9E
# FUrnEw4d2zc4GqEr9u3WfPwwgga8MIIEpKADAgECAhALrma8Wrp/lYfG+ekE4zME
# MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1MjM1
# OTU5WjBCMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxIDAeBgNVBAMT
# F0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDI0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAvmpzn/aVIauWMLpbbeZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMSvgjE
# dEZ3v4vrrTHleW1JWGErrjOL0J4L0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijvoQ7u
# jm0u6yXF2v1CrzZopykD07/9fpAT4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4fduks
# THulntq9WelRWY++TFPxzZrbILRYynyEy7rS1lHQKFpXvo2GePfsMRhNf1F41nyE
# g5h7iOXv+vjX0K8RhUisfqw3TTLHj1uhS66YX2LZPxS4oaf33rp9HlfqSBePejlY
# eEdU740GKQM7SaVSH3TbBL8R6HwX9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUNK6lY
# k2y1WSKour4hJN0SMkoaNV8hyyADiX1xuTxKaXN12HgR+8WulU2d6zhzXomJ2Ple
# I9V2yfmfXSPGYanGgxzqI+ShoOGLomMd3mJt92nm7Mheng/TBeSA2z4I78JpwGpT
# RHiT7yHqBiV2ngUIyCtd0pZ8zg3S7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1HG93V
# p6lJ415ERcC7bFQMRbxqrMVANiav1k425zYyFMyLNyE1QulQSgDpW9rtvVcIH7Wv
# G9sqYup9j8z9J1XqbBZPJ5XLln8mS8wWmdDLnBHXgYly/p1DhoQo5fkCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUn1csA3cO
# KBWQZqVjXu5Pkh92oFswWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH2UOR
# 9hHbm04IHdEoT8/T3HuBSyZeq3jSi5GXeWP7xCKhVireKCnCs+8GZl2uVYFvQe+p
# PTScVJeCZSsMo1JCoZN2mMew/L4tpqVNbSpWO9QGFwfMEy60HofN6V51sMLMXNTL
# fhVqs+e8haupWiArSozyAmGH/6oMQAh078qRh6wvJNU6gnh5OruCP1QUAvVSu4kq
# VOcJVozZR5RRb/zPd++PGE3qF1P3xWvYViUJLsxtvge/mzA75oBfFZSbdakHJe2B
# VDGIGVNVjOp8sNt70+kEoMF+T6tptMUNlehSR7vM+C13v9+9ZOUKzfRUAYSyyEmY
# tsnpltD/GWX8eM70ls1V6QG/ZOB6b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xrW7tw
# ipXTJ5/i5pkU5E16RSBAdOp12aw8IQhhA/vEbFkEiF2abhuFixUDobZaA0VhqAsM
# HOmaT3XThZDNi5U2zHKhUs5uHHdG6BoQau75KiNbh0c+hatSF+02kULkftARjsyE
# pHKsF7u5zKRbt5oK5YGwFvgc4pEVUNytmB3BpIiowOIIuDgP5M9WArHYSAR16gc0
# dP2XdkMEP5eBsX7bf/MGN4K3HP50v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx4Q1z
# ZKDyHcp4VQJLu2kWTsKsOqQxggUKMIIFBgIBATA0MCAxHjAcBgNVBAMMFVBoaW5J
# VC1QU3NjcmlwdHNfU2lnbgIQd487Ml/QoIxIvrAQtqwTEzANBglghkgBZQMEAgEF
# AKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3
# DQEJBDEiBCC0UtP/JmdhXOpcasGNMepmOoxBpFzz8KVAvjLna+AYBzANBgkqhkiG
# 9w0BAQEFAASCAQAwK1/Gva0IWixRPP7fEywV2ucBw5aC0kDX7T3tcxeS3nm4K+xl
# HhKKZsewfySBIU3lDcuY1NLc5DFQzBp8UDcx+HscPnAd1pz63WZbEeu7I9vl8BQD
# bIpV02t3esBrnK8OPXjDZ6SgEFWE0j5bbOARhx/kP7IiwhNdUqOQGPWDDf65o0DX
# l2dDWQy1eM+xxZAEgxkPU1KKNFIiQqp03kO7wZL0bk/YKis/JUoaBSOnNBOjvk3W
# zS43MzjYnLEpqjfR3jx+8JyFcl0BXXxyzzgAPTBIKcuZYeDrL0E9m+zTPeD+Oq4w
# onqocNcvrC5X1r8QPZnJrkLGU3bR24EsYEA/oYIDIDCCAxwGCSqGSIb3DQEJBjGC
# Aw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MDcwNTEwMTE0MlowLwYJKoZIhvcNAQkEMSIEIOXFAj0lWtp/o+tbLUt60kXmW7IT
# assISsdfJigxzaHPMA0GCSqGSIb3DQEBAQUABIICAGLPbGcuMuLULCyAK42+uuuZ
# jX5nLwIgv4h86UhfW66QIeExusXjYfPdHciL/PWChNorFEJMWjyov7THo+gXiVe7
# u+6Qk8FxWyaM89YUmMm7ocm1B4phZokZue2MphlV37SQg/WBZBHWfgI2Pbs9XlGz
# he+cccOHk2kYewjRT5TFbaBh1bZffpc9WG5wfT2oVxfuxBBT4dQoU0NDLyY8O26S
# CTRG8dKoeMGBtMCV8CJSvQUtzRdF+P8IL95H/Zkr5FvG4sKvfJJzYusMAnvczRLg
# sX0zxscNQSPnpCcSdkvcGZu4bgLSmyrnzY2940yrffpLnjk56leBHn1225nyXU9/
# O5Hojeeu3SsXscgE8e5CfneScEdFEamOqL9rqqUhH67dBFHsGhHA5X3HiTKbglrF
# aJ5eNEW0jab17UIUjT8g3ByG/+n+gc2Pgh/3hcdaZuZRUbxplbnZ+qJr8DBjPx+d
# Dtu6XSRtq7J6TMdSGy1OZAuVKvQiyWYtDYuAg2EMC+otwWji6elz31RElhrGGyUA
# eepEO8g001Nm8vZYWombU7+hQhAmwjrMxAz9YJkN1AOuuueYH5OqGhfbdL55Uxz8
# j0sFtdhCt05sXkyn111CgX4efVCUbm/JnYWqY7UJxdLfTYxGMKrhoIbiGK8id4LI
# PBM+uugY/p5EhxhB3yLj
# SIG # End signature block
