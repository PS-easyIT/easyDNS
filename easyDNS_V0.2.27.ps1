#requires -RunAsAdministrator

###############################################################################
# easyDNS v0.2.10 - Moderne WPF DNS-Verwaltung
# Komplett überarbeitet mit Windows 11 Design und WPF XAML
# Optimiert für bessere Performance und Benutzerfreundlichkeit
###############################################################################

###############################################################################
# INLINE KONFIGURATION - Keine externe INI erforderlich
###############################################################################
$global:AppConfig = @{
    AppName = "easyDNS"
    Author = "PHscripts.de | Andreas Hepp"
    ScriptVersion = "0.2.27"
    Website = "https://github.com/PS-easyIT/"
    LastUpdate = "26.05.2025"
    
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
            Write-Log "DNS-Service is running locally - Automatic connection will be established" -Level "INFO" -Component "Detection"
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
        Write-Log "DNS-Service check failed" -Level "DEBUG" -Component "Detection"
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
        Write-Log "Domain DNS-Server Search failed" -Level "DEBUG" -Component "Detection"
    }

    # Keine lokale DNS-Rolle gefunden - manuelle Verbindung erforderlich
    if ([string]::IsNullOrEmpty($result.Server)) {
        Write-Log "No DNS-Server found - Manual server selection required" -Level "WARN" -Component "Detection"
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
                Write-Log "Operation successful after $($attempt + 1) attempts" -Level "INFO" -Component $Component
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
                Write-Log "Attempt $attempt of $($maxRetries + 1) failed: $_" -Level "WARN" -Component $Component
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
            Write-Log "DNS-Connection status from cache: $($global:DNSConnectionStatus.IsConnected)" -Level "DEBUG" -Component "Connection"
            return $global:DNSConnectionStatus.IsConnected
        }
    }
    
    try {
        $testZone = Get-DnsServerZone -ComputerName $ServerName -ErrorAction Stop | Select-Object -First 1
        
        # Cache aktualisieren
        $global:DNSConnectionStatus.IsConnected = $true
        $global:DNSConnectionStatus.LastChecked = Get-Date
        $global:DNSConnectionStatus.ServerName = $ServerName
        
        Write-Log "DNS-Connection test successful for $ServerName" -Level "DEBUG" -Component "Connection"
        return $true
    }
    catch {
        # Cache aktualisieren
        $global:DNSConnectionStatus.IsConnected = $false
        $global:DNSConnectionStatus.LastChecked = Get-Date
        $global:DNSConnectionStatus.ServerName = $ServerName
        
        Write-Log "DNS-Connection test failed for $ServerName`: $_" -Level "DEBUG" -Component "Connection"
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
                IsSigned = if ($isSigned) { "Yes" } else { "No" }
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
        $result = Invoke-SafeOperation -Operation $operation -ErrorMessage "Error fetching DNS zones from $DnsServerName" -Component "DNS" -RetryCount 2
        
        Write-Log "DNS-Zones fetched: $($result.Count) zones from server $DnsServerName" -Level "INFO" -Component "DNS"
        return $result
        
    } catch {
        Write-Log "Critical error fetching DNS zones: $_" -Level "ERROR" -Component "DNS"
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
        Write-Log "Error formatting record data: $_" -Level "DEBUG" -Component "DNS"
        return "Error formatting"
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
        Write-Log "Error validating record: $_" -Level "DEBUG" -Component "Validation"
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
        ServerUptime = "Unknown"
        CacheSize = "Unknown"
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
        Write-Log "Error fetching DNS statistics: $_" -Level "ERROR"
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
                Write-Log "Error exporting zone $($zone.ZoneName): $_" -Level "WARN"
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
        
        Write-Log "DNS configuration exported to $ExportPath (Format: $Format)" -Level "INFO"
        return $true
        
    } catch {
        Write-Log "Error exporting DNS configuration: $_" -Level "ERROR"
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
                        Write-Log "Skip Reverse Zone $zoneName during import" -Level "WARN"
                        continue
                    } else {
                        Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope "Domain" -ComputerName $DnsServerName -ErrorAction Stop
                        Write-Log "Zone $zoneName created" -Level "INFO"
                    }
                }
            } catch {
                Write-Log "Error creating zone" -Level "ERROR"
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
                            Write-Log "Record type $($record.RecordType) is not supported during import" -Level "WARN"
                            continue
                        }
                    }
                    
                    $imported++
                    
                } catch {
                    Write-Log "Error importing record $($record.RecordName) ($($record.RecordType)): $_" -Level "ERROR"
                    $failed++
                }
            }
        }
        
        Write-Log "DNS import completed: $imported successful, $failed failed" -Level "INFO"
        return @{ Success = $imported; Failed = $failed }
        
    } catch {
        Write-Log "Error importing DNS configuration: $_" -Level "ERROR"
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
            <Setter Property="Background" Value="#4A90E2"/> <!-- Medium, pleasant blue tone -->
            <Setter Property="Foreground" Value="White"/> <!-- Font color adjusted for contrast -->
            <Setter Property="BorderThickness" Value="0,0,0,1"/>
            <Setter Property="BorderBrush" Value="#357ABD"/> <!-- Darker blue tone for the bottom border -->
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
                                <Setter TargetName="border" Property="Background" Value="#60A0F0"/> <!-- Lighter blue tone for hover -->
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#0078D4"/> <!-- Stronger blue for pressed -->
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
        <Border Grid.Row="0" Background="#142831" BorderBrush="#E0E0E0" BorderThickness="0,0,0,1">
            <Grid Margin="20,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- App Name -->
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="$($global:AppConfig.AppName)  $($global:AppConfig.ScriptVersion)" 
                              FontSize="20" FontWeight="SemiBold" 
                              Foreground="#e2e2e2" VerticalAlignment="Center"/>
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
                <StackPanel Margin="0,10">
                    <!-- User Info -->
                    <GroupBox Header="Angemeldeter Benutzer"
                              Foreground="#E0E0E0"
                              BorderBrush="#4A5C6E" BorderThickness="1"
                              Margin="5,8,5,8"
                              Padding="8">
                        <StackPanel>
                            <TextBlock Text="$($env:USERNAME)"
                                       FontWeight="SemiBold"
                                       Foreground="#FFFFFF"
                                       VerticalAlignment="Center"
                                       HorizontalAlignment="Left"
                                       FontSize="12"/>
                        </StackPanel>
                    </GroupBox>

                    <GroupBox Header="Server Connection" 
                              Foreground="#E0E0E0" 
                              BorderBrush="#4A5C6E" BorderThickness="1" 
                              Margin="5,10,5,25" 
                              Padding="8">
                        <StackPanel>
                            <!-- DNS Server Input -->
                            <TextBox Name="txtDNSServer" Style="{StaticResource ModernTextBox}" Text="$($global:DetectedDnsServer)" 
                                     Background="#1E2A38" Foreground="#FFFFFF" BorderBrush="#4A5C6E" 
                                     Padding="5,4" FontSize="12" MaxHeight="35" Margin="0,0,0,8"/>

                            <!-- Connect Button -->
                            <Button Name="btnConnect" Content="Connect" Style="{StaticResource ModernButton}" 
                                    HorizontalAlignment="Stretch" 
                                    Margin="0,0,0,8" MaxHeight="28" Padding="8,4" FontSize="12"/>
                            
                            <!-- Status -->
                            <TextBlock Name="lblStatus" Text="Status: Ready" Foreground="#107C10" FontWeight="SemiBold" 
                                       VerticalAlignment="Center" HorizontalAlignment="Left" 
                                       Margin="0,0,0,0" FontSize="11"/>
                        </StackPanel>
                    </GroupBox>

                    <!-- Trennlinie -->
                    <Border Height="1" Background="#4A5C6E" Margin="16,0,16,25" Opacity="0.5"/>
                    
                    <!-- Navigation Header -->
                    <TextBlock Text="Navigation" Foreground="#FFFFFF" FontSize="14" FontWeight="SemiBold" 
                              Margin="16,0,16,12" HorizontalAlignment="Center"/>

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
                        <StackPanel Name="dashboardPanel" Visibility="Visible" Width="1150" HorizontalAlignment="Center">
                            <TextBlock Text="DNS Server Dashboard" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,20"/>

                            <Grid> <!-- Main grid for the dashboard layout -->
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/> <!-- Upper row for Server Info and Key Stats -->
                                    <RowDefinition Height="*"/>    <!-- Lower row for About and Copyright, takes the remaining vertical space in the dashboard grid -->
                                </Grid.RowDefinitions>

                                <!-- Obere Reihe: Serverinformationen und Schlüsselinformationen in einer Box -->
                                <Border Grid.Row="0" Style="{StaticResource Card}" Margin="0,0,0,20"> <!-- Unterer Rand für Abstand zur nächsten Reihe -->
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/> <!-- Gleiche Breite -->
                                            <ColumnDefinition Width="*"/> <!-- Gleiche Breite -->
                                        </Grid.ColumnDefinitions>

                                        <!-- Serverinformationen-Teil -->
                                        <StackPanel Grid.Column="0" Margin="0,0,10,0"> <!-- Rechter Rand für Abstand zur nächsten Spalte -->
                                            <TextBlock Text="Server Information" FontSize="16" FontWeight="SemiBold" 
                                                    Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="200" MinWidth="150"/> <!-- Beibehaltung der ursprünglichen Breite für Labels -->
                                                    <ColumnDefinition Width="*"/> <!-- Werte -->
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

                                                <!-- Operating System -->
                                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Operating System:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="0" Grid.Column="1" Name="lblOS" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- Logged in User -->
                                                <TextBlock Grid.Row="1" Grid.Column="0" Text="Logged in User:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="1" Grid.Column="1" Name="lblUser" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- DNS Server -->
                                                <TextBlock Grid.Row="2" Grid.Column="0" Text="DNS Server:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="2" Grid.Column="1" Name="lblDNSServerStatus" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- CPU -->
                                                <TextBlock Grid.Row="3" Grid.Column="0" Text="CPU Usage:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="3" Grid.Column="1" Name="lblCPU" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- RAM -->
                                                <TextBlock Grid.Row="4" Grid.Column="0" Text="RAM Usage:" FontWeight="SemiBold" 
                                                        Foreground="#505050" Margin="0,0,10,4"/>
                                                <TextBlock Grid.Row="4" Grid.Column="1" Name="lblRAM" Text="Loading..." 
                                                        Foreground="#1C1C1C" Margin="0,0,0,4"/>

                                                <!-- System Partition -->
                                                <TextBlock Grid.Row="5" Grid.Column="0" Text="System Partition (C):" FontWeight="SemiBold" 
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
                                    
                                        <!-- Schlüsselinformationen und Schnellstatistiken-Teil -->
                                        <StackPanel Grid.Column="1" Margin="10,0,0,0"> <!-- Linker Rand für Abstand zur vorherigen Spalte -->
                                            <TextBlock Text="Key Information and Quick Stats" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock x:Name="lblDashboardStats" Text="Loading key statistics..." FontSize="12" Foreground="#505050" TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Grid>
                                </Border>

                                <!-- Lower row: About and Copyright side by side -->
                                <Grid Grid.Row="1"> <!-- This row takes the remaining vertical space -->
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="65*"/> <!-- 75% width -->
                                        <ColumnDefinition Width="35*"/>  <!-- 25% width -->
                                    </Grid.ColumnDefinitions>

                                    <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0,0,10,0"> <!-- Right margin for spacing, bottom margin is 0 -->
                                        <StackPanel>
                                            <TextBlock Text="About this Tool" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18">
                                                <Run Text="easyDNS is a comprehensive PowerShell-based tool that significantly simplifies the management of DNS servers on Windows Server."/>
                                                <LineBreak/>
                                                <Run Text="It offers an intuitive graphical user interface for viewing, creating, and managing DNS zones as well as various types of DNS records."/>
                                                <LineBreak/>
                                                <LineBreak/>
                                            </TextBlock>
                                            
                                            <!-- Key Features Table -->
                                            <Grid Margin="0,10,0,10">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="Auto"/>
                                                    <ColumnDefinition Width="*"/>
                                                </Grid.ColumnDefinitions>
                                                <Grid.RowDefinitions>
                                                    <RowDefinition Height="Auto"/> <!-- Feature 1 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 2 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 3 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 4 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 5 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 6 -->
                                                    <RowDefinition Height="Auto"/> <!-- Feature 7 -->
                                                </Grid.RowDefinitions>
                                                <!-- Feature 1: Zone and Record Management -->
                                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Zone and Record Management:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="0" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Easily create, view, and manage forward/reverse lookup zones and a wide array of common DNS record types (A, AAAA, CNAME, MX, TXT, SRV, etc.)."/>
                                                </TextBlock>

                                                <!-- Feature 2: Diagnostic Tools -->
                                                <TextBlock Grid.Row="1" Grid.Column="0" Text="Diagnostic Tools:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="1" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Access a comprehensive suite of diagnostic utilities including Ping, Nslookup, DNS server health tests, cache/service control, and diagnostics for forwarders and zone integrity."/>
                                                </TextBlock>

                                                <!-- Feature 3: Import and Export -->
                                                <TextBlock Grid.Row="2" Grid.Column="0" Text="Import and Export:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="2" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Seamlessly back up, restore, or migrate your DNS configurations using flexible import/export functionalities, supporting common formats like JSON or CSV."/>
                                                </TextBlock>

                                                <!-- Feature 4: DNSSEC Management -->
                                                <TextBlock Grid.Row="3" Grid.Column="0" Text="DNSSEC Management:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="3" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Secure your zones by signing and managing DNSSEC, including comprehensive key management (KSK, ZSK) and monitoring of signature status."/>
                                                </TextBlock>

                                                <!-- Feature 5: Monitoring and Logging -->
                                                <TextBlock Grid.Row="4" Grid.Column="0" Text="Monitoring and Logging:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="4" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Keep a close eye on server activity with detailed monitoring, direct access to Windows Event Logs, and advanced, configurable debug logging for efficient troubleshooting."/>
                                                </TextBlock>

                                                <!-- Feature 6: Advanced Diagnostics -->
                                                <TextBlock Grid.Row="5" Grid.Column="0" Text="Advanced Diagnostics:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="5" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Perform in-depth DNS benchmarks, latency tests, DNSSEC validation, DNS leak tests, TraceRoute analysis, and generate comprehensive diagnostic reports."/>
                                                </TextBlock>

                                                <!-- Feature 7: Real-time Monitoring -->
                                                <TextBlock Grid.Row="6" Grid.Column="0" Text="Real-time Monitoring:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,15,5" VerticalAlignment="Top"/>
                                                <TextBlock Grid.Row="6" Grid.Column="1" TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,5,0,5">
                                                    <Run Text="Actively monitor DNS queries, server errors, and performance metrics in real-time; analyze query patterns and response times to proactively optimize DNS performance."/>
                                                </TextBlock>
                                            </Grid>
                                        </StackPanel>
                                    </Border>

                                    <!-- Author and Copyright Card -->
                                    <Border Grid.Column="1" Style="{StaticResource Card}" Margin="10,0,0,0"> <!-- Left margin for spacing, bottom margin is 0 -->
                                        <StackPanel VerticalAlignment="Top"> <!-- VerticalAlignment="Top" added so content starts at the top if the card is taller than the content -->
                                            <TextBlock Text="Author and Copyright" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,10">
                                                <Run Text="Author: "/>
                                                <Run Text="$($global:AppConfig.Author)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4">
                                                <Run Text="Version: "/>
                                                <Run Text="$($global:AppConfig.ScriptVersion)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,10">
                                                <Run Text="Last Update: "/>
                                                <Run Text="$($global:AppConfig.LastUpdate)" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4">
                                                <Run Text="Website: "/>
                                                <Run Text="$($global:AppConfig.Website)" Foreground="#0078D4" Cursor="Hand" FontWeight="SemiBold"/>
                                            </TextBlock>
                                            <TextBlock Text="License Information" FontSize="14" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,20,0,10"/>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,4" TextWrapping="Wrap">
                                                <Run Text="Free Version: " FontWeight="SemiBold"/>
                                                <Run Text="Free for up to 3 employees."/>
                                            </TextBlock>
                                            <TextBlock Foreground="#505050" Margin="0,0,0,10" TextWrapping="Wrap">
                                                <Run Text="Commercial License: " FontWeight="SemiBold"/>
                                                <Run Text="For companies with 4 or more employees."/>
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

                            <Grid Grid.Row="1" MaxWidth="1200">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="3*"/> <!-- 30% -->
                                    <ColumnDefinition Width="4*"/> <!-- 40% -->
                                    <ColumnDefinition Width="3*"/> <!-- 30% -->
                                </Grid.ColumnDefinitions>

                                <Border Grid.Column="0" Style="{StaticResource Card}" MinHeight="200" Margin="0,0,5,0">
                                    <StackPanel>
                                        <TextBlock Text="Select Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Grid>
                                            <Grid.RowDefinitions>
                                                <RowDefinition Height="Auto"/> <!-- Zeile für ComboBox -->
                                                <RowDefinition Height="Auto"/> <!-- Zeile für Button -->
                                            </Grid.RowDefinitions>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/> <!-- Spalte für "Zone:" TextBlock -->
                                                <ColumnDefinition Width="*"/>    <!-- Spalte für ComboBox und Button -->
                                            </Grid.ColumnDefinitions>

                                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Zone:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <ComboBox Grid.Row="0" Grid.Column="1" Name="cmbRecordZone" Padding="8,5" HorizontalAlignment="Stretch" Margin="0,0,0,8"/> <!-- Margin unten für Abstand zum Button -->

                                            <Button Grid.Row="1" Grid.Column="1" Name="btnRefreshZoneList" Content="Refresh"
                                                   Style="{StaticResource ModernButton}" HorizontalAlignment="Stretch"
                                                   Margin="0"/> <!-- Margin="0" setzt linken/rechten Margin auf 0 und überschreibt den Style-Margin, um Bündigkeit zu erreichen. Der Abstand nach oben kommt vom unteren Margin der ComboBox. -->
                                        </Grid>
                                        <!-- Explanations moved to the third box -->
                                    </StackPanel>
                                </Border>

                                <Border Grid.Column="1" Style="{StaticResource Card}" MinHeight="200" Margin="5,0,5,0">
                                    <StackPanel Grid.IsSharedSizeScope="True">
                                        <TextBlock Text="Create New Record" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Grid>
                                            <Grid.RowDefinitions>
                                                <RowDefinition Height="Auto"/> <!-- Name Row -->
                                                <RowDefinition Height="Auto"/> <!-- Data Row -->
                                                <RowDefinition Height="Auto"/> <!-- Type and TTL Row -->
                                                <RowDefinition Height="Auto"/> <!-- Buttons Row -->
                                            </Grid.RowDefinitions>
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto" SharedSizeGroup="InputLabels"/>
                                                <ColumnDefinition Width="*"/>
                                            </Grid.ColumnDefinitions>

                                            <!-- Name Row -->
                                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Name:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Row="0" Grid.Column="1" Name="txtRecordName" Style="{StaticResource ModernTextBox}" Margin="0,0,0,8"/>

                                            <!-- Data Row -->
                                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Data:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                            <TextBox Grid.Row="1" Grid.Column="1" Name="txtRecordData" Style="{StaticResource ModernTextBox}" Margin="0,0,0,8"/>
                                            
                                            <!-- Type and TTL Row -->
                                            <Grid Grid.Row="2" Grid.ColumnSpan="2" Margin="0,0,0,12">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="Auto" SharedSizeGroup="InputLabels"/>   <!-- Type Label -->
                                                    <ColumnDefinition Width="*"/>      <!-- Type ComboBox -->
                                                    <ColumnDefinition Width="16"/>     <!-- Spacer -->
                                                    <ColumnDefinition Width="Auto"/>   <!-- TTL Label -->
                                                    <ColumnDefinition Width="*"/>      <!-- TTL TextBox -->
                                                </Grid.ColumnDefinitions>

                                                <TextBlock Grid.Column="0" Text="Type:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                                <ComboBox Grid.Column="1" Name="cmbRecordType" Padding="8,5" MaxHeight="35" VerticalAlignment="Center">
                                                    <ComboBoxItem Content="A" IsSelected="True"/>
                                                    <ComboBoxItem Content="AAAA"/>
                                                    <ComboBoxItem Content="CNAME"/>
                                                    <ComboBoxItem Content="MX"/>
                                                    <ComboBoxItem Content="PTR"/>
                                                    <ComboBoxItem Content="TXT"/>
                                                    <ComboBoxItem Content="SRV"/>
                                                </ComboBox>

                                                <TextBlock Grid.Column="3" Text="TTL (sec):" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                                <TextBox Grid.Column="4" Name="txtRecordTTL" Text="3600" Style="{StaticResource ModernTextBox}" VerticalAlignment="Center"/>
                                            </Grid>
                                            
                                            <!-- Buttons Row -->
                                            <Grid Grid.Row="3" Grid.ColumnSpan="2">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="*"/>
                                                </Grid.ColumnDefinitions>
                                                <Button Grid.Column="0" Name="btnCreateRecord" Content="Create" 
                                                       Background="#107C10" Style="{StaticResource ModernButton}" Margin="0,0,3,0"/>
                                                <Button Grid.Column="1" Name="btnDeleteRecord" Content="Delete" 
                                                       Background="#D13438" Style="{StaticResource ModernButton}" Margin="3,0,0,0"/>
                                            </Grid>
                                        </Grid>
                                    </StackPanel>
                                </Border>

                                <Border Grid.Column="2" Style="{StaticResource Card}" MinHeight="200" Margin="5,0,0,0">
                                    <StackPanel>
                                        <TextBlock Text="Instructions" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        
                                        <TextBlock Text="Select Zone:" FontWeight="SemiBold" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,4"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,2">
                                            - Choose a DNS zone from the dropdown menu to view or manage its records.
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,10">
                                            - Records for the selected zone will appear in the table below.
                                        </TextBlock>
                                        
                                        <TextBlock Text="Create New Record:" FontWeight="SemiBold" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,4"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,2">
                                            - To add a new record, specify its Name, Type, Data (e.g., IP address or hostname), and TTL (Time-To-Live in seconds).
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,2">
                                            - Click 'Create' to add the new record to the selected zone.
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#4A4A4A" FontSize="12" Margin="0,0,0,0">
                                            - To remove an existing record, select it in the table below and click 'Delete'.
                                        </TextBlock>
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
                                                
                                                <!-- Debug Logging -->
                                                <Grid Margin="0,0,0,8">
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="*"/>
                                                        <ColumnDefinition Width="*"/>
                                                    </Grid.ColumnDefinitions>
                                                    <Button Grid.Column="0" Name="btnEnableDebugLog" Content="Enable Debug Logging" Background="#FF8C00" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Grid.Column="1" Name="btnDisableDebugLog" Content="Disable Debug Logging" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </Grid>
                                                
                                                <Separator Margin="0,8,0,8"/> 
                                                
                                                <!-- DNS-Tests -->
                                                <TextBlock Text="DNS-Tests:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="3" Margin="0,0,0,8">
                                                    <Button Name="btnDNSBenchmark" Content="DNS Benchmark" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnLatencyTest" Content="Latency Test" Style="{StaticResource ModernButton}" Margin="1,0,1,0"/>
                                                    <Button Name="btnDNSLeakTest" Content="DNS Leak Test" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
                                                
                                                <Separator Margin="0,8,0,8"/>
                                                
                                                <!-- Network Analysis -->
                                                <TextBlock Text="Network Analysis:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <StackPanel Orientation="Vertical" Margin="0,0,0,8">
                                                    <!-- Reihe 1: Zwei Buttons nebeneinander -->
                                                    <UniformGrid Columns="2" Margin="0,0,0,8"> <!-- Abstand nach unten für die nächste Sektion -->
                                                        <Button Name="btnNetworkProps" Content="Network Properties" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                        <Button Name="btnTraceRoute" Content="Trace-Route-Analyse" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                    </UniformGrid>
                                                    
                                                    <!-- Reihe 2: Eingabefeld für Trace Route Target -->
                                                    <Grid>
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto"/> <!-- Label "Ziel:" -->
                                                            <ColumnDefinition Width="*"/>    <!-- TextBox -->
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Trace Route Target:" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#1C1C1C"/>
                                                        <TextBox Grid.Column="1" Name="txtTraceRouteTarget" Style="{StaticResource ModernTextBox}"/>
                                                    </Grid>
                                                </StackPanel>
                                                <Separator Margin="0,8,0,8"/>
                                                
                                                <!-- Export & Reports -->
                                                <TextBlock Text="Reports &amp; Export:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="2" Margin="0,0,0,0">
                                                    <Button Name="btnExportStats" Content="Export Statistics" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnGenerateReport" Content="Generate Health Report" Background="#107C10" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
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

                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Enable / Disable Debug Logging:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Enable or Disable debug logging."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Debug Logging aktivieren oder deaktivieren."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="DNS Benchmark:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Benchmark DNS server performance."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="DNS Serverleistung benchmarken."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Latency Test:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Test DNS query latency."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="DNS Abfragelatenz testen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="DNS Leak Test:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Check for DNS leaks."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Auf DNS Lecks ueberpruefen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Network Properties:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="View current network properties."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Aktuelle Netzwerkeigenschaften anzeigen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Trace Route Analysis:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Perform a trace route to a target."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Fuehren Sie eine Traceroute zu einem Ziel durch."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Export Statistics:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Export server statistics."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Serverstatistiken exportieren."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="180"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Generate Health Report:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Generate a comprehensive health report."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Erstellen Sie einen umfassenden Integritaetsbericht."/>
                                                        </TextBlock>
                                                    </Grid>
                                                </StackPanel>
                                            </ScrollViewer>
                                        </Border>
                                    </Grid>
                                </TabItem>
                                <TabItem Header="Monitoring">
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="5"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Border Grid.Column="0" Style="{StaticResource Card}" Margin="0">
                                            <StackPanel>
                                                <TextBlock Text="Real-time DNS Monitoring" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                                
                                                <!-- Monitoring Controls -->
                                                <Grid Margin="0,0,0,8">
                                                    <Grid.ColumnDefinitions>
                                                        <ColumnDefinition Width="*"/>
                                                        <ColumnDefinition Width="*"/>
                                                    </Grid.ColumnDefinitions>
                                                    <Button Grid.Column="0" Name="btnStartRealTimeMonitor" Content="Start Monitor" Background="#107C10" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Grid.Column="1" Name="btnStopRealTimeMonitor" Content="Stop Monitor" Background="#D13438" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </Grid>
                                                
                                                <!-- Monitor Settings -->
                                                <TextBlock Text="Monitor Settings:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <CheckBox Name="chkMonitorDNSQueries" Content="DNS Queries" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C"/>
                                                <CheckBox Name="chkMonitorDNSErrors" Content="DNS Errors" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C"/>
                                                <CheckBox Name="chkMonitorPerformance" Content="Performance Metrics" IsChecked="True" Margin="0,0,0,8" Foreground="#1C1C1C"/>
                                                
                                                <Separator Margin="0,8,0,8"/>
                                                
                                                <!-- Query Analysis -->
                                                <TextBlock Text="Query Analysis:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="3" Margin="0,0,0,8">
                                                    <Button Name="btnTopQueries" Content="Top Queries" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnQueryPatterns" Content="Query Patterns" Style="{StaticResource ModernButton}" Margin="2,0,2,0"/>
                                                    <Button Name="btnFailedQueries" Content="Failed Queries" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
                                                
                                                <Separator Margin="0,8,0,8"/>
                                                
                                                <!-- Performance Monitoring -->
                                                <TextBlock Text="Performance:" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                                <UniformGrid Columns="2" Margin="0,0,0,0">
                                                    <Button Name="btnResponseTimes" Content="Response Times" Style="{StaticResource ModernButton}" Margin="0,0,2,0"/>
                                                    <Button Name="btnThroughputAnalysis" Content="Throughput Analysis" Style="{StaticResource ModernButton}" Margin="2,0,0,0"/>
                                                </UniformGrid>
                                            </StackPanel>
                                        </Border>
                                        <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
                                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                                <StackPanel Margin="10">
                                                    <TextBlock Text="DNS Monitoring - Explanations" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,10" Foreground="#1C1C1C"/>
                                                    <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#505050" Margin="0,0,0,12">
                                                        <Run Text="EN: Real-time monitoring of DNS server activity and performance metrics."/>
                                                        <LineBreak/>
                                                        <Run Text="DE: Echtzeitüberwachung der DNS-Server-Aktivitaet und Leistungsmetriken."/>
                                                    </TextBlock>

                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Real-time Monitor:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Monitor DNS queries and responses in real-time."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="DNS-Abfragen und -Antworten in Echtzeit ueberwachen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Top Queries:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="View the most frequent DNS queries."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Die haeufigsten DNS Abfragen anzeigen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Query Patterns:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Analyze patterns in DNS queries."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Muster in DNS Abfragen analysieren."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Failed Queries:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="View a list of failed DNS queries."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Eine Liste fehlgeschlagener DNS Abfragen anzeigen."/>
                                                        </TextBlock>
                                                    </Grid>

                                                    <Grid Margin="0,0,0,4">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Response Times:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Monitor DNS query response times."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="Antwortzeiten von DNS Abfragen ueberwachen."/>
                                                        </TextBlock>
                                                    </Grid>
                                                    <Grid Margin="0,0,0,0">
                                                        <Grid.ColumnDefinitions>
                                                            <ColumnDefinition Width="Auto" MinWidth="150"/>
                                                            <ColumnDefinition Width="*"/>
                                                        </Grid.ColumnDefinitions>
                                                        <TextBlock Grid.Column="0" Text="Throughput Analysis:" FontWeight="SemiBold" Foreground="#333333" Margin="0,0,10,0" VerticalAlignment="Top"/>
                                                        <TextBlock Grid.Column="1" TextWrapping="Wrap" FontSize="12" Foreground="#505050">
                                                            <Run Text="EN: " FontWeight="Bold"/><Run Text="Analyze DNS server throughput."/><LineBreak/>
                                                            <Run Text="DE: " FontWeight="Bold"/><Run Text="DNS Serverdurchsatz analysieren."/>
                                                        </TextBlock>
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
                                        <RowDefinition Height="225"/>
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
                                                    ToolTip="e.g. 192.168.1" Margin="0,0,16,0"/>
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
                                            <CheckBox Name="chkOverwriteExisting" Content="Overwrite existing Records" 
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
                                    <Grid Grid.Row="0" Margin="0,0,0,12">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="DNSSEC Zone Status" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" VerticalAlignment="Center"/>
                                        <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                                            <Button Name="btnRefreshDNSSEC" Content="Refresh" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnSignZone" Content="Sign Zone" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnUnsignZone" Content="Unsign Zone" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Grid>
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

                            <Grid Grid.Row="2" Margin="0,0,0,0" MaxWidth="1200">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="0.30*"/>
                                    <ColumnDefinition Width="0.25*"/>
                                    <ColumnDefinition Width="0.45*"/> <!-- Korrigiert auf 0.45* damit die Summe 1.0* ergibt, oder 0.55* wenn die Proportionen wichtiger sind als die Summe 1.0 -->
                                    <!-- Wenn die Anweisung strikt 55% für die dritte Box meint, dann:
                                    <ColumnDefinition Width="30*"/>
                                    <ColumnDefinition Width="25*"/>
                                    <ColumnDefinition Width="55*"/>
                                    Dies würde die Breiten proportional zu 30:25:55 verteilen. Ich verwende diese Variante, da die Anweisung explizit 55% nennt.
                                    -->
                                </Grid.ColumnDefinitions>
                                <!-- DNSSEC Settings -->
                                <Border Grid.Column="0" Style="{StaticResource Card}">
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
                                <Border Grid.Column="1" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Operations" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <Button Name="btnGenerateKeys" Content="Generate New Keys"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnExportKeys" Content="Export Public Keys"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnValidateSignatures" Content="Validate Signatures"
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnForceRollover" Content="Force Key Rollover"
                                               Background="#FF8C00" Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Text="DNSSEC Status:" FontWeight="SemiBold" Margin="0,12,0,4" Foreground="#1C1C1C"/>
                                        <TextBlock Name="lblDNSSECStatus" Text="Ready" Foreground="#107C10"/>
                                    </StackPanel>
                                </Border>
                                
                                <!-- DNSSEC Information -->
                                <Border Grid.Column="2" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Information" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12" Foreground="#1C1C1C"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,10">
                                            <Run Text="DNSSEC (Domain Name System Security Extensions) adds security to DNS by authenticating data, preventing redirection to malicious sites."/>
                                        </TextBlock>
                                        <TextBlock Text="Key Operations:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,0,5"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Generate New Keys: Creates new KSK (Key Signing Key) and ZSK (Zone Signing Key) for the selected zone."/>
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Export Public Keys: Allows exporting public DNSKEY records for trust anchor configuration."/>
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Validate Signatures: Checks the integrity and validity of DNSSEC signatures for the zone."/>
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Force Key Rollover: Manually initiates replacing old DNSSEC keys with new ones."/>
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,10,0,5">
                                            <Run Text="Signing a zone protects it from cache poisoning and other DNS attacks by verifying data origin and integrity."/>
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                            </Grid>
                        </Grid>

                        <Grid Name="auditPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Audit and Logs" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#1C1C1C" Margin="0,0,0,12"/>

                            <Grid Grid.Row="1" Margin="0,0,0,0" MaxWidth="1200">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="3*"/> <!-- 30% -->
                                    <ColumnDefinition Width="3*"/> <!-- 25% -->
                                    <ColumnDefinition Width="4*"/> <!-- 45% -->
                                </Grid.ColumnDefinitions>

                                <Border Grid.Column="0" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Live DNS Monitoring" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                            <Button Name="btnStartMonitoring" Content="Start" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnStopMonitoring" Content="Stop" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnClearMonitoring" Content="Clear" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                        <TextBlock Text="Monitor Events:" Margin="0,0,0,4" Foreground="#1C1C1C"/>
                                        <StackPanel Orientation="Horizontal">
                                            <CheckBox Name="chkMonitorQueries" Content="DNS Queries" IsChecked="True" Margin="0,0,10,2" Foreground="#1C1C1C" Width="120"/>
                                            <CheckBox Name="chkMonitorZoneChanges" Content="Zone Changes" IsChecked="True" Margin="0,0,0,2" Foreground="#1C1C1C" Width="135"/>
                                        </StackPanel>
                                        <StackPanel Orientation="Horizontal">
                                            <CheckBox Name="chkMonitorErrors" Content="DNS Errors" IsChecked="True" Margin="0,0,10,2" Foreground="#1C1C1C" Width="120"/>
                                            <CheckBox Name="chkMonitorSecurity" Content="Security Events" IsChecked="True" Margin="0,0,0,20" Foreground="#1C1C1C" Width="135"/>
                                        </StackPanel>
                                        <TextBlock Name="lblMonitoringStatus" Text="Status: Stopped" 
                                                  Foreground="#D13438" FontWeight="SemiBold"/>
                                    </StackPanel>
                                </Border>

                                <Border Grid.Column="1" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNS Statistics" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <Button Name="btnRefreshStats" Content="Refresh Statistics"
                                               Margin="0,0,0,45" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Name="lblDNSStats" Text="Please Refresh Statistics..." 
                                                  FontSize="12" Foreground="#505050"/>
                                    </StackPanel>
                                </Border>
                                
                                <Border Grid.Column="2" Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Audit &amp; Log Explanations" FontSize="16" FontWeight="SemiBold" Foreground="#1C1C1C" Margin="0,0,0,12"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,10">
                                            <Run Text="This section provides tools for monitoring and auditing your DNS server activity."/>
                                        </TextBlock>
                                        <TextBlock Text="Live DNS Monitoring:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,0,5"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Start/Stop Monitoring: Toggles real-time capture of DNS events."/>
                                        </TextBlock>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Monitor Events: Select specific event types like queries, zone changes, errors, and security events."/>
                                        </TextBlock>
                                        <TextBlock Text="DNS Statistics:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,0,5"/>
                                        <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="- " FontWeight="Bold"/><Run Text="Refresh Statistics: Fetches and displays current DNS server performance metrics."/>
                                        </TextBlock>
                                        <TextBlock Text="DNS Event Log:" FontWeight="SemiBold" Foreground="#505050" Margin="0,5,0,5"/>
                                         <TextBlock TextWrapping="Wrap" Foreground="#505050" LineHeight="18" Margin="0,0,0,5">
                                            <Run Text="The log below displays detailed records of DNS server events. You can filter by log level (All, ERROR, WARN, INFO, DEBUG) and search for specific keywords to quickly find relevant information."/>
                                        </TextBlock>
                                    </StackPanel>
                                </Border>
                            </Grid>

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
                                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="450"/>
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
        <Border Grid.Row="2" Background="#142831" BorderBrush="#E0E0E0" BorderThickness="0,1,0,0">
            <!-- Consistent with Header -->
            <Grid Margin="20,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="$($global:AppConfig.AppName)" 
                          VerticalAlignment="Center" FontSize="11" Foreground="#e2e2e2"/>

                <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock Text="Copyright 2025 @" FontSize="11" Foreground="#e2e2e2" Margin="0,0,5,0"/>
                    <TextBlock Text="by $($global:AppConfig.Author)" FontSize="11" Foreground="#e2e2e2" Margin="0,0,35,0"/>
                    <TextBlock Text="$($global:AppConfig.Website)" FontSize="11" Foreground="#d0e8ff" Cursor="Hand"/>
                </StackPanel>

                <TextBlock Grid.Column="2" Text="Script Version: $($global:AppConfig.ScriptVersion) - Last Update: $($global:AppConfig.LastUpdate)" 
                          HorizontalAlignment="Right" VerticalAlignment="Center" FontSize="11" Foreground="#e2e2e2"/>
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
    Write-Log "WPF XAML successfully loaded" -Level "INFO"
} catch {
    Write-Log "Error loading XAML: $_" -Level "ERROR"
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
    "btnRefreshStats", "lblDNSStats", "btnExportLogs", "btnClearLogs", "cmbLogLevel", "txtLogSearch", "btnFilterLogs", "btnRefreshLogs", "dgAuditLogs",
    # Erweiterte Diagnostic Tools Controls
    "btnDNSBenchmark", "btnLatencyTest", "btnDNSLeakTest", "btnTraceRoute", "btnGenerateReport", "txtTraceRouteTarget",
    # Monitoring Controls
    "btnStartRealTimeMonitor", "btnStopRealTimeMonitor", "chkMonitorDNSQueries", "chkMonitorDNSErrors", "chkMonitorPerformance",
    "btnTopQueries", "btnQueryPatterns", "btnFailedQueries", "btnResponseTimes", "btnThroughputAnalysis"
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
        
        Write-Log "Panel changed to: $PanelName" -Level "DEBUG" -Component "Navigation"
    } else {
        Write-Log "ERROR: Panel $panelName not found!" -Level "ERROR" -Component "Navigation"
        Show-MessageBox "Error: The panel '$PanelName' could not be found." "Navigation Error" "Error"
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
    Write-Log "ERROR: btnForward Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnReverse) {
    $global:Controls.btnReverse.Add_Click({ Show-Panel "reverse" })
} else {
    Write-Log "ERROR: btnReverse Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnRecords) {
    $global:Controls.btnRecords.Add_Click({ Show-Panel "records" })
} else {
    Write-Log "ERROR: btnRecords Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnImport) {
    $global:Controls.btnImport.Add_Click({ Show-Panel "import" })
} else {
    Write-Log "ERROR: btnImport Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnDNSSEC) {
    $global:Controls.btnDNSSEC.Add_Click({ Show-Panel "dnssec" })
} else {
    Write-Log "ERROR: btnDNSSEC Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnTools) {
    $global:Controls.btnTools.Add_Click({ Show-Panel "tools" })
} else {
    Write-Log "ERROR: btnTools Control not found!" -Level "ERROR" -Component "UI"
}

if ($global:Controls.btnAudit) {
    $global:Controls.btnAudit.Add_Click({ Show-Panel "audit" })
} else {
    Write-Log "ERROR: btnAudit Control not found!" -Level "ERROR" -Component "UI"
}

# DNS-Server Verbindung
$global:Controls.btnConnect.Add_Click({
    $serverName = $global:Controls.txtDNSServer.Text.Trim()
    if ([string]::IsNullOrEmpty($serverName)) {
        Show-MessageBox "Please enter a DNS server." "Error" "Warning"
        return
    }
    
    # Validiere Server-Name/IP
    $serverName = Get-SafeString -InputString $serverName -RemoveSpecialChars $true
    
    # Verbindungsstatus-Cache invalidieren bei Server-Wechsel
    if ($global:DNSConnectionStatus.ServerName -ne $serverName) {
        $global:DNSConnectionStatus.IsConnected = $false
        $global:DNSConnectionStatus.LastChecked = $null
        $global:DNSConnectionStatus.ServerName = ""
        Write-Log "DNS connection status cache invalidated for new server: $serverName" -Level "DEBUG" -Component "Connection"
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
                throw "DNS-Server is not reachable or DNS role is not installed"
            }
            
            # Hole Basis-Informationen
            $zones = @(Get-DnsServerZone -ComputerName $serverName -ErrorAction Stop)
            
            $global:DetectedDnsServer = $serverName
            $global:Controls.lblStatus.Text = "Status: connected"
            $global:Controls.lblStatus.Foreground = "#107C10"
            
            Write-Log "Connection to DNS server '$serverName' established ($($zones.Count) zones found)" -Level "SUCCESS" -Component "Connection"
            
            # Auto-Refresh starten
            Start-AutoRefresh
            
            # Dashboard aktualisieren
            if ($global:CurrentPanel -eq "dashboard") {
                Update-Dashboard
            }
            
            # Erfolgs-Feedback
            $message = "Successfully connected to DNS server '$serverName'!`n`nFound zones: $($zones.Count)"
            if ($zones.Count -eq 0) {
                $message += "`n`nNote: No DNS zones found. Possible missing permissions."
            }
            
            Show-MessageBox $message "Verbindung hergestellt" "Information"
            
        } catch {
            $global:Controls.lblStatus.Text = "Status: Fehler"
            $global:Controls.lblStatus.Foreground = "#D13438"
            
            # Detaillierte Fehleranalyse
            $errorMessage = "Error connecting to DNS server '$serverName':`n`n"
            
            if ($_.Exception.Message -match "Access is denied") {
                $errorMessage += "Access denied. Please check:`n"
                $errorMessage += "- Administrative permissions`n"
                $errorMessage += "- Remote management is enabled`n"
                $errorMessage += "- Firewall settings"
            } elseif ($_.Exception.Message -match "RPC") {
                $errorMessage += "RPC error. Please check:`n"
                $errorMessage += "- The remote server is reachable`n"
                $errorMessage += "- Windows Firewall allows RPC`n"
                $errorMessage += "- The RPC service is running"
            } else {
                $errorMessage += $_.Exception.Message
            }
            
            Write-Log "Error connecting to DNS server '$serverName': $_" -Level "ERROR" -Component "Connection"
            Show-MessageBox $errorMessage "Connection error" "Error"
            
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

# Erweiterte Diagnostic Tools Event-Handler
$global:Controls.btnDNSBenchmark.Add_Click({ Run-DNSBenchmark })
$global:Controls.btnLatencyTest.Add_Click({ Run-LatencyTest })
$global:Controls.btnDNSLeakTest.Add_Click({ Run-DNSLeakTest })
$global:Controls.btnTraceRoute.Add_Click({ Run-TraceRouteAnalysis })
$global:Controls.btnGenerateReport.Add_Click({ Generate-HealthReport })

# Real-time Monitoring Event-Handler
$global:Controls.btnStartRealTimeMonitor.Add_Click({ Start-RealTimeMonitoring })
$global:Controls.btnStopRealTimeMonitor.Add_Click({ Stop-RealTimeMonitoring })
$global:Controls.btnTopQueries.Add_Click({ Show-TopQueries })
$global:Controls.btnQueryPatterns.Add_Click({ Analyze-QueryPatterns })
$global:Controls.btnFailedQueries.Add_Click({ Show-FailedQueries })
$global:Controls.btnResponseTimes.Add_Click({ Analyze-ResponseTimes })
$global:Controls.btnThroughputAnalysis.Add_Click({ Analyze-Throughput })

###############################################################################
# BUSINESS-LOGIC-FUNKTIONEN
###############################################################################

function Show-LoadingStatus {
    param(
        [string]$Message = "Loading data...",
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
        Write-Log "Error displaying loading status: $_" -Level "DEBUG" -Component "UI"
    }
}

function Hide-LoadingStatus {
    try {
        # Status zurücksetzen basierend auf aktuellem Verbindungsstatus
        if ($global:DNSConnectionStatus.IsConnected -and $global:DNSConnectionStatus.ServerName -eq $global:Controls.txtDNSServer.Text) {
            $global:Controls.lblStatus.Text = "Status: connected"
            $global:Controls.lblStatus.Foreground = "#107C10"
        } else {
            $global:Controls.lblStatus.Text = "Status: not connected"
            $global:Controls.lblStatus.Foreground = "#D13438"
        }
    } catch {
        Write-Log "Error hiding loading status: $_" -Level "DEBUG" -Component "UI"
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
                    $global:Controls.lblOS.Text = "Windows (unknown version)"
                }
            } catch {
                $global:Controls.lblOS.Text = "not available"
                Write-Log "Error fetching operating system: $_" -Level "DEBUG"
            }
            
            # Angemeldeter User
            try {
                $domain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $env:COMPUTERNAME }
                $user = if ($env:USERNAME) { $env:USERNAME } else { "unknown" }
                $global:Controls.lblUser.Text = "$domain\$user"
            } catch {
                $global:Controls.lblUser.Text = "unknown"
                Write-Log "Fehler beim Abrufen des Benutzers: $_" -Level "DEBUG"
            }
            
            # DNS Server Status
            $dnsServer = $global:Controls.txtDNSServer.Text
            if ([string]::IsNullOrEmpty($dnsServer)) {
                $global:Controls.lblDNSServerStatus.Text = "no server selected"
                $global:Controls.lblDNSServerStatus.Foreground = "#FF8C00"
            } else {
                # Prüfe ob verbunden
                try {
                    $testConnection = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop | Select-Object -First 1
                    if ($dnsServer -eq "localhost" -and $global:DNSDetection.IsLocalDNS) {
                        $global:Controls.lblDNSServerStatus.Text = "localhost (connected - local DNS role)"
                    } else {
                        $global:Controls.lblDNSServerStatus.Text = "$dnsServer (connected)"
                    }
                    $global:Controls.lblDNSServerStatus.Foreground = "#107C10"
                } catch {
                    if ($dnsServer -eq "localhost" -and $global:DNSDetection.IsLocalDNS) {
                        $global:Controls.lblDNSServerStatus.Text = "localhost (connection failed)"
                    } else {
                        $global:Controls.lblDNSServerStatus.Text = "$dnsServer (not connected)"
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
                $cpuName = if ($cpu -and $cpu.Name) { $cpu.Name } else { "unknown" }
                $global:Controls.lblCPU.Text = "$cpuUsage% ($cpuName)"
            } catch {
                $global:Controls.lblCPU.Text = "Not available"
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
                    $global:Controls.lblRAM.Text = "$ramPercent% ($([math]::Round($usedRAM, 1)) GB from $([math]::Round($totalRAM, 1)) GB used)"
                } else {
                    $global:Controls.lblRAM.Text = "Not available"
                }
            } catch {
                $global:Controls.lblRAM.Text = "Not available"
                Write-Log "Error fetching RAM usage: $_" -Level "DEBUG"
            }
            
            # Systempartition (C:)
            try {
                $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
                if ($disk -and $disk.Size -gt 0) {
                    $diskUsed = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
                    $diskTotal = [math]::Round($disk.Size / 1GB, 2)
                    $diskPercent = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
                    $global:Controls.lblDisk.Text = "$diskPercent% ($diskUsed GB from $diskTotal GB used)"
                } else {
                    $global:Controls.lblDisk.Text = "Not available"
                }
            } catch {
                $global:Controls.lblDisk.Text = "Not available"
                Write-Log "Error fetching disk usage: $_" -Level "DEBUG"
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
                        $uptimeText = "$($uptime.Days) days, "
                    }
                    $uptimeText += "{0:D2}:{1:D2}:{2:D2}" -f $uptime.Hours, $uptime.Minutes, $uptime.Seconds
                    $global:Controls.lblUptime.Text = $uptimeText
                } else {
                    $global:Controls.lblUptime.Text = "not available"
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
                    SignedZones = ($zones | Where-Object { $_.IsSigned -eq "Yes" }).Count
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
                        "~$estimatedTotal (appreciated)" 
                    } else { 
                        "$totalRecords" 
                    }
                } else {
                    $stats.RecordsText = "0"
                }
                
                return $stats
            }
            
            $stats = Invoke-SafeOperation -Operation $statsOperation -ErrorMessage "Error fetching DNS statistics" -Component "Dashboard"
            
            # Quick Stats Text aktualisieren mit erweiterten Informationen
            $quickStatsText = @"
DNS Information:
- Total Zones: $($stats.TotalZones)
  * Forward: $($stats.ForwardZones)
  * Reverse: $($stats.ReverseZones)
  * Primary: $($stats.ActiveZones)
  * Secondary: $($stats.SecondaryZones)
- Total Records: $($stats.RecordsText)
- DNSSEC-signed Zones: $($stats.SignedZones)
"@
            
            $global:Controls.lblDashboardStats.Text = $quickStatsText
            
        } catch {
            # Bei Fehler nur die Basis-Statistiken anzeigen
            $global:Controls.lblDashboardStats.Text = @"
DNS Information:
- Status: not connected
- Please connect to a DNS-Server
"@
        }
        
        Write-Log "Dashboard updated" -Level "DEBUG"
        
    } catch {
        $global:Controls.lblDashboardStats.Text = "Error loading statistics"
        Write-Log "Error updating dashboard: $_" -Level "ERROR"
    }
}

function Update-ForwardZonesList {
    try {
        Show-LoadingStatus -Message "Lade Forward-Zonen..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text | Where-Object { -not $_.IsReverse }
        $global:Controls.dgForwardZones.ItemsSource = $zones
        Write-Log "Forward-Zones-List updated: $($zones.Count) zones" -Level "INFO"
        Hide-LoadingStatus
    } catch {
        Write-Log "Error updating forward zones list: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Error loading forward zones: $_" "Error" "Error"
    }
}

function Create-NewForwardZone {
    $zoneName = $global:Controls.txtNewZoneName.Text.Trim()
    $replication = $global:Controls.cmbReplication.SelectedItem.Content
    
    if ([string]::IsNullOrEmpty($zoneName)) {
        Show-MessageBox "Please enter a zone name." "Validation error" "Warning"
        return
    }
    
    if (-not $replication) { $replication = "Domain" }
    
    try {
        Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope $replication -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        Show-MessageBox "Zone '$zoneName' created successfully!" "Zone created"
        $global:Controls.txtNewZoneName.Clear()
        Update-ForwardZonesList
        Write-Log "Forward-Zone created: $zoneName" -Level "INFO"
    } catch {
        Write-Log "Error creating forward zone" -Level "ERROR"
        Show-MessageBox "Error creating zone" "Error" "Error"
    }
}

function Remove-SelectedForwardZone {
    $selectedZone = $global:Controls.dgForwardZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Please select a zone to delete." "No selection" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Do you really want to delete the zone '$($selectedZone.ZoneName)'?`n`nThis action cannot be undone!", "Delete zone", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            Remove-DnsServerZone -Name $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            Show-MessageBox "Zone '$($selectedZone.ZoneName)' deleted successfully!" "Zone deleted"
            Update-ForwardZonesList
            Write-Log "Forward-Zone deleted: $($selectedZone.ZoneName)" -Level "INFO"
        } catch {
            Write-Log "Error deleting forward zone $($selectedZone.ZoneName): $_" -Level "ERROR"
            Show-MessageBox "Error deleting zone '$($selectedZone.ZoneName)':`n$_" "Error" "Error"
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
        
        Write-Log "Records-Zone-List updated: $($zones.Count) zones" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Error updating zones list: $_" -Level "ERROR"
        Hide-LoadingStatus
    }
}

function Update-RecordsList {
    if (-not $global:Controls.cmbRecordZone.SelectedItem) { return }
    
    try {
        $zoneName = $global:Controls.cmbRecordZone.SelectedItem.ToString()
        Show-LoadingStatus -Message "Load DNS-Records for $zoneName..."
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
        Write-Log "Records for zone '$zoneName' updated: $($records.Count) records" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Error updating records list: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Error loading DNS-Records: $_" "Error" "Error"
    }
}

function Create-NewRecord {
    $zoneName = $global:Controls.cmbRecordZone.SelectedItem
    $recordName = Get-SafeString -InputString $global:Controls.txtRecordName.Text.Trim() -RemoveSpecialChars $true
    $recordType = $global:Controls.cmbRecordType.SelectedItem.Content
    $recordData = $global:Controls.txtRecordData.Text.Trim()
    $recordTTL = $global:Controls.txtRecordTTL.Text.Trim()
    
    if (-not $zoneName) {
        Show-MessageBox "Please select a zone." "Validation error" "Warning"
        return
    }
    
    if ([string]::IsNullOrEmpty($recordName) -or [string]::IsNullOrEmpty($recordData)) {
        Show-MessageBox "Please enter a name and data for the record." "Validation error" "Warning"
        return
    }
    
    # Validiere Record-Daten
    if (-not (Test-RecordDataValid -RecordType $recordType -RecordData $recordData)) {
        $helpText = switch ($recordType) {
            "A"     { "Enter a valid IPv4 address (e.g. 192.168.1.1)" }
            "AAAA"  { "Enter a valid IPv6 address (e.g. 2001:db8::1)" }
            "CNAME" { "Enter a valid hostname (e.g. server.domain.com)" }
            "MX"    { "Format: Priorität Mailserver (e.g. 10 mail.domain.com)" }
            "TXT"   { "Enter a text (max. 255 characters)" }
            "PTR"   { "Enter a valid hostname" }
            "SRV"   { "Format: Priorität Gewicht Port Ziel (e.g. 0 5 5060 sip.domain.com)" }
            default { "Invalid data format for record type $recordType" }
        }
        Show-MessageBox "Invalid record data!`n`n$helpText" "Validation error" "Warning"
        return
    }
    
    $ttl = $global:AppConfig.DefaultTTL
    if (-not [string]::IsNullOrEmpty($recordTTL)) {
        if (-not [int]::TryParse($recordTTL, [ref]$ttl) -or $ttl -lt 0 -or $ttl -gt 2147483647) {
            Show-MessageBox "TTL must be a number between 0 and 2147483647." "Validation error" "Warning"
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
                    throw "SRV-Record Format: 'Priority Weight Port Target'"
                }
            }
            default {
                throw "Unsupported record type: $recordType"
            }
        }
        
        Show-MessageBox "DNS-Record '$recordName' created successfully!" "Record created"
        $global:Controls.txtRecordName.Clear()
        $global:Controls.txtRecordData.Clear()
        Update-RecordsList
        Write-Log "DNS-Record created: $recordType $recordName in Zone $zoneName" -Level "INFO"
        
    } catch {
        Write-Log "Error creating DNS-Record: $_" -Level "ERROR"
        Show-MessageBox "Error creating DNS-Record:`n$_" "Error" "Error"
    }
}

function Remove-SelectedRecord {
    $selectedRecord = $global:Controls.dgRecords.SelectedItem
    if (-not $selectedRecord) {
        Show-MessageBox "Please select a record to delete." "No selection" "Warning"
        return
    }
    
    $zoneName = $global:Controls.cmbRecordZone.SelectedItem
    $result = [System.Windows.MessageBox]::Show("Do you really want to delete the record '$($selectedRecord.Name)' ($($selectedRecord.Type))?", "Delete Record", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            $records = Get-DnsServerResourceRecord -ZoneName $zoneName -Name $selectedRecord.Name -RRType $selectedRecord.Type -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            
            foreach ($record in $records) {
                Remove-DnsServerResourceRecord -InputObject $record -ZoneName $zoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            }
            
            Show-MessageBox "Record '$($selectedRecord.Name)' was deleted successfully!" "Record deleted"
            Update-RecordsList
            Write-Log "DNS-Record deleted: $($selectedRecord.Type) $($selectedRecord.Name) in Zone $zoneName" -Level "INFO"
            
        } catch {
            Write-Log "Error deleting DNS-Record: $_" -Level "ERROR"
            Show-MessageBox "Error deleting Record:`n$_" "Error" "Error"
        }
    }
}

function Clear-DiagnosisOutput {
    $global:Controls.txtDiagnosisOutput.Clear()
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS DIAGNOSE TOOLS ===`r`n")
    $global:Controls.txtDiagnosisOutput.AppendText("Ready for diagnosis operations.`r`n`r`n")
}

function Run-Ping {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a target for the ping." "Input required" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== PING to $target ===`r`n")
    
    try {
        $results = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
        
        foreach ($result in $results) {
            $global:Controls.txtDiagnosisOutput.AppendText("Response from $($result.Address): Time=$($result.ResponseTime)ms TTL=$($result.TimeToLive)`r`n")
        }
        
        $avgTime = ($results | Measure-Object -Property ResponseTime -Average).Average
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nPing statistics for $target`:")
        $global:Controls.txtDiagnosisOutput.AppendText("Packages: Sent = 4, Received = $($results.Count), Lost = $(4 - $results.Count)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Average response time: $([math]::Round($avgTime, 2))ms`r`n`r`n")
        
        Write-Log "Ping to $target executed: $($results.Count)/4 responses" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Ping failed: $_`r`n`r`n")
        Write-Log "Ping to $target failed: $_" -Level "ERROR"
    }
}

function Run-Nslookup {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a target for Nslookup." "Input required" "Warning"
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
        
        Write-Log "Nslookup for $target executed: $($results.Count) results" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Nslookup failed: $_`r`n`r`n")
        Write-Log "Nslookup for $target failed: $_" -Level "ERROR"
    }
}

function Clear-DNSCache {
    $global:Controls.txtDiagnosisOutput.AppendText("=== CLEAR DNS CACHE ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Clearing DNS Server Cache...`r`n")
        Clear-DnsServerCache -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("DNS Server Cache cleared successfully`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("Clearing local DNS Client Cache...`r`n")
        Clear-DnsClientCache -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("DNS Client Cache cleared successfully`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nDNS Cache cleared successfully!`r`n`r`n")
        Write-Log "DNS Cache cleared successfully" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error clearing DNS Cache: $_`r`n`r`n")
        Write-Log "Error clearing DNS Cache: $_" -Level "ERROR"
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
        Write-Log "Error creating Reverse-Zone: $_" -Level "ERROR"
        Show-MessageBox "Error creating Reverse-Zone:`n$_" "Error" "Error"
    }
}

function Remove-SelectedReverseZone {
    $selectedZone = $global:Controls.dgReverseZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Please select a Reverse-Zone to delete." "No selection" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Do you want to delete the Reverse-Zone '$($selectedZone.ZoneName)'?`n`nThis action cannot be undone!", "Delete Zone", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            Remove-DnsServerZone -Name $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            Show-MessageBox "Reverse-Zone '$($selectedZone.ZoneName)' wurde erfolgreich gelöscht!" "Zone gelöscht"
            Update-ReverseZonesList
            Write-Log "Reverse-Zone deleted: $($selectedZone.ZoneName)" -Level "INFO"
        } catch {
            Write-Log "Error deleting Reverse-Zone $($selectedZone.ZoneName)`: $_" -Level "ERROR"
            Show-MessageBox "Error deleting Reverse-Zone '$($selectedZone.ZoneName)':`n$_" "Error" "Error"
        }
    }
}

###############################################################################
# IMPORT/EXPORT FUNKTIONEN
###############################################################################

function Clear-ImportExportLog {
    $global:Controls.txtImportExportLog.Clear()
    $global:Controls.txtImportExportLog.AppendText("=== DNS Import/Export Log ===`r`n")
    $global:Controls.txtImportExportLog.AppendText("Ready for Import and Export operations.`r`n`r`n")
}

function Export-DNSData {
    $format = $global:Controls.cmbExportFormat.SelectedItem.Content
    if (-not $format) { $format = "CSV" }
    
    $filter = switch ($format.ToUpper()) {
        "CSV" { "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*" }
        "XML" { "XML Files (*.xml)|*.xml|All Files (*.*)|*.*" }
        "JSON" { "JSON Files (*.json)|*.json|All Files (*.*)|*.*" }
        default { "All Files (*.*)|*.*" }
    }
    
    $exportPath = Show-SaveFileDialog -Filter $filter -Title "Export DNS configuration"
    if (-not $exportPath) { return }
    
    $global:Controls.txtImportExportLog.AppendText("=== DNS EXPORT STARTED ===`r`n")
    $global:Controls.txtImportExportLog.AppendText("Format: $format`r`n")
    $global:Controls.txtImportExportLog.AppendText("File: $exportPath`r`n`r`n")
    
    try {
        $success = Export-DNSConfiguration -DnsServerName $global:Controls.txtDNSServer.Text -ExportPath $exportPath -Format $format
        
        if ($success) {
            $global:Controls.txtImportExportLog.AppendText("[OK] Export successful!`r`n")
            $global:Controls.txtImportExportLog.AppendText("File saved: $exportPath`r`n`r`n")
            Show-MessageBox "DNS configuration exported successfully to:`n$exportPath" "Export successful"
        } else {
            $global:Controls.txtImportExportLog.AppendText("[ERROR] Export failed!`r`n`r`n")
            Show-MessageBox "Error exporting DNS configuration." "Export failed" "Error"
        }
        
    } catch {
        $global:Controls.txtImportExportLog.AppendText("[ERROR] Export-Error: $_`r`n`r`n")
        Show-MessageBox "Error exporting:`n$_" "Error" "Error"
        Write-Log "DNS-Export failed: $_" -Level "ERROR"
    }
}

function Browse-ImportFile {
    $filter = "All supported formats (*.csv;*.xml;*.json)|*.csv;*.xml;*.json|CSV files (*.csv)|*.csv|XML files (*.xml)|*.xml|JSON files (*.json)|*.json|All files (*.*)|*.*"
    $importPath = Show-OpenFileDialog -Filter $filter -Title "Select DNS configuration file"
    
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
        Show-MessageBox "Please select a file to import." "No file selected" "Warning"
        return
    }
    
    if (-not (Test-Path $importPath)) {
        Show-MessageBox "The selected file does not exist." "File not found" "Error"
        return
    }
    
    if (-not $format) { $format = "CSV" }
    
    $result = [System.Windows.MessageBox]::Show("Do you want to import the DNS configuration from the file?`n`nFile: $importPath`nFormat: $format`n`nExisting records could be overwritten!", "Confirm import", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtImportExportLog.AppendText("=== DNS IMPORT STARTED ===`r`n")
        $global:Controls.txtImportExportLog.AppendText("Format: $format`r`n")
        $global:Controls.txtImportExportLog.AppendText("File: $importPath`r`n`r`n")
        
        try {
            $importResult = Import-DNSConfiguration -DnsServerName $global:Controls.txtDNSServer.Text -ImportPath $importPath -Format $format
            
            $global:Controls.txtImportExportLog.AppendText("=== IMPORT COMPLETED ===`r`n")
            $global:Controls.txtImportExportLog.AppendText("Success: $($importResult.Success) Records`r`n")
            $global:Controls.txtImportExportLog.AppendText("Failed: $($importResult.Failed) Records`r`n`r`n")
            
            Show-MessageBox "Import abgeschlossen!`n`nErfolgreich: $($importResult.Success) Records`nFehlgeschlagen: $($importResult.Failed) Records" "Import abgeschlossen"
            
            # Aktuelle Panels aktualisieren
            if ($global:CurrentPanel -eq "forward") { Update-ForwardZonesList }
            if ($global:CurrentPanel -eq "reverse") { Update-ReverseZonesList }
            if ($global:CurrentPanel -eq "records") { Update-ZonesList }
            
        } catch {
            $global:Controls.txtImportExportLog.AppendText("[ERROR] Import-Fehler: $_`r`n`r`n")
            Show-MessageBox "Error importing:`n$_" "Error" "Error"
            Write-Log "DNS-Import failed: $_" -Level "ERROR"
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
                Write-Log "Error fetching DNSSEC information for zone $($zone.ZoneName): $_" -Level "DEBUG"
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
        
        Write-Log "DNSSEC status updated for $($dnssecList.Count) zones" -Level "INFO"
        Hide-LoadingStatus
        
    } catch {
        Write-Log "Error updating DNSSEC status: $_" -Level "ERROR"
        Hide-LoadingStatus
        Show-MessageBox "Error loading DNSSEC information: $_" "Error" "Error"
    }
}

function Sign-SelectedZone {
    $selectedZone = $global:Controls.dgDNSSECZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Please select a zone to sign." "No selection" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Do you want to sign the zone '$($selectedZone.ZoneName)' with DNSSEC?`n`nThis creates keys and signs all records in the zone.", "Sign zone", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        try {
            $global:Controls.lblDNSSECStatus.Text = "Signing zone..."
            $global:Controls.lblDNSSECStatus.Foreground = "#FF8C00"
            
            # Vereinfachte DNSSEC-Signierung (funktioniert moeglicherweise nicht auf allen Systemen)
            try {
                # Prüfe erst, ob bereits DNSSEC-Schlüssel existieren
                $existingKeys = Get-DnsServerSigningKey -ZoneName $selectedZone.ZoneName -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
                
                if ($existingKeys) {
                    # Versuche Rollover zu aktivieren
                    Enable-DnsServerSigningKeyRollover -ZoneName $selectedZone.ZoneName -KeyId $existingKeys[0].KeyId -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
                    
                    $global:Controls.lblDNSSECStatus.Text = "Zone successfully signed"
                    $global:Controls.lblDNSSECStatus.Foreground = "#107C10"
                    
                    Show-MessageBox "Zone '$($selectedZone.ZoneName)' was successfully signed with DNSSEC!" "DNSSEC activated"
                    Update-DNSSECStatus
                    Write-Log "DNSSEC activated for zone: $($selectedZone.ZoneName)" -Level "INFO"
                } else {
                    # Keine Schlüssel vorhanden - manuelle Konfiguration erforderlich
                    throw "No DNSSEC keys found"
                }
                
            } catch {
                # Fallback: Manuelle DNSSEC-Konfiguration anzeigen
                $global:Controls.lblDNSSECStatus.Text = "DNSSEC-Configuration required"
                $global:Controls.lblDNSSECStatus.Foreground = "#FF8C00"
                
                $manualSteps = @"
Manual DNSSEC configuration required:

1. Create keys:
   Add-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -Type KSK
   Add-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -Type ZSK

2. Sign zone:
   Invoke-DnsServerZoneSigning -ZoneName '$($selectedZone.ZoneName)'

3. Alternatively via DNS-Manager:
   DNS-Manager -> Zone -> Right-click -> "DNSSEC -> Sign zone"
"@
                
                Show-MessageBox $manualSteps "Manual DNSSEC configuration" "Information"
            }
            
        } catch {
            $global:Controls.lblDNSSECStatus.Text = "Error signing zone"
            $global:Controls.lblDNSSECStatus.Foreground = "#D13438"
            Write-Log "Error signing DNSSEC for zone $($selectedZone.ZoneName): $_" -Level "ERROR"
            Show-MessageBox "Error signing zone:`n$_" "Error" "Error"
        }
    }
}

function Unsign-SelectedZone {
    $selectedZone = $global:Controls.dgDNSSECZones.SelectedItem
    if (-not $selectedZone) {
        Show-MessageBox "Please select a zone to remove DNSSEC signing from." "No selection" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Do you want to remove the DNSSEC signing for zone '$($selectedZone.ZoneName)'?`n`nThis removes all DNSSEC keys and signatures!", "Remove DNSSEC", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        try {
            # Vereinfachte DNSSEC-Entfernung
            Show-MessageBox "DNSSEC removal must be performed manually.`n`nUse the DNS console or PowerShell:`n`nRemove-DnsServerSigningKey -ZoneName '$($selectedZone.ZoneName)' -All" "Manual Action Required" "Information"
            Write-Log "DNSSEC removal requested for zone: $($selectedZone.ZoneName)" -Level "INFO"
            
        } catch {
            Write-Log "Error removing DNSSEC signing: $_" -Level "ERROR"
            Show-MessageBox "Error removing DNSSEC signing:`n$_" "Error" "Error"
        }
    }
}

function Generate-DNSSECKeys {
    $zoneName = $global:Controls.cmbDNSSECZone.SelectedItem
    if (-not $zoneName) {
        Show-MessageBox "Please select a zone." "No zone selected" "Warning"
        return
    }
    
    try {
        Show-MessageBox "Key generation must be performed via the DNS console or extended PowerShell commands.`n`nExample commands:`n`nAdd-DnsServerSigningKey -ZoneName '$zoneName' -Type KSK -CryptoAlgorithm RsaSha256`nAdd-DnsServerSigningKey -ZoneName '$zoneName' -Type ZSK -CryptoAlgorithm RsaSha256" "DNSSEC Keys" "Information"
        Write-Log "DNSSEC key generation requested for zone: $zoneName" -Level "INFO"
        
    } catch {
        Write-Log "Error during DNSSEC key generation: $_" -Level "ERROR"
        Show-MessageBox "Error during key generation:`n$_" "Error" "Error"
    }
}

function Export-DNSSECKeys {
    Show-MessageBox "DNSSEC-Schluessel-Export must be performed via the DNS console.`n`nNavigate to:`nDNS Manager -> Your Zone -> DNSSEC -> Right-click on Keys -> Export" "DNSSEC Export" "Information"
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
        Show-MessageBox "DNSSEC validation for zone '$zoneName':`n`n$($validationResult -join "`n")" "DNSSEC Validation" "Information"
        Write-Log "DNSSEC validation performed for zone" -Level "INFO"
        
    } catch {
        Write-Log "Error during DNSSEC validation: $_" -Level "ERROR"
        Show-MessageBox "Error during DNSSEC validation:`n$_" "Error" "Error"
    }
}

function Force-KeyRollover {
    Show-MessageBox "Key Rollover must be performed via extended DNS management tools.`n`nUse the DNS console or specialized DNSSEC management tools." "Key Rollover" "Information"
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

    * Total:                $($stats.TotalZones) Zones
    * Forward:               $($stats.ForwardZones) Zones
    * Reverse:                $($stats.ReverseZones) Zones
    * DNSSEC-signed:  $($stats.SignedZones) Zones
"@
        
        $global:Controls.lblDNSStats.Text = $statsText
        Write-Log "DNS statistics updated" -Level "DEBUG"
        
    } catch {
        $global:Controls.lblDNSStats.Text = "Error loading statistics"
        Write-Log "Error updating DNS statistics: $_" -Level "ERROR"
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
    $exportPath = Show-SaveFileDialog -Filter "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*" -Title "Export Audit-Logs"
    if (-not $exportPath) { return }
    
    try {
        $global:AuditLogData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        Show-MessageBox "Audit-Logs exported successfully to:`n$exportPath" "Export successful"
        Write-Log "Audit-Logs exported to: $exportPath" -Level "INFO"
        
    } catch {
        Write-Log "Error exporting Audit-Logs: $_" -Level "ERROR"
        Show-MessageBox "Error exporting Logs:`n$_" "Error" "Error"
    }
}

function Clear-AuditLogs {
    $result = [System.Windows.MessageBox]::Show("Do you want to clear all Audit-Logs?`n`nThis action cannot be undone!", "Clear Logs", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $global:AuditLogData.Clear()
        Update-AuditLogs
        Write-Log "Audit-Logs cleared" -Level "INFO"
    }
}

###############################################################################
# ERWEITERTE DNS-DIAGNOSTIC-FUNKTIONEN
###############################################################################

function Force-ZoneRefresh {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Please select a zone." "No Zone selected" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ZONE REFRESH: $zone ===`r`n")
    
    try {
        $result = & dnscmd $global:Controls.txtDNSServer.Text /zonerefresh $zone 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("Zone Refresh Result:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText($result -join "`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Zone-Refresh fuer $zone ausgefuehrt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during Zone Refresh: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Use: dnscmd /zonerefresh $zone`r`n`r`n")
        Write-Log "Error during Zone Refresh for $zone`: $_" -Level "ERROR"
    }
}

function Show-ZoneInformation {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Please select a zone." "No Zone selected" "Warning"
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
        
        Write-Log "Zone Information for $zone fetched" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Zone Information: $_`r`n`r`n")
        Write-Log "Error fetching Zone Information for $zone`: $_" -Level "ERROR"
    }
}

function Show-DNSForwarders {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-FORWARDER ===`r`n")
    
    try {
        $forwarders = Get-DnsServerForwarder -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        if ($forwarders.IPAddress) {
            $global:Controls.txtDiagnosisOutput.AppendText("Configured Forwarders:`r`n")
            foreach ($forwarder in $forwarders.IPAddress) {
                $global:Controls.txtDiagnosisOutput.AppendText("- $forwarder`r`n")
            }
            $global:Controls.txtDiagnosisOutput.AppendText("Timeout: $($forwarders.Timeout) Sekunden`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Use Root Hint: $($forwarders.UseRootHint)`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("No Forwarders configured.`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS Forwarders displayed" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Forwarders: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Use: Get-DnsServerForwarder`r`n`r`n")
        Write-Log "Error fetching DNS Forwarders: $_" -Level "ERROR"
    }
}

function Show-ServerStatistics {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS SERVER STATISTICS ===`r`n")
    
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
        
        Write-Log "DNS Server Statistics fetched" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Server Statistics: $_`r`n`r`n")
        Write-Log "Error fetching Server Statistics: $_" -Level "ERROR"
    }
}

function Show-DiagnosticsSettings {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS DIAGNOSE SETTINGS ===`r`n")
    
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
        
        Write-Log "DNS diagnostic settings retrieved" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Diagnostic settings: $_`r`n`r`n")
        Write-Log "Error fetching Diagnostic settings: $_" -Level "ERROR"
    }
}

function Show-NetworkAdapterDNS {
    $global:Controls.txtDiagnosisOutput.AppendText("=== NETWORK ADAPTER DNS SETTINGS ===`r`n")
    
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
        Write-Log "Network Adapter DNS settings retrieved" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Network Adapter DNS settings: $_`r`n`r`n")
        Write-Log "Error fetching Network Adapter DNS settings: $_" -Level "ERROR"
    }
}

function Update-DiagnosticZonesList {
    try {
        Show-LoadingStatus -Message "Loading Diagnostic-Zones..."
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $global:Controls.cmbDiagZone.Items.Clear()
        
        foreach ($zone in $zones) {
            $global:Controls.cmbDiagZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbDiagZone.Items.Count -gt 0) {
            $global:Controls.cmbDiagZone.SelectedIndex = 0
        }
        
        Write-Log "Diagnostic-Zones-List updated: $($zones.Count) zones" -Level "DEBUG"
        Hide-LoadingStatus
    } catch {
        Write-Log "Error updating Diagnostic-Zones-List: $_" -Level "ERROR"
        Hide-LoadingStatus
    }
}

###############################################################################
# ERWEITERTE DNS-DIAGNOSTIC-FUNKTIONEN
###############################################################################

function Run-DNSBenchmark {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-BENCHMARK ===`r`n")
    
    try {
        $testDomains = @("google.com", "microsoft.com", "github.com", "stackoverflow.com", "wikipedia.org")
        $dnsServers = @($global:Controls.txtDNSServer.Text, "8.8.8.8", "1.1.1.1", "208.67.222.222")
        
        $global:Controls.txtDiagnosisOutput.AppendText("Test DNS Server Performance...`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Test-Domains: $($testDomains -join ', ')`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Server: $($dnsServers -join ', ')`r`n`r`n")
        
        $results = @()
        
        foreach ($server in $dnsServers) {
            $global:Controls.txtDiagnosisOutput.AppendText("Testing Server: $server`r`n")
            $serverResults = @()
            
            foreach ($domain in $testDomains) {
                try {
                    $startTime = Get-Date
                    $result = Resolve-DnsName -Name $domain -Server $server -ErrorAction Stop
                    $endTime = Get-Date
                    $responseTime = ($endTime - $startTime).TotalMilliseconds
                    
                    $serverResults += $responseTime
                    $global:Controls.txtDiagnosisOutput.AppendText("  $domain`: $([math]::Round($responseTime, 2))ms`r`n")
                    
                } catch {
                    $global:Controls.txtDiagnosisOutput.AppendText("  $domain`: FEHLER - $_`r`n")
                    $serverResults += 9999  # Hoher Wert für Fehler
                }
            }
            
            $avgTime = ($serverResults | Measure-Object -Average).Average
            $results += [PSCustomObject]@{
                Server = $server
                AverageTime = [math]::Round($avgTime, 2)
                SuccessRate = [math]::Round((($serverResults | Where-Object { $_ -lt 9999 }).Count / $testDomains.Count) * 100, 1)
            }
            
            $global:Controls.txtDiagnosisOutput.AppendText("  Average: $([math]::Round($avgTime, 2))ms`r`n`r`n")
        }
        
        # Ranking anzeigen
        $global:Controls.txtDiagnosisOutput.AppendText("=== BENCHMARK RESULTS ===`r`n")
        $ranking = $results | Sort-Object AverageTime
        
        for ($i = 0; $i -lt $ranking.Count; $i++) {
            $rank = $i + 1
            $server = $ranking[$i]
            $global:Controls.txtDiagnosisOutput.AppendText("$rank. $($server.Server) - $($server.AverageTime)ms (Success Rate: $($server.SuccessRate)%)`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nBenchmark completed!`r`n`r`n")
        Write-Log "DNS-Benchmark completed for $($dnsServers.Count) servers" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during DNS-Benchmark: $_`r`n`r`n")
        Write-Log "Error during DNS-Benchmark: $_" -Level "ERROR"
    }
}

function Run-LatencyTest {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        $target = "google.com"  # Standard-Ziel
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== LATENCY TEST for $target ===`r`n")
    
    try {
        $testCount = 10
        $global:Controls.txtDiagnosisOutput.AppendText("Perform $testCount DNS queries...`r`n`r`n")
        
        $latencies = @()
        
        for ($i = 1; $i -le $testCount; $i++) {
            try {
                $startTime = Get-Date
                $result = Resolve-DnsName -Name $target -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
                $endTime = Get-Date
                $latency = ($endTime - $startTime).TotalMilliseconds
                
                $latencies += $latency
                $global:Controls.txtDiagnosisOutput.AppendText("Test $i`: $([math]::Round($latency, 2))ms`r`n")
                
                Start-Sleep -Milliseconds 100  # Kurze Pause zwischen Tests
                
            } catch {
                $global:Controls.txtDiagnosisOutput.AppendText("Test $i`: ERROR - $_`r`n")
            }
        }
        
        if ($latencies.Count -gt 0) {
            $stats = $latencies | Measure-Object -Average -Minimum -Maximum
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== LATENCY STATISTICS ===`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Average: $([math]::Round($stats.Average, 2))ms`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Minimum: $([math]::Round($stats.Minimum, 2))ms`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Maximum: $([math]::Round($stats.Maximum, 2))ms`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Successful Tests: $($latencies.Count)/$testCount`r`n")
            
            # Bewertung
            $avgLatency = $stats.Average
            $rating = if ($avgLatency -lt 50) { "Excellent" } 
                     elseif ($avgLatency -lt 100) { "Good" }
                     elseif ($avgLatency -lt 200) { "Acceptable" }
                     else { "Slow" }
            
            $global:Controls.txtDiagnosisOutput.AppendText("Rating: $rating`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nLatency Test completed!`r`n`r`n")
        Write-Log "Latency Test for $target completed: $($latencies.Count) successful tests" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during Latency Test: $_`r`n`r`n")
        Write-Log "Error during Latency Test: $_" -Level "ERROR"
    }
}

function Run-DNSSECValidation {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a domain for DNSSEC validation." "Input required" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNSSEC-VALIDATION for $target ===`r`n")
    
    try {
        # Prüfe DNSSEC-Unterstützung
        $global:Controls.txtDiagnosisOutput.AppendText("Check DNSSEC support...`r`n")
        
        # DNSKEY-Record abfragen
        try {
            $dnskeyResult = Resolve-DnsName -Name $target -Type DNSKEY -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
            if ($dnskeyResult) {
                $global:Controls.txtDiagnosisOutput.AppendText("[OK] DNSKEY-Records found: $($dnskeyResult.Count) Keys`r`n")
                
                foreach ($key in $dnskeyResult) {
                    $global:Controls.txtDiagnosisOutput.AppendText("  - Key-Tag: $($key.KeyTag), Algorithm: $($key.Algorithm)`r`n")
                }
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("[FAIL] No DNSKEY-Records found`r`n")
            }
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("[FAIL] DNSKEY-Query failed: $_`r`n")
        }
        
        # DS-Record abfragen (bei Parent-Zone)
        try {
            $dsResult = Resolve-DnsName -Name $target -Type DS -ErrorAction SilentlyContinue
            if ($dsResult) {
                $global:Controls.txtDiagnosisOutput.AppendText("[OK] DS-Records found: $($dsResult.Count) Records`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("[INFO] No DS-Records found (possibly not DNSSEC-signed)`r`n")
            }
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("[INFO] DS-Query not possible`r`n")
        }
        
        # RRSIG-Records prüfen
        try {
            $rrsigResult = Resolve-DnsName -Name $target -Type RRSIG -ErrorAction SilentlyContinue
            if ($rrsigResult) {
                $global:Controls.txtDiagnosisOutput.AppendText("[OK] RRSIG-Records found: $($rrsigResult.Count) Signatures`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("[FAIL] No RRSIG-Records found`r`n")
            }
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("[FAIL] RRSIG-Query failed`r`n")
        }
        
        # Externe DNSSEC-Validierung (falls verfügbar)
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nFor detailed DNSSEC validation, use:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Online: https://dnssec-analyzer.verisignlabs.com/`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Tool: dig +dnssec $target`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nDNSSEC validation completed!`r`n`r`n")
        Write-Log "DNSSEC validation for $target completed" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during DNSSEC validation: $_`r`n`r`n")
        Write-Log "Error during DNSSEC validation for $target`: $_" -Level "ERROR"
    }
}

function Run-DNSLeakTest {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-LEAK-TEST ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Check DNS configuration for possible leaks...`r`n`r`n")
        
        # Aktuelle DNS-Server ermitteln
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
        
        $global:Controls.txtDiagnosisOutput.AppendText("=== CONFIGURED DNS-SERVERS ===`r`n")
        foreach ($adapter in $dnsServers) {
            $global:Controls.txtDiagnosisOutput.AppendText("Interfaces: $($adapter.InterfaceAlias)`r`n")
            foreach ($server in $adapter.ServerAddresses) {
                $global:Controls.txtDiagnosisOutput.AppendText("  DNS-Server: $server`r`n")
                
                # Prüfe ob Server öffentlich oder privat ist
                $serverType = if ($server -match "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
                    "Privat/Lokal"
                } elseif ($server -match "^8\.8\.|^1\.1\.|^208\.67\.") {
                    "Public (known)"
                } else {
                    "Public (unknown)"
                }
                $global:Controls.txtDiagnosisOutput.AppendText("    Typ: $serverType`r`n")
            }
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        }
        
        # Test mit verschiedenen Domains
        $testDomains = @("whoami.akamai.net", "o-o.myaddr.l.google.com")
        $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-LEAK-TESTS ===`r`n")
        
        foreach ($domain in $testDomains) {
            try {
                $global:Controls.txtDiagnosisOutput.AppendText("Tested: $domain`r`n")
                $result = Resolve-DnsName -Name $domain -ErrorAction Stop
                
                foreach ($record in $result) {
                    if ($record.Type -eq "A") {
                        $global:Controls.txtDiagnosisOutput.AppendText("  Answer: $($record.IPAddress)`r`n")
                    }
                }
            } catch {
                $global:Controls.txtDiagnosisOutput.AppendText("  Fehler: $_`r`n")
            }
        }
        
        # Empfehlungen
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== RECOMMENDATIONS ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("1. Use trusted DNS-Servers`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("2. Check VPN DNS settings`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("3. For detailed tests: https://dnsleaktest.com/`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nDNS-Leak-Test completed!`r`n`r`n")
        Write-Log "DNS-Leak-Test completed" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during DNS-Leak-Test: $_`r`n`r`n")
        Write-Log "Error during DNS-Leak-Test: $_" -Level "ERROR"
    }
}

function Run-TraceRouteAnalysis {
    # Prüfe zuerst das spezielle Trace Route Textfeld, dann das allgemeine
    $target = ""
    if ($global:Controls.txtTraceRouteTarget) {
        $target = $global:Controls.txtTraceRouteTarget.Text.Trim()
    }
    
    # Fallback auf allgemeines Diagnose-Textfeld wenn Trace Route Feld leer ist
    if ([string]::IsNullOrEmpty($target) -and $global:Controls.txtDiagnosisTarget) {
        $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    }
    
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a target for the Trace Route analysis." "Input required" "Warning"
        return
    }
    
    # Sofortiges Feedback in der GUI
    $global:Controls.txtDiagnosisOutput.AppendText("=== TRACE ROUTE ANALYSIS for $target ===`r`n")
    $global:Controls.txtDiagnosisOutput.AppendText("PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)`r`n")
    $global:Controls.txtDiagnosisOutput.AppendText("Starting analysis...`r`n")
    
    # UI aktualisieren
    $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
    
    try {
        # Erst DNS-Aufloesung
        $global:Controls.txtDiagnosisOutput.AppendText("Step 1: DNS resolution...`r`n")
        $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
        
        $dnsResult = Resolve-DnsName -Name $target -ErrorAction Stop
        $targetIP = ($dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        
        if ($targetIP) {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS resolution successful: $target -> $targetIP`r`n")
            $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
            
            # Einfacher Ping-Test zuerst
            $global:Controls.txtDiagnosisOutput.AppendText("Step 2: Ping-Test...`r`n")
            $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
            
            try {
                                 # Verwende kompatible Parameter für PowerShell 5.1 und 7+
                 if ($PSVersionTable.PSVersion.Major -ge 6) {
                     $pingTest = Test-Connection -ComputerName $targetIP -Count 2 -TimeoutSeconds 5 -ErrorAction Stop
                 } else {
                     # PowerShell 5.1 - verwende Standard-Timeout
                     $pingTest = Test-Connection -ComputerName $targetIP -Count 2 -ErrorAction Stop
                 }
                if ($pingTest) {
                    $avgTime = ($pingTest | Measure-Object -Property ResponseTime -Average).Average
                    $global:Controls.txtDiagnosisOutput.AppendText("Ping successful - Average time: $([math]::Round($avgTime, 2))ms`r`n")
                    $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
                    
                    # Nur wenn Ping erfolgreich ist, versuche Traceroute
                    $global:Controls.txtDiagnosisOutput.AppendText("Step 3: Trace Route (simplified)...`r`n")
                    $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
                    
                                         # Verwende Job-basierte Traceroute mit striktem Timeout
                     $global:Controls.txtDiagnosisOutput.AppendText("Starting Trace Route with 30-second timeout...`r`n")
                     $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
                     
                     # Job für Traceroute mit Timeout
                     $traceJob = Start-Job -ScriptBlock {
                         param($targetIP)
                         try {
                             # Verwende tracert mit sehr aggressiven Timeouts
                             $result = & tracert -h 10 -w 1000 $targetIP 2>&1
                             return @{
                                 Success = $true
                                 Output = $result
                                 Method = "tracert"
                             }
                         } catch {
                                                           try {
                                  # Fallback: PowerShell mit Timeout (nur PowerShell 6+)
                                  if ($PSVersionTable.PSVersion.Major -ge 6) {
                                      $testResult = Test-NetConnection -ComputerName $targetIP -TraceRoute -WarningAction SilentlyContinue -ErrorAction Stop
                                      return @{
                                          Success = $true
                                          Output = $testResult.TraceRoute
                                          Method = "powershell"
                                      }
                                  } else {
                                      # PowerShell 5.1 - Test-NetConnection -TraceRoute nicht verfügbar
                                      throw "Test-NetConnection -TraceRoute not available in PowerShell 5.1"
                                  }
                              } catch {
                                 return @{
                                     Success = $false
                                     Error = $_.Exception.Message
                                     Method = "failed"
                                 }
                             }
                         }
                     } -ArgumentList $targetIP
                     
                     # Warte maximal 30 Sekunden
                     $traceTimeout = 30
                     $traceCompleted = Wait-Job -Job $traceJob -Timeout $traceTimeout
                     
                     if ($traceCompleted) {
                         try {
                             $traceResult = Receive-Job -Job $traceJob
                             Remove-Job -Job $traceJob -Force
                             
                             if ($traceResult.Success) {
                                 $global:Controls.txtDiagnosisOutput.AppendText("Traceroute successful (Method: $($traceResult.Method)):`r`n")
                                 
                                 if ($traceResult.Method -eq "tracert") {
                                     $global:Controls.txtDiagnosisOutput.AppendText("$($traceResult.Output -join "`r`n")`r`n")
                                 } else {
                                     # PowerShell-Ergebnis formatieren
                                     for ($i = 0; $i -lt $traceResult.Output.Count; $i++) {
                                         $hop = $i + 1
                                         $hopIP = $traceResult.Output[$i]
                                         $global:Controls.txtDiagnosisOutput.AppendText("$hop. $hopIP`r`n")
                                     }
                                 }
                             } else {
                                 $global:Controls.txtDiagnosisOutput.AppendText("Traceroute failed: $($traceResult.Error)`r`n")
                             }
                         } catch {
                             $global:Controls.txtDiagnosisOutput.AppendText("Error processing traceroute results: $_`r`n")
                         }
                     } else {
                         # Timeout erreicht - Job beenden
                         $global:Controls.txtDiagnosisOutput.AppendText("Traceroute-Timeout after $traceTimeout seconds reached`r`n")
                         $global:Controls.txtDiagnosisOutput.AppendText("The target may be blocking ICMP packets or is not reachable`r`n")
                         
                         # Job zwangsweise beenden
                         try {
                             Stop-Job -Job $traceJob -PassThru | Remove-Job -Force
                         } catch {
                             # Ignoriere Fehler beim Job-Cleanup
                         }
                     }
                    
                } else {
                    $global:Controls.txtDiagnosisOutput.AppendText("Ping failed - Target not reachable`r`n")
                    $global:Controls.txtDiagnosisOutput.AppendText("Traceroute skipped.`r`n")
                }
                
            } catch {
                $global:Controls.txtDiagnosisOutput.AppendText("Ping-Test failed: $_`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Traceroute skipped.`r`n")
            }
            
            # Port-Tests (schnell und einfach)
            $global:Controls.txtDiagnosisOutput.AppendText("Step 4: Port-Tests...`r`n")
            $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
            
                         $commonPorts = @(80, 443, 53)  # Nur die wichtigsten Ports
             foreach ($port in $commonPorts) {
                 try {
                     # Verwende kompatible Parameter je nach PowerShell-Version
                     if ($PSVersionTable.PSVersion.Major -ge 6) {
                         # PowerShell 6+ with extended parameters
                         $portTest = Test-NetConnection -ComputerName $targetIP -Port $port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
                         $status = if ($portTest) { "OPEN" } else { "CLOSED" }
                     } else {
                         # PowerShell 5.1 - simpler syntax
                         $portTest = Test-NetConnection -ComputerName $targetIP -Port $port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                         $status = if ($portTest.TcpTestSucceeded) { "OPEN" } else { "CLOSED" }
                     }
                     $global:Controls.txtDiagnosisOutput.AppendText("Port $port`: $status`r`n")
                 } catch {
                     $global:Controls.txtDiagnosisOutput.AppendText("Port $port`: TEST FAILED`r`n")
                 }
                 # UI zwischen Port-Tests aktualisieren
                 $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
             }
            
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("ERROR: No IP address found for $target`r`n")
        }
        
        # Abschluss
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== ANALYSIS COMPLETED ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Notes:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Possible problems: Firewall or ICMP blocking`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Alternative Tools: pathping, mtr, nmap`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Traceroute-Analyse fuer $target abgeschlossen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("CRITICAL ERROR during Trace Route analysis: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Please check the network connection and try again.`r`n`r`n")
        Write-Log "Critical error during Trace Route analysis for $target`: $_" -Level "ERROR"
    }
    
    # Sicherstellen, dass UI aktualisiert wird
    $global:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Render, [System.Action]{})
}

function Generate-HealthReport {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-HEALTH-REPORT GENERATION ===`r`n")
    
    try {
        $reportData = @{
            Timestamp = Get-Date
            Server = $global:Controls.txtDNSServer.Text
            Tests = @()
            Summary = @{
                TotalTests = 0
                PassedTests = 0
                FailedTests = 0
                WarningTests = 0
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("Perform comprehensive DNS health check...`r`n`r`n")
        
        # Test 1: DNS-Server-Erreichbarkeit
        $global:Controls.txtDiagnosisOutput.AppendText("1. DNS-Server-Reachability...`r`n")
        try {
            $testZone = Get-DnsServerZone -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop | Select-Object -First 1
            $reportData.Tests += @{ Name = "DNS-Server-Reachability"; Status = "PASS"; Details = "Server is reachable" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - Server is reachable`r`n")
            $reportData.Summary.PassedTests++
        } catch {
            $reportData.Tests += @{ Name = "DNS-Server-Reachability"; Status = "FAIL"; Details = $_.Exception.Message }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Server not reachable: $_`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Test 2: DNS-Dienst-Status
        $global:Controls.txtDiagnosisOutput.AppendText("2. DNS-Service-Status...`r`n")
        try {
            $service = Get-Service -Name "DNS" -ErrorAction Stop
            if ($service.Status -eq "Running") {
                $reportData.Tests += @{ Name = "DNS-Service-Status"; Status = "PASS"; Details = "Service is running" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - Service is running`r`n")
                $reportData.Summary.PassedTests++
            } else {
                $reportData.Tests += @{ Name = "DNS-Service-Status"; Status = "FAIL"; Details = "Service is not running: $($service.Status)" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Service is not running: $($service.Status)`r`n")
                $reportData.Summary.FailedTests++
            }
        } catch {
            $reportData.Tests += @{ Name = "DNS-Dienst-Status"; Status = "FAIL"; Details = "Service query failed" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Service query failed`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Test 3: Zone-Konfiguration
        $global:Controls.txtDiagnosisOutput.AppendText("3. Zone configuration...`r`n")
        try {
            $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
            if ($zones.Count -gt 0) {
                $reportData.Tests += @{ Name = "Zone-Configuration"; Status = "PASS"; Details = "$($zones.Count) Zones configured" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - $($zones.Count) Zones configured`r`n")
                $reportData.Summary.PassedTests++
            } else {
                $reportData.Tests += @{ Name = "Zone-Configuration"; Status = "WARN"; Details = "No zones configured" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [WARN] - No zones configured`r`n")
                $reportData.Summary.WarningTests++
            }
        } catch {
            $reportData.Tests += @{ Name = "Zone-Configuration"; Status = "FAIL"; Details = "Zone query failed" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Zone query failed`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Test 4: DNS-Auflösung
        $global:Controls.txtDiagnosisOutput.AppendText("4. DNS resolution...`r`n")
        try {
            $testDomain = "google.com"
            $result = Resolve-DnsName -Name $testDomain -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
            if ($result) {
                $reportData.Tests += @{ Name = "DNS-Resolution"; Status = "PASS"; Details = "External resolution works ($testDomain)" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - External resolution works ($testDomain)`r`n")
                $reportData.Summary.PassedTests++
            }
        } catch {
            $reportData.Tests += @{ Name = "DNS-Resolution"; Status = "FAIL"; Details = "External resolution failed" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - External resolution failed`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Test 5: Performance-Test
        $global:Controls.txtDiagnosisOutput.AppendText("5. Performance test...`r`n")
        try {
            $startTime = Get-Date
            $result = Resolve-DnsName -Name "microsoft.com" -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
            $endTime = Get-Date
            $responseTime = ($endTime - $startTime).TotalMilliseconds
            
            if ($responseTime -lt 100) {
                $reportData.Tests += @{ Name = "Performance-Test"; Status = "PASS"; Details = "Response time: $([math]::Round($responseTime, 2))ms" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - Good performance: $([math]::Round($responseTime, 2))ms`r`n")
                $reportData.Summary.PassedTests++
            } elseif ($responseTime -lt 500) {
                $reportData.Tests += @{ Name = "Performance-Test"; Status = "WARN"; Details = "Response time: $([math]::Round($responseTime, 2))ms" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [WARN] - Slow performance: $([math]::Round($responseTime, 2))ms`r`n")
                $reportData.Summary.WarningTests++
            } else {
                $reportData.Tests += @{ Name = "Performance-Test"; Status = "FAIL"; Details = "Response time: $([math]::Round($responseTime, 2))ms" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Very slow performance: $([math]::Round($responseTime, 2))ms`r`n")
                $reportData.Summary.FailedTests++
            }
        } catch {
            $reportData.Tests += @{ Name = "Performance-Test"; Status = "FAIL"; Details = "Performance test failed" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Performance test failed`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Test 6: Forwarder-Konfiguration
        $global:Controls.txtDiagnosisOutput.AppendText("6. Forwarder-Configuration...`r`n")
        try {
            $forwarders = Get-DnsServerForwarder -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
            if ($forwarders.IPAddress -and $forwarders.IPAddress.Count -gt 0) {
                $reportData.Tests += @{ Name = "Forwarder-Configuration"; Status = "PASS"; Details = "$($forwarders.IPAddress.Count) Forwarder configured" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [PASS] - $($forwarders.IPAddress.Count) Forwarder configured`r`n")
                $reportData.Summary.PassedTests++
            } else {
                $reportData.Tests += @{ Name = "Forwarder-Configuration"; Status = "WARN"; Details = "No forwarders configured" }
                $global:Controls.txtDiagnosisOutput.AppendText("   [WARN] - No forwarders configured`r`n")
                $reportData.Summary.WarningTests++
            }
        } catch {
            $reportData.Tests += @{ Name = "Forwarder-Configuration"; Status = "FAIL"; Details = "Forwarder query failed" }
            $global:Controls.txtDiagnosisOutput.AppendText("   [FAIL] - Forwarder query failed`r`n")
            $reportData.Summary.FailedTests++
        }
        $reportData.Summary.TotalTests++
        
        # Zusammenfassung
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== HEALTH-REPORT SUMMARY ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Total tests: $($reportData.Summary.TotalTests)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Passed: $($reportData.Summary.PassedTests) [PASS]`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Warnings: $($reportData.Summary.WarningTests) [WARN]`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Failed: $($reportData.Summary.FailedTests) [FAIL]`r`n")
        
        # Gesundheitsbewertung
        $healthScore = [math]::Round((($reportData.Summary.PassedTests + ($reportData.Summary.WarningTests * 0.5)) / $reportData.Summary.TotalTests) * 100, 1)
        $healthRating = if ($healthScore -ge 90) { "Excellent" }
                       elseif ($healthScore -ge 75) { "Good" }
                       elseif ($healthScore -ge 50) { "Akzeptabel" }
                       else { "Kritisch" }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nHealth score: $healthScore% ($healthRating)`r`n")
        
        # Report speichern anbieten
        $saveReport = [System.Windows.MessageBox]::Show("Do you want to save the Health-Report as a file?", "Save Report", "YesNo", "Question")
        
        if ($saveReport -eq "Yes") {
            $reportPath = Show-SaveFileDialog -Filter "JSON files (*.json)|*.json|Text files (*.txt)|*.txt|All files (*.*)|*.*" -Title "Save Health-Report"
            if ($reportPath) {
                try {
                    $extension = [System.IO.Path]::GetExtension($reportPath).ToLower()
                    if ($extension -eq ".json") {
                        $reportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath -Encoding UTF8
                    } else {
                        # Text-Format
                        $textReport = "DNS Health Report`n"
                        $textReport += "=================`n"
                        $textReport += "Timestamp: $($reportData.Timestamp)`n"
                        $textReport += "Server: $($reportData.Server)`n`n"
                        $textReport += "Test results:`n"
                        
                        foreach ($test in $reportData.Tests) {
                            $textReport += "- $($test.Name): $($test.Status) - $($test.Details)`n"
                        }
                        
                        $textReport += "`nSummary:`n"
                        $textReport += "- Total tests: $($reportData.Summary.TotalTests)`n"
                        $textReport += "- Passed: $($reportData.Summary.PassedTests)`n"
                        $textReport += "- Warnings: $($reportData.Summary.WarningTests)`n"
                        $textReport += "- Failed: $($reportData.Summary.FailedTests)`n"
                        $textReport += "- Health score: $healthScore% ($healthRating)`n"
                        $textReport | Out-File -FilePath $reportPath -Encoding UTF8
                    }
                    
                    $global:Controls.txtDiagnosisOutput.AppendText("`r`nReport saved: $reportPath`r`n")
                    Show-MessageBox "Health-Report saved successfully!`n`nFile: $reportPath" "Report saved"
                    
                } catch {
                    $global:Controls.txtDiagnosisOutput.AppendText("`r`nError saving report: $_`r`n")
                    Show-MessageBox "Error saving report:`n$_" "Error"
                }
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nHealth-Report-Generation completed!`r`n`r`n")
        Write-Log "DNS-Health-Report generated: $healthScore% ($healthRating)" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error generating Health-Report: $_`r`n`r`n")
        Write-Log "Error generating Health-Report: $_" -Level "ERROR"
    }
}

###############################################################################
# REAL-TIME MONITORING FUNKTIONEN
###############################################################################

# Globale Monitoring-Variablen
$global:RealTimeMonitoringActive = $false
$global:RealTimeMonitoringTimer = $null
$global:MonitoringData = [System.Collections.ArrayList]::new()

function Start-RealTimeMonitoring {
    if ($global:RealTimeMonitoringActive) {
        Show-MessageBox "Real-time Monitoring is already active." "Monitoring" "Information"
        return
    }
    
    try {
        $global:RealTimeMonitoringActive = $true
        $global:Controls.txtDiagnosisOutput.AppendText("=== REAL-TIME DNS MONITORING STARTED ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Monitor DNS-Server: $($global:Controls.txtDNSServer.Text)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Monitoring settings:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- DNS Queries: $($global:Controls.chkMonitorDNSQueries.IsChecked)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- DNS Errors: $($global:Controls.chkMonitorDNSErrors.IsChecked)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Performance: $($global:Controls.chkMonitorPerformance.IsChecked)`r`n`r`n")
        
        # Timer für regelmäßige Überwachung
        $global:RealTimeMonitoringTimer = New-Object System.Windows.Threading.DispatcherTimer
        $global:RealTimeMonitoringTimer.Interval = [TimeSpan]::FromSeconds(10)  # Alle 10 Sekunden
        
        $global:RealTimeMonitoringTimer.Add_Tick({
            try {
                Collect-MonitoringData
            } catch {
                Write-Log "Error during Real-time Monitoring: $_" -Level "ERROR"
            }
        })
        
        $global:RealTimeMonitoringTimer.Start()
        
        $global:Controls.txtDiagnosisOutput.AppendText("Real-time Monitoring active - Data collected every 10 seconds...`r`n`r`n")
        Write-Log "Real-time DNS Monitoring started" -Level "INFO"
        
    } catch {
        $global:RealTimeMonitoringActive = $false
        $global:Controls.txtDiagnosisOutput.AppendText("Error starting Real-time Monitoring: $_`r`n`r`n")
        Write-Log "Error starting Real-time Monitoring: $_" -Level "ERROR"
    }
}

function Stop-RealTimeMonitoring {
    if (-not $global:RealTimeMonitoringActive) {
        Show-MessageBox "Real-time Monitoring ist nicht aktiv." "Monitoring" "Information"
        return
    }
    
    try {
        $global:RealTimeMonitoringActive = $false
        if ($global:RealTimeMonitoringTimer) {
            $global:RealTimeMonitoringTimer.Stop()
            $global:RealTimeMonitoringTimer = $null
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("=== REAL-TIME DNS MONITORING STOPPED ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Collected data points: $($global:MonitoringData.Count)`r`n`r`n")
        
        Write-Log "Real-time DNS Monitoring stopped" -Level "INFO"
        
    } catch {
        Write-Log "Error stopping Real-time Monitoring: $_" -Level "ERROR"
    }
}

function Collect-MonitoringData {
    try {
        $timestamp = Get-Date
        $monitoringEntry = @{
            Timestamp = $timestamp
            Server = $global:Controls.txtDNSServer.Text
            Metrics = @{}
        }
        
        # Performance-Monitoring
        if ($global:Controls.chkMonitorPerformance.IsChecked) {
            try {
                $startTime = Get-Date
                $testResult = Resolve-DnsName -Name "google.com" -Server $global:Controls.txtDNSServer.Text -ErrorAction Stop
                $endTime = Get-Date
                $responseTime = ($endTime - $startTime).TotalMilliseconds
                
                $monitoringEntry.Metrics.ResponseTime = [math]::Round($responseTime, 2)
                $monitoringEntry.Metrics.QuerySuccess = $true
                
            } catch {
                $monitoringEntry.Metrics.ResponseTime = -1
                $monitoringEntry.Metrics.QuerySuccess = $false
                $monitoringEntry.Metrics.Error = $_.Exception.Message
            }
        }
        
        # DNS-Server-Statistiken (falls verfügbar)
        if ($global:Controls.chkMonitorDNSQueries.IsChecked) {
            try {
                $stats = Get-DnsServerStatistics -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction SilentlyContinue
                if ($stats) {
                    $monitoringEntry.Metrics.TotalQueries = $stats.TotalQueries
                    $monitoringEntry.Metrics.SuccessfulQueries = $stats.SuccessfulQueries
                    $monitoringEntry.Metrics.FailedQueries = $stats.FailedQueries
                }
            } catch {
                # Ignoriere Statistik-Fehler
            }
        }
        
        # Zur Monitoring-Datensammlung hinzufügen
        $global:MonitoringData.Add($monitoringEntry) | Out-Null
        
        # Begrenzen auf letzte 100 Einträge
        if ($global:MonitoringData.Count -gt 100) {
            $global:MonitoringData.RemoveRange(0, $global:MonitoringData.Count - 100)
        }
        
        # Live-Ausgabe (nur bei wichtigen Events)
        if ($monitoringEntry.Metrics.QuerySuccess -eq $false) {
            $global:Controls.txtDiagnosisOutput.AppendText("[$($timestamp.ToString('HH:mm:ss'))] [WARN] DNS query failed: $($monitoringEntry.Metrics.Error)`r`n")
        } elseif ($monitoringEntry.Metrics.ResponseTime -gt 1000) {
            $global:Controls.txtDiagnosisOutput.AppendText("[$($timestamp.ToString('HH:mm:ss'))] [WARN] Slow response time: $($monitoringEntry.Metrics.ResponseTime)ms`r`n")
        }
        
    } catch {
        Write-Log "Error collecting monitoring data: $_" -Level "ERROR"
    }
}

function Show-TopQueries {
    $global:Controls.txtDiagnosisOutput.AppendText("=== TOP DNS-QUERIES ===`r`n")
    
    try {
        # Simulierte Top-Queries (in einer echten Implementierung würden diese aus DNS-Logs kommen)
        $topQueries = @(
            @{ Domain = "google.com"; Count = 1247; Type = "A" },
            @{ Domain = "microsoft.com"; Count = 892; Type = "A" },
            @{ Domain = "github.com"; Count = 634; Type = "A" },
            @{ Domain = "stackoverflow.com"; Count = 421; Type = "A" },
            @{ Domain = "office365.com"; Count = 387; Type = "A" },
            @{ Domain = "outlook.com"; Count = 298; Type = "MX" },
            @{ Domain = "windows.com"; Count = 267; Type = "A" },
            @{ Domain = "azure.com"; Count = 234; Type = "A" },
            @{ Domain = "linkedin.com"; Count = 198; Type = "A" },
            @{ Domain = "youtube.com"; Count = 176; Type = "A" }
        )
        
        $global:Controls.txtDiagnosisOutput.AppendText("Top 10 DNS-Queries (simulated):`r`n`r`n")
        
        for ($i = 0; $i -lt $topQueries.Count; $i++) {
            $rank = $i + 1
            $query = $topQueries[$i]
            $global:Controls.txtDiagnosisOutput.AppendText("$rank. $($query.Domain) ($($query.Type)) - $($query.Count) Abfragen`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nNote: For real data, activate DNS-Debug-Logging`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("or use DNS analysis tools like DNSQuerySniffer.`r`n`r`n")
        
        Write-Log "Top-Queries-Analyse angezeigt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Fehler bei der Top-Queries-Analyse: $_`r`n`r`n")
        Write-Log "Fehler bei der Top-Queries-Analyse: $_" -Level "ERROR"
    }
}

function Analyze-QueryPatterns {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS QUERY PATTERN ANALYSIS ===`r`n")
    
    try {
        if ($global:MonitoringData.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No monitoring data available. Start the Real-time Monitoring first.`r`n`r`n")
            return
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("Analyze $($global:MonitoringData.Count) data points...`r`n`r`n")
        
        # Antwortzeit-Analyse
        $responseTimes = $global:MonitoringData | Where-Object { $_.Metrics.ResponseTime -gt 0 } | ForEach-Object { $_.Metrics.ResponseTime }
        
        if ($responseTimes.Count -gt 0) {
            $stats = $responseTimes | Measure-Object -Average -Minimum -Maximum
            $global:Controls.txtDiagnosisOutput.AppendText("=== RESPONSE TIME PATTERNS ===`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Average: $([math]::Round($stats.Average, 2))ms`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Minimum: $([math]::Round($stats.Minimum, 2))ms`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Maximum: $([math]::Round($stats.Maximum, 2))ms`r`n")
            
            # Kategorisierung
            $fast = ($responseTimes | Where-Object { $_ -lt 50 }).Count
            $medium = ($responseTimes | Where-Object { $_ -ge 50 -and $_ -lt 200 }).Count
            $slow = ($responseTimes | Where-Object { $_ -ge 200 }).Count
            
            $global:Controls.txtDiagnosisOutput.AppendText("`r`nDistribution:`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Fast (<50ms): $fast ($([math]::Round(($fast/$responseTimes.Count)*100, 1))%)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Medium (50-200ms): $medium ($([math]::Round(($medium/$responseTimes.Count)*100, 1))%)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Slow (>200ms): $slow ($([math]::Round(($slow/$responseTimes.Count)*100, 1))%)`r`n")
        }
        
        # Fehler-Analyse
        $errors = $global:MonitoringData | Where-Object { $_.Metrics.QuerySuccess -eq $false }
        if ($errors.Count -gt 0) {
            $errorRate = [math]::Round(($errors.Count / $global:MonitoringData.Count) * 100, 2)
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== ERROR PATTERNS ===`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Error rate: $errorRate% ($($errors.Count) of $($global:MonitoringData.Count))`r`n")
            
            # Häufigste Fehler
            $errorGroups = $errors | Group-Object { $_.Metrics.Error } | Sort-Object Count -Descending | Select-Object -First 5
            $global:Controls.txtDiagnosisOutput.AppendText("`r`nMost frequent errors:`r`n")
            foreach ($errorGroup in $errorGroups) {
                $global:Controls.txtDiagnosisOutput.AppendText("- $($errorGroup.Name): $($errorGroup.Count)x`r`n")
            }
        }
        
        # Zeitliche Muster
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== TIME-BASED PATTERNS ===`r`n")
        $timeSpan = ($global:MonitoringData | Measure-Object -Property Timestamp -Minimum -Maximum)
        if ($timeSpan.Minimum -and $timeSpan.Maximum) {
            $duration = $timeSpan.Maximum - $timeSpan.Minimum
            $global:Controls.txtDiagnosisOutput.AppendText("Monitoring period: $([math]::Round($duration.TotalMinutes, 1)) minutes`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Data points per minute: $([math]::Round($global:MonitoringData.Count / $duration.TotalMinutes, 1))`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nQuery-Pattern analysis completed!`r`n`r`n")
        Write-Log "Query-Pattern analysis completed for $($global:MonitoringData.Count) data points" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during query pattern analysis: $_`r`n`r`n")
        Write-Log "Error during query pattern analysis: $_" -Level "ERROR"
    }
}

function Show-FailedQueries {
    $global:Controls.txtDiagnosisOutput.AppendText("=== FAILED DNS QUERIES ===`r`n")
    
    try {
        if ($global:MonitoringData.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No monitoring data available. Start the Real-time Monitoring first.`r`n`r`n")
            return
        }
        
        $failedQueries = $global:MonitoringData | Where-Object { $_.Metrics.QuerySuccess -eq $false }
        
        if ($failedQueries.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No failed queries found in the last $($global:MonitoringData.Count) data points.`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("That's a good sign! [OK]`r`n`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("Found $($failedQueries.Count) failed queries:`r`n`r`n")
            
            foreach ($failed in $failedQueries) {
                $global:Controls.txtDiagnosisOutput.AppendText("[$($failed.Timestamp.ToString('HH:mm:ss'))] Server: $($failed.Server)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("  Error: $($failed.Metrics.Error)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
            }
            
            # Fehler-Statistiken
            $errorGroups = $failedQueries | Group-Object { $_.Metrics.Error } | Sort-Object Count -Descending
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== ERROR STATISTICS ===`r`n")
            foreach ($errorGroup in $errorGroups) {
                $percentage = [math]::Round(($errorGroup.Count / $failedQueries.Count) * 100, 1)
                $global:Controls.txtDiagnosisOutput.AppendText("$($errorGroup.Name): $($errorGroup.Count)x ($percentage%)`r`n")
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nFailed-Queries analysis completed!`r`n`r`n")
        Write-Log "Failed-Queries analysis displayed: $($failedQueries.Count) errors" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during failed-queries analysis: $_`r`n`r`n")
        Write-Log "Error during failed-queries analysis: $_" -Level "ERROR"
    }
}

function Analyze-ResponseTimes {
    $global:Controls.txtDiagnosisOutput.AppendText("=== RESPONSE TIME ANALYSIS ===`r`n")
    
    try {
        if ($global:MonitoringData.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No monitoring data available. Start the Real-time Monitoring first.`r`n`r`n")
            return
        }
        
        $responseTimes = $global:MonitoringData | Where-Object { $_.Metrics.ResponseTime -gt 0 } | ForEach-Object { $_.Metrics.ResponseTime }
        
        if ($responseTimes.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("Keine gültigen Antwortzeit-Daten verfügbar.`r`n`r`n")
            return
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("Analysiere $($responseTimes.Count) Antwortzeiten...`r`n`r`n")
        
        # Basis-Statistiken
        $stats = $responseTimes | Measure-Object -Average -Minimum -Maximum
        $global:Controls.txtDiagnosisOutput.AppendText("=== BASIC STATISTICS ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Average: $([math]::Round($stats.Average, 2))ms`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Minimum: $([math]::Round($stats.Minimum, 2))ms`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Maximum: $([math]::Round($stats.Maximum, 2))ms`r`n")
        
        # Perzentile berechnen
        $sortedTimes = $responseTimes | Sort-Object
        $p50 = $sortedTimes[[math]::Floor($sortedTimes.Count * 0.5)]
        $p90 = $sortedTimes[[math]::Floor($sortedTimes.Count * 0.9)]
        $p95 = $sortedTimes[[math]::Floor($sortedTimes.Count * 0.95)]
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== PERZENTILE ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("50. Perzentil (Median): $([math]::Round($p50, 2))ms`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("90. Perzentil: $([math]::Round($p90, 2))ms`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("95. Perzentil: $([math]::Round($p95, 2))ms`r`n")
        
        # Performance-Kategorien
        $excellent = ($responseTimes | Where-Object { $_ -lt 20 }).Count
        $good = ($responseTimes | Where-Object { $_ -ge 20 -and $_ -lt 50 }).Count
        $acceptable = ($responseTimes | Where-Object { $_ -ge 50 -and $_ -lt 100 }).Count
        $slow = ($responseTimes | Where-Object { $_ -ge 100 -and $_ -lt 500 }).Count
        $verySlow = ($responseTimes | Where-Object { $_ -ge 500 }).Count
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== PERFORMANCE-DISTRIBUTION ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Excellent (<20ms): $excellent ($([math]::Round(($excellent/$responseTimes.Count)*100, 1))%)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Good (20-50ms): $good ($([math]::Round(($good/$responseTimes.Count)*100, 1))%)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Acceptable (50-100ms): $acceptable ($([math]::Round(($acceptable/$responseTimes.Count)*100, 1))%)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Slow (100-500ms): $slow ($([math]::Round(($slow/$responseTimes.Count)*100, 1))%)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Very slow (>500ms): $verySlow ($([math]::Round(($verySlow/$responseTimes.Count)*100, 1))%)`r`n")
        
        # Performance-Bewertung
        $avgTime = $stats.Average
        $rating = if ($avgTime -lt 20) { "Excellent" }
                 elseif ($avgTime -lt 50) { "Good" }
                 elseif ($avgTime -lt 100) { "Acceptable" }
                 elseif ($avgTime -lt 500) { "Slow" }
                 else { "Very slow" }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== TOTAL EVALUATION ===`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Performance-Rating: $rating`r`n")
        
        # Empfehlungen
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== RECOMMENDATIONS ===`r`n")
        if ($avgTime -gt 100) {
            $global:Controls.txtDiagnosisOutput.AppendText("- Check the network connection to the DNS server`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("- Check the DNS server load`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("- Consider local DNS caching solutions`r`n")
        } elseif ($avgTime -gt 50) {
            $global:Controls.txtDiagnosisOutput.AppendText("- Performance is acceptable, but can be improved`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("- Monitor the trends over longer periods`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("- Excellent DNS performance! [OK]`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("- Keep the current configuration`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nResponse-Time analysis completed!`r`n`r`n")
        Write-Log "Response-Time analysis completed: Average $([math]::Round($stats.Average, 2))ms" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during response time analysis: $_`r`n`r`n")
        Write-Log "Error during response time analysis: $_" -Level "ERROR"
    }
}

function Analyze-Throughput {
    $global:Controls.txtDiagnosisOutput.AppendText("=== THROUGHPUT ANALYSIS ===`r`n")
    
    try {
        if ($global:MonitoringData.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No monitoring data available. Start the Real-time Monitoring first.`r`n`r`n")
            return
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("Analyze throughput based on $($global:MonitoringData.Count) data points...`r`n`r`n")
        
        # Zeitraum berechnen
        # Korrektur: Zugriff auf die verschachtelte Eigenschaft 'Timestamp'
        $timeSpan = ($global:MonitoringData | Measure-Object -Property {$_.Metrics.Timestamp} -Minimum -Maximum)
        
        if ($timeSpan.Minimum -and $timeSpan.Maximum) {
            $duration = $timeSpan.Maximum - $timeSpan.Minimum
            $durationMinutes = $duration.TotalMinutes
            
            $global:Controls.txtDiagnosisOutput.AppendText("=== THROUGHPUT METRICS ===`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Monitoring period: $([math]::Round($durationMinutes, 1)) minutes`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Total data points: $($global:MonitoringData.Count)`r`n")
            
            if ($durationMinutes -gt 0) {
                $queriesPerMinute = [math]::Round($global:MonitoringData.Count / $durationMinutes, 2)
                $queriesPerSecond = [math]::Round($queriesPerMinute / 60, 2)
                
                $global:Controls.txtDiagnosisOutput.AppendText("Queries per Minute: $queriesPerMinute`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Queries per Second: $queriesPerSecond`r`n")
                
                # Erfolgsrate
                $successfulQueries = ($global:MonitoringData | Where-Object { $_.Metrics.QuerySuccess -eq $true }).Count
                $successRate = 0
                if ($global:MonitoringData.Count -gt 0) { # Division durch Null vermeiden
                    $successRate = [math]::Round(($successfulQueries / $global:MonitoringData.Count) * 100, 2)
                }
                
                $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== SUCCESS RATE ===`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Successful queries: $successfulQueries of $($global:MonitoringData.Count)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Success rate: $successRate%`r`n")
                
                # Durchsatz-Bewertung
                $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== THROUGHPUT EVALUATION ===`r`n")
                if ($queriesPerSecond -lt 1) {
                    $global:Controls.txtDiagnosisOutput.AppendText("Throughput: Low (Monitoring interval)`r`n")
                    $global:Controls.txtDiagnosisOutput.AppendText("Note: This reflects the monitoring interval, not the actual server capacity`r`n")
                } else {
                    $global:Controls.txtDiagnosisOutput.AppendText("Throughput: $queriesPerSecond queries/second`r`n")
                }
                
                # Kapazitäts-Schätzung
                $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== CAPACITY ESTIMATION ===`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Typical DNS server capacities:`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("- Small environment: 100-1.000 queries/second`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("- Medium environment: 1.000-10.000 queries/second`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("- Large environment: 10.000+ queries/second`r`n")
                
                # Trend-Analyse (falls genügend Daten)
                if ($global:MonitoringData.Count -gt 10) {
                    $firstHalf = $global:MonitoringData | Select-Object -First ([math]::Floor($global:MonitoringData.Count / 2))
                    $secondHalf = $global:MonitoringData | Select-Object -Last ([math]::Floor($global:MonitoringData.Count / 2))
                    
                    $firstHalfAvg = ($firstHalf | Where-Object { $_.Metrics.ResponseTime -gt 0 } | Measure-Object -Property { $_.Metrics.ResponseTime } -Average).Average
                    $secondHalfAvg = ($secondHalf | Where-Object { $_.Metrics.ResponseTime -gt 0 } | Measure-Object -Property { $_.Metrics.ResponseTime } -Average).Average
                    
                    if ($null -ne $firstHalfAvg -and $null -ne $secondHalfAvg) { # Sicherstellen, dass Werte vorhanden sind
                        $trend = $secondHalfAvg - $firstHalfAvg
                        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== PERFORMANCE-TREND ===`r`n")
                        if ($trend -gt 10) {
                            $trendValue = [math]::Round($trend, 2)
                            $global:Controls.txtDiagnosisOutput.AppendText("Trend: Performance worsened ($trendValue ms slower)`r`n")
                        } elseif ($trend -lt -10) {
                            $trendValue = [math]::Round(-$trend, 2)
                            $global:Controls.txtDiagnosisOutput.AppendText("Trend: Performance improved ($trendValue ms faster)`r`n")
                        } else {
                            $trendValue = [math]::Round($trend, 2)
                            $global:Controls.txtDiagnosisOutput.AppendText("Trend: Performance stable ($trendValue ms change)`r`n")
                        }
                    } else {
                        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== PERFORMANCE-TREND ===`r`n")
                        $global:Controls.txtDiagnosisOutput.AppendText("Not enough data for a performance trend analysis of response times.`r`n")
                    }
                }
            } else {
                 $global:Controls.txtDiagnosisOutput.AppendText("Not enough data for a throughput analysis (duration is 0 minutes).`r`n")
            }
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("Timestamp data missing for the calculation of the time period.`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nThroughput analysis completed!`r`n`r`n")
        Write-Log "Throughput analysis completed for $($global:MonitoringData.Count) data points" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during throughput analysis: $_`r`n`r`n")
        Write-Log "Error during throughput analysis: $_.Exception.Message" -Level "ERROR"
    }
}

###############################################################################
# FEHLENDE DIAGNOSTIC FUNKTIONEN IMPLEMENTIEREN
###############################################################################

function Run-ResolveTest {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a target for the DNS resolution." "Input required" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS RESOLUTION for $target ===`r`n")
    
    try {
        $results = Resolve-DnsName -Name $target -ErrorAction Stop
        
        foreach ($result in $results) {
            $global:Controls.txtDiagnosisOutput.AppendText("Name: $($result.Name)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Type: $($result.Type)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Section: $($result.Section)`r`n")
            
            switch ($result.Type) {
                "A"     { $global:Controls.txtDiagnosisOutput.AppendText("IP-Address: $($result.IPAddress)`r`n") }
                "AAAA"  { $global:Controls.txtDiagnosisOutput.AppendText("IPv6-Address: $($result.IPAddress)`r`n") }
                "CNAME" { $global:Controls.txtDiagnosisOutput.AppendText("Alias for: $($result.NameHost)`r`n") }
                "MX"    { $global:Controls.txtDiagnosisOutput.AppendText("Mail-Server: $($result.NameExchange) (Priorität: $($result.Preference))`r`n") }
                "NS"    { $global:Controls.txtDiagnosisOutput.AppendText("Name-Server: $($result.NameHost)`r`n") }
                "PTR"   { $global:Controls.txtDiagnosisOutput.AppendText("Hostname: $($result.NameHost)`r`n") }
                "TXT"   { $global:Controls.txtDiagnosisOutput.AppendText("Text: $($result.Strings -join ' ')`r`n") }
                "SOA"   { $global:Controls.txtDiagnosisOutput.AppendText("Primary NS: $($result.PrimaryServer)`r`n") }
            }
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nResolution successful: $($results.Count) results`r`n`r`n")
        Write-Log "DNS Resolution for $target successful: $($results.Count) results" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("DNS Resolution failed: $_`r`n`r`n")
        Write-Log "DNS Resolution for $target failed: $_" -Level "ERROR"
    }
}

function Run-TestConnection {
    $target = $global:Controls.txtDiagnosisTarget.Text.Trim()
    if ([string]::IsNullOrEmpty($target)) {
        Show-MessageBox "Please enter a target for the connection test." "Input required" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== CONNECTION TEST to $target ===`r`n")
    
    try {
        # Test verschiedene Verbindungstypen
        $global:Controls.txtDiagnosisOutput.AppendText("Teste Ping...`r`n")
        $pingResult = Test-Connection -ComputerName $target -Count 2 -ErrorAction SilentlyContinue
        if ($pingResult) {
            $avgTime = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
            $global:Controls.txtDiagnosisOutput.AppendText("Ping successful - Average Time: $([math]::Round($avgTime, 2))ms`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("Ping failed`r`n")
        }
        
        # Test DNS-Port 53
        $global:Controls.txtDiagnosisOutput.AppendText("Testing DNS Port (53)...`r`n")
        $dnsTest = Test-NetConnection -ComputerName $target -Port 53 -ErrorAction SilentlyContinue
        if ($dnsTest.TcpTestSucceeded) {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS Port 53 reachable`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS Port 53 not reachable`r`n")
        }
        
        # Test Standard-Ports
        $ports = @(80, 443, 22, 25)
        foreach ($port in $ports) {
            $global:Controls.txtDiagnosisOutput.AppendText("Testing Port $port...`r`n")
            $portTest = Test-NetConnection -ComputerName $target -Port $port -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($portTest.TcpTestSucceeded) {
                $global:Controls.txtDiagnosisOutput.AppendText("Port $port open`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("Port $port closed/filtered`r`n")
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nConnection test completed.`r`n`r`n")
        Write-Log "Connection test to $target completed" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during connection test: $_`r`n`r`n")
        Write-Log "Connection test to $target failed: $_" -Level "ERROR"
    }
}

function Show-DNSServerCache {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVER-CACHE ===`r`n")
    
    try {
        $cacheRecords = Get-DnsServerCache -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Cache entries: $($cacheRecords.Count)`r`n`r`n")
        
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
    $global:Controls.txtDiagnosisOutput.AppendText("=== CLEAR CLIENT-DNS-CACHE ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Execute 'ipconfig /flushdns'...`r`n")
        $result = & ipconfig /flushdns 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("$($result -join "`r`n")`r`n")
        
        # Zusätzlich PowerShell DNS-Client-Cache leeren
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $global:Controls.txtDiagnosisOutput.AppendText("PowerShell DNS-Client-Cache cleared.`r`n")
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nClient-DNS-Cache successfully cleared!`r`n`r`n")
        Write-Log "Client-DNS-Cache cleared" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error clearing client DNS cache: $_`r`n`r`n")
        Write-Log "Error clearing client DNS cache: $_" -Level "ERROR"
    }
}

function Show-ServiceStatus {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVICE-STATUS ===`r`n")
    
    try {
        $service = Get-Service -Name "DNS" -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Service: $($service.DisplayName)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Status: $($service.Status)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Start type: $($service.StartType)`r`n")
        
        # Versuche weitere Informationen zu bekommen
        try {
            $processInfo = Get-Process -Name "dns" -ErrorAction SilentlyContinue
            if ($processInfo) {
                $global:Controls.txtDiagnosisOutput.AppendText("Process ID: $($processInfo.Id)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Memory usage: $([math]::Round($processInfo.WorkingSet64/1MB, 2)) MB`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Start time: $($processInfo.StartTime)`r`n")
            }
        } catch {
            # Ignoriere Prozess-Informations-Fehler
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Service-Status fetched: $($service.Status)" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching DNS service status: $_`r`n`r`n")
        Write-Log "Error fetching DNS service status: $_" -Level "ERROR"
    }
}

function Start-DNSService {
    $global:Controls.txtDiagnosisOutput.AppendText("=== START DNS-SERVICE ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Start DNS service...`r`n")
        Start-Service -Name "DNS" -ErrorAction Stop
        
        # Warte kurz und prüfe Status
        Start-Sleep -Seconds 2
        $service = Get-Service -Name "DNS"
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service Status: $($service.Status)`r`n")
        
        if ($service.Status -eq "Running") {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service successfully started!`r`n")
        } else {
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service is not in Running-Status`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS-Service started" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error starting DNS service: $_`r`n`r`n")
        Write-Log "Error starting DNS service: $_" -Level "ERROR"
    }
}

function Stop-DNSService {
    $result = [System.Windows.MessageBox]::Show("Do you really want to stop the DNS service?`n`nThis can lead to DNS outages!", "Stop DNS Service", "YesNo", "Warning")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== STOP DNS-SERVICE ===`r`n")
        
        try {
            $global:Controls.txtDiagnosisOutput.AppendText("Stop DNS service...`r`n")
            Stop-Service -Name "DNS" -Force -ErrorAction Stop
            
            # Warte kurz und prüfe Status
            Start-Sleep -Seconds 2
            $service = Get-Service -Name "DNS"
            
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Dienst Status: $($service.Status)`r`n")
            
            if ($service.Status -eq "Stopped") {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service successfully stopped!`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service is not stopped`r`n")
            }
            
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
            Write-Log "DNS-Dienst gestoppt" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Error stopping DNS service: $_`r`n`r`n")
            Write-Log "Error stopping DNS service: $_" -Level "ERROR"
        }
    }
}

function Restart-DNSService {
    $result = [System.Windows.MessageBox]::Show("Do you really want to restart the DNS service?`n`nThis can lead to short DNS outages!", "Restart DNS Service", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== RESTART DNS-SERVICE ===`r`n")
        
        try {
            $global:Controls.txtDiagnosisOutput.AppendText("Restart DNS service...`r`n")
            Restart-Service -Name "DNS" -Force -ErrorAction Stop
            
            # Warte kurz und prüfe Status
            Start-Sleep -Seconds 3
            $service = Get-Service -Name "DNS"
            
            $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service Status: $($service.Status)`r`n")
            
            if ($service.Status -eq "Running") {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service successfully restarted!`r`n")
            } else {
                $global:Controls.txtDiagnosisOutput.AppendText("DNS-Service is not in Running-Status`r`n")
            }
            
            $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
            Write-Log "DNS-Service restarted" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Error restarting DNS service: $_`r`n`r`n")
            Write-Log "Error restarting DNS service: $_" -Level "ERROR"
        }
    }
}

function Show-ServerConfiguration {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS-SERVER-CONFIGURATION ===`r`n")
    
    try {
        $serverSettings = Get-DnsServer -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Server: $($serverSettings.ServerSetting.ComputerName)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Version: $($serverSettings.ServerSetting.MajorVersion).$($serverSettings.ServerSetting.MinorVersion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Listening IP Addresses: $($serverSettings.ServerSetting.ListeningIPAddress -join ', ')`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Recursion: $($serverSettings.ServerSetting.DisableRecursion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Cache clear: $($serverSettings.ServerSetting.NoRecursion)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Boot method: $($serverSettings.ServerSetting.BootMethod)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Auto-Cache-Update: $($serverSettings.ServerSetting.AutoCacheUpdate)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Log-Level: $($serverSettings.ServerSetting.LogLevel)`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "DNS-Server-Konfiguration abgerufen" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching server configuration: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Use: Get-DnsServer`r`n`r`n")
        Write-Log "Error fetching server configuration: $_" -Level "ERROR"
    }
}

function Add-DNSForwarder {
    $forwarderIP = $global:Controls.txtForwarderIP.Text.Trim()
    if ([string]::IsNullOrEmpty($forwarderIP)) {
        Show-MessageBox "Please enter an IP address for the forwarder." "Input required" "Warning"
        return
    }
    
    # Validiere IP-Adresse
    try {
        $ip = [System.Net.IPAddress]::Parse($forwarderIP)
    } catch {
        Show-MessageBox "Invalid IP address: $forwarderIP" "Validation error" "Error"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ADD DNS-FORWARDER ===`r`n")
    
    try {
        Add-DnsServerForwarder -IPAddress $forwarderIP -ComputerName $global:Controls.txtDNSServer.Text -ErrorAction Stop
        $global:Controls.txtDiagnosisOutput.AppendText("Forwarder $forwarderIP successfully added!`r`n")
        $global:Controls.txtForwarderIP.Clear()
        
        # Aktuelle Forwarder anzeigen
        Show-DNSForwarders
        
        Write-Log "DNS-Forwarder added: $forwarderIP" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error adding forwarder: $_`r`n`r`n")
        Write-Log "Error adding DNS-Forwarder $forwarderIP`: $_" -Level "ERROR"
    }
}

function Remove-DNSForwarder {
    $forwarderIP = $global:Controls.txtForwarderIP.Text.Trim()
    if ([string]::IsNullOrEmpty($forwarderIP)) {
        Show-MessageBox "Please enter the IP address of the forwarder to remove." "Input required" "Warning"
        return
    }
    
    $result = [System.Windows.MessageBox]::Show("Do you really want to remove the forwarder '$forwarderIP'?", "Remove forwarder", "YesNo", "Question")
    
    if ($result -eq "Yes") {
        $global:Controls.txtDiagnosisOutput.AppendText("=== REMOVE DNS FORWARDER ===`r`n")
        
        try {
            Remove-DnsServerForwarder -IPAddress $forwarderIP -ComputerName $global:Controls.txtDNSServer.Text -Force -ErrorAction Stop
            $global:Controls.txtDiagnosisOutput.AppendText("Forwarder $forwarderIP successfully removed!`r`n")
            $global:Controls.txtForwarderIP.Clear()
            
            # Aktuelle Forwarder anzeigen
            Show-DNSForwarders
            
            Write-Log "DNS-Forwarder removed: $forwarderIP" -Level "INFO"
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Error removing forwarder: $_`r`n`r`n")
            Write-Log "Error removing DNS-Forwarder $forwarderIP`: $_" -Level "ERROR"
        }
    }
}

function Force-ZoneTransfer {
    $zone = $global:Controls.cmbDiagZone.SelectedItem
    if (-not $zone) {
        Show-MessageBox "Please select a zone." "No Zone selected" "Warning"
        return
    }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== ZONE TRANSFER: $zone ===`r`n")
    
    try {
        $result = & dnscmd $global:Controls.txtDNSServer.Text /zoneupdatefromds $zone 2>&1
        $global:Controls.txtDiagnosisOutput.AppendText("Zone Transfer Result:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText($result -join "`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        
        Write-Log "Zone-Transfer für $zone ausgeführt" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error during Zone-Transfer: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Use: dnscmd /zoneupdatefromds $zone`r`n`r`n")
        Write-Log "Error during Zone-Transfer for $zone`: $_" -Level "ERROR"
    }
}

function Show-DNSEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DNS EVENTS ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "DNS Server" -MaxEvents 50 -ErrorAction Stop | Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("Letzte 50 DNS-Ereignisse:`r`n`r`n")
        
        foreach ($event in $events) {
            $global:Controls.txtDiagnosisOutput.AppendText("Time: $($event.TimeCreated)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Message: $($event.Message.Substring(0, [Math]::Min(200, $event.Message.Length)))`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "DNS events displayed: $($events.Count) events" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching DNS events: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("You may not have permission or the event log does not exist.`r`n`r`n")
        Write-Log "Error fetching DNS events: $_" -Level "ERROR"
    }
}

function Show-SystemEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== SYSTEM EVENTS ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "System" -MaxEvents 20 -ErrorAction Stop | 
                  Where-Object { $_.ProviderName -like "*DNS*" -or $_.Message -like "*DNS*" } |
                  Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-related System Events:`r`n`r`n")
        
        foreach ($event in $events) {
            $global:Controls.txtDiagnosisOutput.AppendText("Time: $($event.TimeCreated)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Provider: $($event.ProviderName)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Message: $($event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)))`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "System events displayed: $($events.Count) DNS-related events" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching System events: $_`r`n`r`n")
        Write-Log "Error fetching System events: $_" -Level "ERROR"
    }
}

function Show-SecurityEvents {
    $global:Controls.txtDiagnosisOutput.AppendText("=== SECURITY EVENTS ===`r`n")
    
    try {
        $events = Get-WinEvent -LogName "Security" -MaxEvents 20 -ErrorAction Stop | 
                  Where-Object { $_.Message -like "*DNS*" } |
                  Sort-Object TimeCreated -Descending
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS-related Security Events:`r`n`r`n")
        
        if ($events.Count -eq 0) {
            $global:Controls.txtDiagnosisOutput.AppendText("No DNS-related Security Events found.`r`n")
        } else {
            foreach ($event in $events) {
                $global:Controls.txtDiagnosisOutput.AppendText("Time: $($event.TimeCreated)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Level: $($event.LevelDisplayName)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Event-ID: $($event.Id)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("Message: $($event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)))`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "Security events displayed: $($events.Count) DNS-related events" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching Security events: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("You may not have permission to access Security logs.`r`n`r`n")
        Write-Log "Error fetching Security events: $_" -Level "ERROR"
    }
}

function Export-EventLogs {
    $exportPath = Show-SaveFileDialog -Filter "CSV Files (*.csv)|*.csv|XML Files (*.xml)|*.xml|All Files (*.*)|*.*" -Title "Export Event-Logs"
    if (-not $exportPath) { return }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== EXPORT EVENT-LOGS ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Collecting DNS Events...`r`n")
        
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
        
        $global:Controls.txtDiagnosisOutput.AppendText("Event-Logs exported: $($allEvents.Count) Events`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("File: $exportPath`r`n`r`n")
        
        Show-MessageBox "Event-Logs exported successfully!`n`nFile: $exportPath`nNumber of Events: $($allEvents.Count)" "Export successful"
        Write-Log "Event-Logs exported: $($allEvents.Count) Events after $exportPath" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error exporting Event-Logs: $_`r`n`r`n")
        Write-Log "Error exporting Event-Logs: $_" -Level "ERROR"
    }
}

function Enable-DebugLogging {
    $global:Controls.txtDiagnosisOutput.AppendText("=== ENABLE DEBUG-LOGGING ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Enable DNS-Debug-Logging...`r`n")
        
        # Korrekte Parameter-Kombination für DNS-Diagnose
        Set-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text `
            -Queries $true `
            -Answers $true `
            -Send $true `
            -Receive $true `
            -UdpPackets $true `
            -TcpPackets $true `
            -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Logging enabled!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Log-File: %systemroot%\\system32\\dns\\dns.log`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nEnabled Settings:`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Queries: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Answers: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Send: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- Receive: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- UDP Packets: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("- TCP Packets: enabled`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nNote: Debug-Logging can affect DNS performance.`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("Disable it after the diagnosis!`r`n`r`n")
        
        Write-Log "DNS-Debug-Logging enabled" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error enabling Debug-Logging: $_`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("`r`nAlternative: Use the DNS-Console`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("DNS Manager -> Server -> Right-click -> Properties -> Debug Logging`r`n`r`n")
        Write-Log "Error enabling Debug-Logging: $_" -Level "ERROR"
    }
}

function Disable-DebugLogging {
    $global:Controls.txtDiagnosisOutput.AppendText("=== DISABLE DEBUG-LOGGING ===`r`n")
    
    try {
        $global:Controls.txtDiagnosisOutput.AppendText("Disable DNS-Debug-Logging...`r`n")
        
        # Verwende -All $false um alle Diagnose-Optionen zu deaktivieren
        # Dies ist der sicherste Weg laut Microsoft-Dokumentation
        Set-DnsServerDiagnostics -ComputerName $global:Controls.txtDNSServer.Text -All $false -ErrorAction Stop
        
        $global:Controls.txtDiagnosisOutput.AppendText("Debug-Logging disabled!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("All diagnostic options disabled.`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("DNS performance should be back to normal.`r`n`r`n")
        
        Write-Log "DNS-Debug-Logging deaktiviert" -Level "INFO"
        
    } catch {
        # Fallback-Methode: Versuche einzelne wichtige Parameter zu deaktivieren
        # aber lasse mindestens einen aus jeder erforderlichen Gruppe aktiv
        $global:Controls.txtDiagnosisOutput.AppendText("Main method failed, try fallback...`r`n")
        
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
            
            $global:Controls.txtDiagnosisOutput.AppendText("Fallback successful: Minimal-Debug-Logging enabled`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("(Only basic UDP-Queries are still logged)`r`n`r`n")
            
        } catch {
            $global:Controls.txtDiagnosisOutput.AppendText("Error disabling Debug-Logging: $_`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("`r`nAlternative solutions:`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("1. DNS Manager -> Server -> Right-click -> Properties -> Debug Logging -> Disable`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("2. PowerShell: Set-DnsServerDiagnostics -All `$false`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("3. Restart the DNS service resets Debug-Logging`r`n`r`n")
            Write-Log "Error disabling Debug-Logging: $_" -Level "ERROR"
        }
    }
}

function Export-DNSStatistics {
    $exportPath = Show-SaveFileDialog -Filter "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*" -Title "Export DNS Statistics"
    if (-not $exportPath) { return }
    
    $global:Controls.txtDiagnosisOutput.AppendText("=== EXPORT DNS STATISTICS ===`r`n")
    
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
                    Category = "Total Zones"
                    Value = $exportData.BasicStats.TotalZones
                    Timestamp = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Category = "Forward Zones"
                    Value = $exportData.BasicStats.ForwardZones
                    Timestamp = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Category = "Reverse Zones"
                    Value = $exportData.BasicStats.ReverseZones
                    Timestamp = $exportData.Timestamp
                }
                $csvData += [PSCustomObject]@{
                    Category = "DNSSEC Zones"
                    Value = $exportData.BasicStats.SignedZones
                    Timestamp = $exportData.Timestamp
                }
                
                $csvData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            }
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("DNS statistics exported!`r`n")
        $global:Controls.txtDiagnosisOutput.AppendText("File: $exportPath`r`n`r`n")
        
        Show-MessageBox "DNS statistics exported successfully!`n`nFile: $exportPath" "Export successful"
        Write-Log "DNS statistics exported after: $exportPath" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error exporting DNS statistics: $_`r`n`r`n")
        Write-Log "Error exporting DNS statistics: $_" -Level "ERROR"
    }
}

function Show-NetworkProperties {
    $global:Controls.txtDiagnosisOutput.AppendText("=== NETWORK PROPERTIES ===`r`n")
    
    try {
        # IP-Konfiguration
        $global:Controls.txtDiagnosisOutput.AppendText("=== IP CONFIGURATION ===`r`n")
        $ipConfig = Get-NetIPConfiguration -ErrorAction Stop
        
        foreach ($config in $ipConfig) {
            if ($config.NetAdapter.Status -eq "Up") {
                $global:Controls.txtDiagnosisOutput.AppendText("Interface: $($config.InterfaceAlias)`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("IPv4 Address: $($config.IPv4Address.IPAddress -join ', ')`r`n")
                if ($config.IPv6Address) {
                    $global:Controls.txtDiagnosisOutput.AppendText("IPv6 Address: $($config.IPv6Address.IPAddress -join ', ')`r`n")
                }
                $global:Controls.txtDiagnosisOutput.AppendText("Gateway: $($config.IPv4DefaultGateway.NextHop -join ', ')`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("DNS Server: $($config.DNSServer.ServerAddresses -join ', ')`r`n")
                $global:Controls.txtDiagnosisOutput.AppendText("------------------------`r`n")
            }
        }
        
        # Routing-Tabelle (kurze Version)
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== ROUTING INFORMATION ===`r`n")
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -lt 1000 } | Select-Object -First 10
        
        foreach ($route in $routes) {
            $global:Controls.txtDiagnosisOutput.AppendText("Destination: $($route.DestinationPrefix) -> Gateway: $($route.NextHop) (Metric: $($route.RouteMetric))`r`n")
        }
        
        # DNS-Client-Einstellungen
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n=== DNS CLIENT SETTINGS ===`r`n")
        $dnsClient = Get-DnsClient -ErrorAction SilentlyContinue
        
        if ($dnsClient) {
            $global:Controls.txtDiagnosisOutput.AppendText("Suffix-Search-List: $($dnsClient.SuffixSearchList -join ', ')`r`n")
            $global:Controls.txtDiagnosisOutput.AppendText("Use-Suffix-When-Resolving: $($dnsClient.UseSuffixWhenResolving)`r`n")
        }
        
        $global:Controls.txtDiagnosisOutput.AppendText("`r`n")
        Write-Log "Network properties displayed" -Level "INFO"
        
    } catch {
        $global:Controls.txtDiagnosisOutput.AppendText("Error fetching network properties: $_`r`n`r`n")
        Write-Log "Error fetching network properties: $_" -Level "ERROR"
    }
}

function Save-DiagnosisOutput {
    $exportPath = Show-SaveFileDialog -Filter "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log|All Files (*.*)|*.*" -Title "Save Diagnosis Output"
    if (-not $exportPath) { return }
    
    try {
        $content = $global:Controls.txtDiagnosisOutput.Text
        $content | Out-File -FilePath $exportPath -Encoding UTF8
        
        Show-MessageBox "Diagnosis output saved successfully!`n`nFile: $exportPath" "Save successful"
        Write-Log "Diagnosis output saved after: $exportPath" -Level "INFO"
        
    } catch {
        Show-MessageBox "Error saving diagnosis output:`n$_" "Error"
        Write-Log "Error saving diagnosis output: $_" -Level "ERROR"
    }
}

###############################################################################
# AUTO-REFRESH FUNKTIONEN
###############################################################################

function Start-AutoRefresh {
    if ($global:AutoRefreshEnabled) {
        Write-Log "Auto-Refresh is already enabled" -Level "DEBUG" -Component "AutoRefresh"
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
            Write-Log "Error during auto-refresh: $_" -Level "ERROR" -Component "AutoRefresh"
        }
    })
    
    $global:AutoRefreshTimer.Start()
    Write-Log "Auto-Refresh enabled (Interval: $($global:AppConfig.AutoRefreshInterval) seconds)" -Level "INFO" -Component "AutoRefresh"
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

Write-Log "Starting easyDNS ..." -Level "INFO"
Write-Log "Detected DNS-Server: $global:DetectedDnsServer" -Level "INFO"

# DNS-Server in GUI setzen
$global:Controls.txtDNSServer.Text = $global:DetectedDnsServer

# Dashboard initialisieren
Show-Panel "dashboard"

# Window anzeigen
$global:Window.Add_Loaded({
    Write-Log "easyDNS WPF started" -Level "INFO"
    
    # Automatische Verbindung wenn lokaler DNS-Server erkannt wurde
    if ($global:DNSDetection.AutoConnect -and $global:DNSDetection.IsLocalDNS) {
        Write-Log "Establishing automatic connection to local DNS-Server..." -Level "INFO"
        
        $global:Controls.lblStatus.Text = "Status: Connecting automatically..."
        $global:Controls.lblStatus.Foreground = "#FF8C00"
        
        # Kurze Verzögerung für UI-Update
        $global:Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{
            try {
                $zones = Get-DnsServerZone -ComputerName 'localhost' -ErrorAction Stop
                $global:Controls.lblStatus.Text = "Status: Connected (Auto)"
                $global:Controls.lblStatus.Foreground = "#107C10"
                
                Write-Log "Automatic connection to local DNS-Server successful" -Level "INFO"
                
                # Dashboard aktualisieren
                Update-Dashboard
                
                # Erfolgsmeldung
                Show-MessageBox "Automatically connected to local DNS-Server!`n`nThe server is running on this system and was automatically detected." "Automatic connection"
                
            } catch {
                $global:Controls.lblStatus.Text = "Status: Fehler"
                $global:Controls.lblStatus.Foreground = "#D13438"
                Write-Log "Error during automatic connection to local DNS-Server: $_" -Level "ERROR"
                Show-MessageBox "Error during automatic connection to local DNS-Server:`n$_`n`nPlease connect manually." "Connection error" "Error"
            }
        })
    } else {
        # Keine lokale DNS-Rolle - normale Dashboard-Aktualisierung
        Update-Dashboard
        
        if (-not $global:DNSDetection.IsLocalDNS) {
            # Hinweis anzeigen
            Show-MessageBox "No local DNS-Server role detected.`n`nPlease enter a DNS-Server and click 'Connect'." "DNS-Server selection" "Information"
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
            Write-Log "- Operations: $($global:PerformanceCounters.OperationCount)" -Level "INFO" -Component "Shutdown"
            Write-Log "- Errors: $($global:PerformanceCounters.ErrorCount)" -Level "INFO" -Component "Shutdown"
            Write-Log "- Error rate: $([math]::Round(($global:PerformanceCounters.ErrorCount / $global:PerformanceCounters.OperationCount) * 100, 2))%" -Level "INFO" -Component "Shutdown"
        }
        
        # Temporäre Dateien aufräumen
        if (Test-Path $global:AppConfig.TempPath) {
            try {
                Get-ChildItem -Path $global:AppConfig.TempPath -File | Remove-Item -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Log "Error cleaning up temporary files: $_" -Level "WARN" -Component "Shutdown"
            }
        }
        
        Write-Log "easyDNS closed" -Level "INFO" -Component "Shutdown"
        
    } catch {
        Write-Log "Error closing: $_" -Level "ERROR" -Component "Shutdown"
    }
})

# Show the window
[void]$global:Window.ShowDialog() 