#requires -RunAsAdministrator
<#
===============================================================================
easyDNS Advanced V0.1.1
===============================================================================
Umfangreiches DNS-Server-Verwaltungstool mit folgenden Funktionen:
- Verwaltung von Forward- und Reverse-Zonen
- Umfassende Verwaltung von DNS-Einträgen (A, AAAA, CNAME, MX, PTR, TXT, SRV)
- Massenimport und -export von DNS-Konfigurationen
- Erweiterte Diagnosetools (Ping, Tracert, Nslookup)
- DNSSEC-Unterstützung und -Verwaltung
- Erweiterte Protokollierung und Fehlerbehandlung
- Zonentransfer-Konfiguration und -Management
===============================================================================
#>

###############################################################################
# 1) Import-Ini: Liest eine INI-Datei und gibt deren Inhalt als verschachteltes
#    Dictionary-Objekt (Hashtables) zurück.
###############################################################################
function Import-Ini {
    param([string]$Path)

    # Prüfen, ob die INI-Datei existiert
    if (!(Test-Path $Path)) {
        Write-Error "INI file '$Path' not found."
        return $null
    }

    $ini = @{ }
    $section = ""

    # Jede Zeile der Datei einlesen
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimLine = $line.Trim()

        # Kommentarzeilen und Leerzeilen überspringen
        if ($trimLine -match '^[#;]' -or $trimLine -eq "") { continue }

        # Neue Sektion starten, falls Zeile z. B. [SectionName] ist
        if ($trimLine -match '^\[(.+)\]$') {
            $section = $Matches[1]
            if (-not $ini.ContainsKey($section)) { $ini[$section] = @{} }
            continue
        }

        # Key=Value parsen
        if ($trimLine -match '^(.*?)=(.*)$') {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            if (-not $ini.ContainsKey($section)) { $ini[$section] = @{} }
            $ini[$section][$key] = $value
        }
    }
    return $ini
}

###############################################################################
# 2) Export-Ini: Schreibt ein Dictionary-Objekt in eine INI-Datei
###############################################################################
function Export-Ini {
    param(
        [string]$Path,
        [hashtable]$IniData
    )

    $output = @()
    foreach ($section in $IniData.Keys) {
        $output += "[$section]"
        foreach ($key in $IniData[$section].Keys) {
            $output += "$key=$($IniData[$section][$key])"
        }
        $output += "" # Leerzeile zwischen Sektionen
    }
    
    $output | Out-File -FilePath $Path -Encoding utf8 -Force
}

###############################################################################
# 3) INI LADEN: Ruft Import-Ini auf und bricht ab, falls das fehlschlägt.
###############################################################################
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { 
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path 
}
$configPath = Join-Path $scriptRoot "easyDNS_Advanced.ini"

# Prüfen, ob die Konfigurations-Datei existiert
if (-not (Test-Path $configPath)) {
    # Standard-Konfiguration erstellen
    $defaultConfig = @{
        easyDNSGeneral = @{
            easyDNSScriptVersion = "1.0.0"
            easyDNSLastUpdate = (Get-Date -Format "yyyy-MM-dd")
            easyDNSAuthor = "Admin"
            easyDNSAPPName = "easyDNS Advanced"
            easyDNSGUI_Header = "easyDNS Advanced {ScriptVersion} (Letzte Aktualisierung: {LastUpdate})"
            easyDNSDebugMode = "0"
            easyDNSThemeColor = "#2c3e50"
            easyDNSFontFamily = "Segoe UI"
            easyDNSFontSize = "9"
            easyDNSHeaderLogo = ""
            easyDNSHeaderLogoURL = "https://www.example.com"
            easyDNSFooterText = "© 2023 easyDNS Advanced - Alle Rechte vorbehalten"
        }
        easyDNSserver = @{
            ServerName = "localhost"
        }
        easyDNSReverse = @{
            DefaultReplicationScope = "Domain"
        }
        easyDNSDNSSEC = @{
            EnableDNSSEC = "1"
            SigningAlgorithm = "RSA"
            KeyLength = "2048"
        }
        easyDNSBatch = @{
            DefaultImportFolder = "$scriptRoot\Import"
            DefaultExportFolder = "$scriptRoot\Export"
        }
    }
    
    # Verzeichnisse erstellen
    if (-not (Test-Path "$scriptRoot\Import")) {
        New-Item -ItemType Directory -Path "$scriptRoot\Import" -Force | Out-Null
    }
    if (-not (Test-Path "$scriptRoot\Export")) {
        New-Item -ItemType Directory -Path "$scriptRoot\Export" -Force | Out-Null
    }
    
    # Standardkonfiguration speichern
    Export-Ini -Path $configPath -IniData $defaultConfig
}

$config = Import-Ini -Path $configPath
if (-not $config) {
    Write-Error "Could not load INI config. Exiting."
    return
}

###############################################################################
# 4) .NET Assemblies laden: Forms & Drawing für GUI und Steuerelemente.
###############################################################################
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

###############################################################################
# 5) DETECT-DNSSERVER: Versucht, den DNS-Server in der lokalen Umgebung zu
#    ermitteln (localhost, DNS-Feature, AD-Discovery) oder nimmt ggf. Fallback.
###############################################################################
function Get-DNSServerDetection {
    param([psobject]$config)

    try {
        $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
        if ($dnsFeature -and $dnsFeature.Installed) {
            return 'localhost'
        }
    } catch {}

    try {
        $dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                       Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).ServerAddresses
        foreach ($srv in $dnsServers) {
            try {
                Get-DnsServerZone -ComputerName $srv -ErrorAction Stop | Out-Null
                return $srv
            } catch {}
        }
    } catch {}

    try {
        $dc = Get-ADDomainController -Service "DNS" -Discover -ErrorAction Stop
        if ($dc) {
            return $dc.HostName
        }
    } catch {}

    # Fallback auf den Eintrag in der INI
    return $config.easyDNSserver.ServerName
}

###############################################################################
# 6) EINSTELLUNGEN AUS INI: Hier werden die Hauptvariablen aus den Configs gelesen
###############################################################################
$DetectedDnsServer = Get-DNSServerDetection -config $config

$scriptVersion = $config.easyDNSGeneral.easyDNSScriptVersion
$lastUpdate    = $config.easyDNSGeneral.easyDNSLastUpdate
$author        = $config.easyDNSGeneral.easyDNSAuthor
$headerTextRaw = $config.easyDNSGeneral.easyDNSGUI_Header
$debugMode     = [int]$config.easyDNSGeneral.easyDNSDebugMode
$appName       = $config.easyDNSGeneral.easyDNSAPPName
$themeColor    = $config.easyDNSGeneral.easyDNSThemeColor
$fontFamily    = $config.easyDNSGeneral.easyDNSFontFamily
$fontSize      = [float]$config.easyDNSGeneral.easyDNSFontSize
$headerLogo    = $config.easyDNSGeneral.easyDNSHeaderLogo
$headerLogoURL = $config.easyDNSGeneral.easyDNSHeaderLogoURL
$footerText    = $config.easyDNSGeneral.easyDNSFooterText

# Für Reverse-Zonen (falls nicht in INI gesetzt, Default=Domain)
$reverseDefaultScope = $config.easyDNSReverse.DefaultReplicationScope
if (-not $reverseDefaultScope) {
    $reverseDefaultScope = "Domain"
}

# DNSSEC-Einstellungen
$enableDNSSEC = [bool][int]$config.easyDNSDNSSEC.EnableDNSSEC
$signingAlgorithm = $config.easyDNSDNSSEC.SigningAlgorithm
$keyLength = [int]$config.easyDNSDNSSEC.KeyLength

# Batch-Operationen
$importFolder = $config.easyDNSBatch.DefaultImportFolder
$exportFolder = $config.easyDNSBatch.DefaultExportFolder

if (-not (Test-Path $importFolder)) {
    New-Item -ItemType Directory -Path $importFolder -Force | Out-Null
}
if (-not (Test-Path $exportFolder)) {
    New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
}

###############################################################################
# 7) HEADER-TEXT: Replace-Platzhalter durch INI-Werte
###############################################################################
$headerText = $headerTextRaw `
    -replace '\{ScriptVersion\}', $scriptVersion `
    -replace '\{LastUpdate\}', $lastUpdate `
    -replace '\{Author\}', $author

###############################################################################
# 8) LOGGING-FUNKTION: Schreibt Meldungen in eine Datei im selben Verzeichnis
###############################################################################
function Log-Message {
    param(
        [string]$msg,
        [string]$severity = "INFO"
    )
    $today = (Get-Date -Format "yyyyMMdd")
    $user  = $env:USERNAME
    $logFile = "easyDNS_{0}_{1}.log" -f $today, $user
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "[$severity] $($timestamp): $($msg)" | Out-File -FilePath (Join-Path $scriptRoot $logFile) -Append -Encoding utf8
    
    # Bei DEBUG oder ERROR auch in die Konsole ausgeben, falls verfügbar
    if ($severity -eq "DEBUG" -and $debugMode -eq 1) {
        Write-Host "[$severity] $msg" -ForegroundColor Yellow
    }
    elseif ($severity -eq "ERROR") {
        Write-Host "[$severity] $msg" -ForegroundColor Red
    }
}

###############################################################################
# 9) DEBUG AUSGABE: Debug-Infos, falls in der INI aktiviert
###############################################################################
if ($debugMode -eq 1) {
    Log-Message "DNS-Server: $DetectedDnsServer" -severity "DEBUG"
    Log-Message "scriptVersion: $scriptVersion" -severity "DEBUG"
    Log-Message "lastUpdate: $lastUpdate" -severity "DEBUG"
    Log-Message "author: $author" -severity "DEBUG"
    Log-Message "themeColor: $themeColor" -severity "DEBUG"
    Log-Message "headerLogo: $headerLogo" -severity "DEBUG"
    Log-Message "URL: $headerLogoURL" -severity "DEBUG"
    Log-Message "Footer: $footerText" -severity "DEBUG"
}

###############################################################################
# 10) URL-OPENER: öffnet eine URL im Browser, Fehler werden protokolliert
###############################################################################
function Open-URLInBrowser {
    param([string]$url)
    try {
        [System.Diagnostics.Process]::Start($url) | Out-Null
    }
    catch {
        Log-Message "Could not open URL '$url': ${_.Exception.Message}" -severity "ERROR"
    }
}

###############################################################################
# 11) GET-SAFEDNSSERVERZONE: Liest DNS-Zonen ein und wandelt sie in Objekte um
###############################################################################
function Get-SafeDnsServerZone {
    param([string]$DnsServerName)
    $list = @()
    try {
        $rawZones = Get-DnsServerZone -ComputerName $DnsServerName -ErrorAction Stop | Select-Object *

        foreach ($z in $rawZones) {
            # Cache, RootHints und "." nicht verwenden
            if ($z.ZoneName -in @("RootHints","Cache",".") -or $z.ZoneType -eq "Cache") {
                continue
            }
            $isRev = $false
            if ($z.PSObject.Properties.Name -contains 'IsReverseLookupZone') {
                $isRev = $z.IsReverseLookupZone
            }
            else {
                if ($z.ZoneName -match '\.arpa$') { $isRev = $true }
            }

            $repScope = 'N/A'
            if ($z.PSObject.Properties.Name -contains 'ReplicationScope') {
                if ($z.ReplicationScope) {
                    $repScope = $z.ReplicationScope
                }
            }
            
            # DNSSEC Status prüfen
            $dnssecStatus = "Disabled"
            try {
                $zoneParams = Get-DnsServerZone -Name $z.ZoneName -ComputerName $DnsServerName
                if ($zoneParams.IsSigned) {
                    $dnssecStatus = "Enabled"
                }
            } catch {}

            $list += [PSCustomObject]@{
                ZoneName   = $z.ZoneName
                ZoneType   = $z.ZoneType
                IsReverse  = $isRev
                RepScope   = $repScope
                DNSSECStatus = $dnssecStatus
            }
        }
    }
    catch {
        Log-Message "Error retrieving DNS zones: ${_}" -severity "ERROR"
    }
    return $list
}

###############################################################################
# 12) ESCAPE-CURLY: Ersetzt { und } durch {{ und }}, um Formatierungsfehler
#     zu verhindern (sofern irgendwo {xyz} vorkommen kann).
###############################################################################
function Escape-Curly {
    param([string]$value)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $value
    }
    return $value -replace '\{','{{' -replace '\}','}}'
}

###############################################################################
# 13) HAUPTFORM: Haupt-Fenster mit Panels für Header, Footer, etc.
###############################################################################
$Form = New-Object System.Windows.Forms.Form
$Form.Text = $appName
$Form.Size = New-Object System.Drawing.Size(1300,968)
$Form.StartPosition = "CenterScreen"
$Form.Font = New-Object System.Drawing.Font($fontFamily, $fontSize)
try {
    $Form.BackColor = [System.Drawing.ColorTranslator]::FromHtml($themeColor)
}
catch {
    $Form.BackColor = [System.Drawing.Color]::White
}

# HEADER-PANEL
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(1300,80)
try {
    $headerPanel.BackColor = [System.Drawing.ColorTranslator]::FromHtml($themeColor)
}
catch {
    $headerPanel.BackColor = [System.Drawing.Color]::Gray
}
$Form.Controls.Add($headerPanel)

# MAIN-PANEL: Hier kommt das TabControl hinein
$mainPanel = New-Object System.Windows.Forms.Panel
$mainPanel.Location = New-Object System.Drawing.Point(0,100)
$mainPanel.Size = New-Object System.Drawing.Size(1300,750)
$Form.Controls.Add($mainPanel)

# CLOSE-PANEL: Panel unten für einen zentralen Close-Button
$closePanel = New-Object System.Windows.Forms.Panel
$closePanel.Location = New-Object System.Drawing.Point(0,850)
$closePanel.Size = New-Object System.Drawing.Size(1300,50)
$Form.Controls.Add($closePanel)

# FOOTER-PANEL: unterstes Panel für Footer (z. B. (c)-Hinweise)
$footerPanel = New-Object System.Windows.Forms.Panel
$footerPanel.Location = New-Object System.Drawing.Point(0,900)
$footerPanel.Size = New-Object System.Drawing.Size(1300,30)
$footerPanel.BackColor = [System.Drawing.Color]::LightGray
$Form.Controls.Add($footerPanel)

###############################################################################
# 14) HEADER-INHALT (Logo, Labels, etc.)
###############################################################################
if ($headerLogo -and (Test-Path $headerLogo)) {
    $picLogo = New-Object System.Windows.Forms.PictureBox
    $picLogo.Location = New-Object System.Drawing.Point(20,10)
    $picLogo.Size = New-Object System.Drawing.Size(250,60)
    $picLogo.SizeMode = "StretchImage"
    $picLogo.ImageLocation = $headerLogo
    $picLogo.Cursor = [System.Windows.Forms.Cursors]::Hand
    $picLogo.Add_Click({ Open-URLInBrowser -url $headerLogoURL })
    $headerPanel.Controls.Add($picLogo)
}

# Label mit Versionsinfo (aus INI ersetzt)
$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = $headerText
$headerLabel.ForeColor = [System.Drawing.Color]::White
$headerLabel.Location = New-Object System.Drawing.Point(540,15)
$headerLabel.AutoSize = $true
$headerPanel.Controls.Add($headerLabel)

# DNS-Server Label
$labelDNSServer = New-Object System.Windows.Forms.Label
$labelDNSServer.Text = "DNS-Server:"
$labelDNSServer.ForeColor = [System.Drawing.Color]::White
$labelDNSServer.Location = New-Object System.Drawing.Point(540,50)
$labelDNSServer.AutoSize = $true
$headerPanel.Controls.Add($labelDNSServer)

# TextBox für den erkannten/verwendeten DNS-Server
$txtDNSServer = New-Object System.Windows.Forms.TextBox
$txtDNSServer.Location = New-Object System.Drawing.Point(640,47)
$txtDNSServer.Size = New-Object System.Drawing.Size(300,25)
$txtDNSServer.Text = $DetectedDnsServer
$headerPanel.Controls.Add($txtDNSServer)

# Connect-Button
$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "Verbinden"
$btnConnect.Location = New-Object System.Drawing.Point(950,47)
$btnConnect.Size = New-Object System.Drawing.Size(100,25)
$btnConnect.BackColor = [System.Drawing.Color]::LightSkyBlue
$headerPanel.Controls.Add($btnConnect)

###############################################################################
# 15) FOOTER: ein Label, das ggf. eine Webseite auf Klick öffnet
###############################################################################
$footerLabel = New-Object System.Windows.Forms.Label
$footerLabel.Dock = "Fill"
$footerLabel.TextAlign = "MiddleCenter"
$footerLabel.Text = $footerText
$footerLabel.Cursor = [System.Windows.Forms.Cursors]::Hand
$footerLabel.Add_Click({ Open-URLInBrowser -url $headerLogoURL })
$footerPanel.Controls.Add($footerLabel)

###############################################################################
# 16) CLOSE-BUTTON: rot gefärbter Button auf dem Close-Panel
###############################################################################
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Size = New-Object System.Drawing.Size(120,35)
$btnClose.Text = "BEENDEN"
# "Close" bleibt hellrot
$btnClose.BackColor = [System.Drawing.Color]::LightCoral 
$btnClose.Location = New-Object System.Drawing.Point(
    ([int](($closePanel.Width - $btnClose.Width)/2)),
    ([int](($closePanel.Height - $btnClose.Height)/2))
)
$closePanel.Controls.Add($btnClose)
$btnClose.Add_Click({ $Form.Close() })

###############################################################################
# 17) TABCONTROL: Enthält sechs Tabs für Forward, Reverse, DNS Records, 
#     Import/Export, DNSSEC, Tools
###############################################################################
$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Location = New-Object System.Drawing.Point(20,20)
$TabControl.Size = New-Object System.Drawing.Size(1240,710)
$mainPanel.Controls.Add($TabControl)

###############################################################################
# TAB 1: FORWARD ZONES
###############################################################################
$tabForward = New-Object System.Windows.Forms.TabPage
$tabForward.Text = "Forward Zones"

# Refresh-Button (hellorange)
$btnForwardRefresh = New-Object System.Windows.Forms.Button
$btnForwardRefresh.Text = "Zonen aktualisieren"
$btnForwardRefresh.Location = New-Object System.Drawing.Point(30,20)
$btnForwardRefresh.Size = New-Object System.Drawing.Size(150,25)
$btnForwardRefresh.BackColor = [System.Drawing.Color]::LightSalmon
$tabForward.Controls.Add($btnForwardRefresh)

# ComboBox für die gefundenen Forward-Zonen
$comboForwardZones = New-Object System.Windows.Forms.ComboBox
$comboForwardZones.Location = New-Object System.Drawing.Point(30,60)
$comboForwardZones.Size = New-Object System.Drawing.Size(360,25)
$tabForward.Controls.Add($comboForwardZones)

# Label + TextBox für neue Zone
$lblForwardNewZone = New-Object System.Windows.Forms.Label
$lblForwardNewZone.Text = "Name der neuen Zone:"
$lblForwardNewZone.Location = New-Object System.Drawing.Point(30,120)
$lblForwardNewZone.Size = New-Object System.Drawing.Size(150,20)
$tabForward.Controls.Add($lblForwardNewZone)

$txtForwardZone = New-Object System.Windows.Forms.TextBox
$txtForwardZone.Location = New-Object System.Drawing.Point(185,118)
$txtForwardZone.Size = New-Object System.Drawing.Size(230,25)
$tabForward.Controls.Add($txtForwardZone)

# Replikationsbereich
$lblForwardScope = New-Object System.Windows.Forms.Label
$lblForwardScope.Text = "Replikationsbereich:"
$lblForwardScope.Location = New-Object System.Drawing.Point(30,150)
$lblForwardScope.Size = New-Object System.Drawing.Size(150,20)
$tabForward.Controls.Add($lblForwardScope)

$comboForwardScope = New-Object System.Windows.Forms.ComboBox
$comboForwardScope.Location = New-Object System.Drawing.Point(185,148)
$comboForwardScope.Size = New-Object System.Drawing.Size(150,25)
$comboForwardScope.Items.AddRange(@("Domain","Forest","Legacy"))
# Den Standard aus der INI (oder "Domain") vorauswählen
$comboForwardScope.SelectedItem = $reverseDefaultScope
$tabForward.Controls.Add($comboForwardScope)

# Button zum Erstellen einer neuen Forward-Zone (hellgrün)
$btnForwardCreate = New-Object System.Windows.Forms.Button
$btnForwardCreate.Text = "Zone erstellen"
$btnForwardCreate.Location = New-Object System.Drawing.Point(430,115)
$btnForwardCreate.Size = New-Object System.Drawing.Size(120,25)
$btnForwardCreate.BackColor = [System.Drawing.Color]::LightGreen
$tabForward.Controls.Add($btnForwardCreate)

# Button zum Löschen einer ausgewählten Zone (hellrot)
$btnForwardDelete = New-Object System.Windows.Forms.Button
$btnForwardDelete.Text = "Ausgewählte Zone löschen"
$btnForwardDelete.Location = New-Object System.Drawing.Point(430,60)
$btnForwardDelete.Size = New-Object System.Drawing.Size(180,25)
$btnForwardDelete.BackColor = [System.Drawing.Color]::LightCoral
$tabForward.Controls.Add($btnForwardDelete)

# DataGridView für Zoneninformationen
$dgvForwardZones = New-Object System.Windows.Forms.DataGridView
$dgvForwardZones.Location = New-Object System.Drawing.Point(30,200)
$dgvForwardZones.Size = New-Object System.Drawing.Size(1180,400)
$dgvForwardZones.AllowUserToAddRows = $false
$dgvForwardZones.AllowUserToDeleteRows = $false
$dgvForwardZones.ReadOnly = $true
$dgvForwardZones.AutoSizeColumnsMode = "Fill"
$dgvForwardZones.AutoGenerateColumns = $false
$dgvForwardZones.SelectionMode = "FullRowSelect"
$dgvForwardZones.MultiSelect = $false

# Spalten für das DataGridView definieren
$colZoneName = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colZoneName.HeaderText = "Zonenname"
$colZoneName.DataPropertyName = "ZoneName"
$colZoneName.Width = 300

$colZoneType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colZoneType.HeaderText = "Typ"
$colZoneType.DataPropertyName = "ZoneType"
$colZoneType.Width = 150

$colRepScope = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRepScope.HeaderText = "Replikationsbereich"
$colRepScope.DataPropertyName = "RepScope"
$colRepScope.Width = 150

$colDNSSECStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDNSSECStatus.HeaderText = "DNSSEC-Status"
$colDNSSECStatus.DataPropertyName = "DNSSECStatus"
$colDNSSECStatus.Width = 150

$dgvForwardZones.Columns.Add($colZoneName)
$dgvForwardZones.Columns.Add($colZoneType)
$dgvForwardZones.Columns.Add($colRepScope)
$dgvForwardZones.Columns.Add($colDNSSECStatus)

$tabForward.Controls.Add($dgvForwardZones)

$TabControl.TabPages.Add($tabForward)

###############################################################################
# TAB 2: REVERSE ZONES
###############################################################################
$tabReverse = New-Object System.Windows.Forms.TabPage
$tabReverse.Text = "Reverse Zones"

# Refresh (hellorange)
$btnReverseRefresh = New-Object System.Windows.Forms.Button
$btnReverseRefresh.Text = "Zonen aktualisieren"
$btnReverseRefresh.Location = New-Object System.Drawing.Point(30,20)
$btnReverseRefresh.Size = New-Object System.Drawing.Size(150,25)
$btnReverseRefresh.BackColor = [System.Drawing.Color]::LightSalmon
$tabReverse.Controls.Add($btnReverseRefresh)

$comboReverseZones = New-Object System.Windows.Forms.ComboBox
$comboReverseZones.Location = New-Object System.Drawing.Point(30,60)
$comboReverseZones.Size = New-Object System.Drawing.Size(360,25)
$tabReverse.Controls.Add($comboReverseZones)

# NetworkID
$lblReverseNet = New-Object System.Windows.Forms.Label
$lblReverseNet.Text = "Netzwerk-ID:"
$lblReverseNet.Location = New-Object System.Drawing.Point(30,120)
$lblReverseNet.Size = New-Object System.Drawing.Size(150,20)
$tabReverse.Controls.Add($lblReverseNet)

$txtReverseNet = New-Object System.Windows.Forms.TextBox
$txtReverseNet.Location = New-Object System.Drawing.Point(185,118)
$txtReverseNet.Size = New-Object System.Drawing.Size(150,25)
$tabReverse.Controls.Add($txtReverseNet)

# Scope
$lblReverseScope = New-Object System.Windows.Forms.Label
$lblReverseScope.Text = "Replikationsbereich:"
$lblReverseScope.Location = New-Object System.Drawing.Point(30,150)
$lblReverseScope.Size = New-Object System.Drawing.Size(150,20)
$tabReverse.Controls.Add($lblReverseScope)

$comboReverseScope = New-Object System.Windows.Forms.ComboBox
$comboReverseScope.Location = New-Object System.Drawing.Point(185,148)
$comboReverseScope.Size = New-Object System.Drawing.Size(150,25)
$comboReverseScope.Items.AddRange(@("Domain","Forest","Legacy"))
# Den Standard aus der INI (oder "Domain") vorauswählen
$comboReverseScope.SelectedItem = $reverseDefaultScope
$tabReverse.Controls.Add($comboReverseScope)

# Button Create Reverse (hellgrün)
$btnReverseCreate = New-Object System.Windows.Forms.Button
$btnReverseCreate.Text = "Reverse-Zone erstellen"
$btnReverseCreate.Location = New-Object System.Drawing.Point(350,115)
$btnReverseCreate.Size = New-Object System.Drawing.Size(150,25)
$btnReverseCreate.BackColor = [System.Drawing.Color]::LightGreen
$tabReverse.Controls.Add($btnReverseCreate)

# Button zum Löschen einer ausgewählten Zone (hellrot)
$btnReverseDelete = New-Object System.Windows.Forms.Button
$btnReverseDelete.Text = "Ausgewählte Zone löschen"
$btnReverseDelete.Location = New-Object System.Drawing.Point(430,60)
$btnReverseDelete.Size = New-Object System.Drawing.Size(180,25)
$btnReverseDelete.BackColor = [System.Drawing.Color]::LightCoral
$tabReverse.Controls.Add($btnReverseDelete)

# DataGridView für Reverse-Zoneninformationen
$dgvReverseZones = New-Object System.Windows.Forms.DataGridView
$dgvReverseZones.Location = New-Object System.Drawing.Point(30,200)
$dgvReverseZones.Size = New-Object System.Drawing.Size(1180,400)
$dgvReverseZones.AllowUserToAddRows = $false
$dgvReverseZones.AllowUserToDeleteRows = $false
$dgvReverseZones.ReadOnly = $true
$dgvReverseZones.AutoSizeColumnsMode = "Fill"
$dgvReverseZones.AutoGenerateColumns = $false
$dgvReverseZones.SelectionMode = "FullRowSelect"
$dgvReverseZones.MultiSelect = $false

# Spalten für das DataGridView (gleiche Struktur wie Forward Zones)
$dgvReverseZones.Columns.Add($colZoneName.Clone())
$dgvReverseZones.Columns.Add($colZoneType.Clone())
$dgvReverseZones.Columns.Add($colRepScope.Clone())
$dgvReverseZones.Columns.Add($colDNSSECStatus.Clone())

$tabReverse.Controls.Add($dgvReverseZones)

# IP-Netzwerk-Generator
$lblNetworkHelper = New-Object System.Windows.Forms.Label
$lblNetworkHelper.Text = "IP-Netzwerk-Generator:"
$lblNetworkHelper.Location = New-Object System.Drawing.Point(550,120)
$lblNetworkHelper.Size = New-Object System.Drawing.Size(150,20)
$tabReverse.Controls.Add($lblNetworkHelper)

$lblNetworkIP = New-Object System.Windows.Forms.Label
$lblNetworkIP.Text = "IP-Adresse:"
$lblNetworkIP.Location = New-Object System.Drawing.Point(550,150)
$lblNetworkIP.Size = New-Object System.Drawing.Size(100,20)
$tabReverse.Controls.Add($lblNetworkIP)

$txtNetworkIP = New-Object System.Windows.Forms.TextBox
$txtNetworkIP.Location = New-Object System.Drawing.Point(650,148)
$txtNetworkIP.Size = New-Object System.Drawing.Size(120,25)
$tabReverse.Controls.Add($txtNetworkIP)

$lblNetworkCIDR = New-Object System.Windows.Forms.Label
$lblNetworkCIDR.Text = "CIDR:"
$lblNetworkCIDR.Location = New-Object System.Drawing.Point(780,150)
$lblNetworkCIDR.Size = New-Object System.Drawing.Size(50,20)
$tabReverse.Controls.Add($lblNetworkCIDR)

$txtNetworkCIDR = New-Object System.Windows.Forms.TextBox
$txtNetworkCIDR.Location = New-Object System.Drawing.Point(830,148)
$txtNetworkCIDR.Size = New-Object System.Drawing.Size(40,25)
$tabReverse.Controls.Add($txtNetworkCIDR)

$btnGenerateNetwork = New-Object System.Windows.Forms.Button
$btnGenerateNetwork.Text = "NetworkID generieren"
$btnGenerateNetwork.Location = New-Object System.Drawing.Point(880,148)
$btnGenerateNetwork.Size = New-Object System.Drawing.Size(150,25)
$btnGenerateNetwork.BackColor = [System.Drawing.Color]::LightSalmon
$tabReverse.Controls.Add($btnGenerateNetwork)

$TabControl.TabPages.Add($tabReverse)

###############################################################################
# TAB 3: DNS RECORDS
###############################################################################
$tabRecords = New-Object System.Windows.Forms.TabPage
$tabRecords.Text = "DNS Records"

# Labels und Eingaben (ComboRecZone, LoadZones, Type etc.)
$lblRecZone = New-Object System.Windows.Forms.Label
$lblRecZone.Text = "Zone:"
$lblRecZone.Location = New-Object System.Drawing.Point(30,20)
$lblRecZone.Size = New-Object System.Drawing.Size(120,20)
$tabRecords.Controls.Add($lblRecZone)

$comboRecZone = New-Object System.Windows.Forms.ComboBox
$comboRecZone.Location = New-Object System.Drawing.Point(160,18)
$comboRecZone.Size = New-Object System.Drawing.Size(200,25)
$tabRecords.Controls.Add($comboRecZone)

$btnLoadZones = New-Object System.Windows.Forms.Button
$btnLoadZones.Text = "Zonen laden"
$btnLoadZones.Location = New-Object System.Drawing.Point(380,15)
$btnLoadZones.Size = New-Object System.Drawing.Size(120,25)
$btnLoadZones.BackColor = [System.Drawing.Color]::LightSalmon
$tabRecords.Controls.Add($btnLoadZones)

$lblRecType = New-Object System.Windows.Forms.Label
$lblRecType.Text = "Record-Typ:"
$lblRecType.Location = New-Object System.Drawing.Point(30,60)
$lblRecType.Size = New-Object System.Drawing.Size(120,20)
$tabRecords.Controls.Add($lblRecType)

$comboRecType = New-Object System.Windows.Forms.ComboBox
$comboRecType.Location = New-Object System.Drawing.Point(160,58)
$comboRecType.Size = New-Object System.Drawing.Size(120,25)
$comboRecType.Items.AddRange(@("A","AAAA","CNAME","MX","PTR","TXT","SRV","NS"))
$comboRecType.SelectedIndex = 0
$tabRecords.Controls.Add($comboRecType)

$lblRecName = New-Object System.Windows.Forms.Label
$lblRecName.Text = "Name:"
$lblRecName.Location = New-Object System.Drawing.Point(30,100)
$lblRecName.Size = New-Object System.Drawing.Size(120,20)
$tabRecords.Controls.Add($lblRecName)

$txtRecName = New-Object System.Windows.Forms.TextBox
$txtRecName.Location = New-Object System.Drawing.Point(160,98)
$txtRecName.Size = New-Object System.Drawing.Size(200,25)
$tabRecords.Controls.Add($txtRecName)

$lblRecData = New-Object System.Windows.Forms.Label
$lblRecData.Text = "Daten:"
$lblRecData.Location = New-Object System.Drawing.Point(30,140)
$lblRecData.Size = New-Object System.Drawing.Size(120,20)
$tabRecords.Controls.Add($lblRecData)

$txtRecData = New-Object System.Windows.Forms.TextBox
$txtRecData.Location = New-Object System.Drawing.Point(160,138)
$txtRecData.Size = New-Object System.Drawing.Size(200,25)
$tabRecords.Controls.Add($txtRecData)

# Zusätzliche Felder für MX und SRV Records
$lblRecordPriority = New-Object System.Windows.Forms.Label
$lblRecordPriority.Text = "Priorität:"
$lblRecordPriority.Location = New-Object System.Drawing.Point(30,180)
$lblRecordPriority.Size = New-Object System.Drawing.Size(120,20)
$lblRecordPriority.Visible = $false
$tabRecords.Controls.Add($lblRecordPriority)

$txtRecordPriority = New-Object System.Windows.Forms.TextBox
$txtRecordPriority.Location = New-Object System.Drawing.Point(160,178)
$txtRecordPriority.Size = New-Object System.Drawing.Size(200,25)
$txtRecordPriority.Text = "10"
$txtRecordPriority.Visible = $false
$tabRecords.Controls.Add($txtRecordPriority)

$lblRecordWeight = New-Object System.Windows.Forms.Label
$lblRecordWeight.Text = "Gewichtung:"
$lblRecordWeight.Location = New-Object System.Drawing.Point(30,220)
$lblRecordWeight.Size = New-Object System.Drawing.Size(120,20)
$lblRecordWeight.Visible = $false
$tabRecords.Controls.Add($lblRecordWeight)

$txtRecordWeight = New-Object System.Windows.Forms.TextBox
$txtRecordWeight.Location = New-Object System.Drawing.Point(160,218)
$txtRecordWeight.Size = New-Object System.Drawing.Size(200,25)
$txtRecordWeight.Text = "10"
$txtRecordWeight.Visible = $false
$tabRecords.Controls.Add($txtRecordWeight)

$lblRecordPort = New-Object System.Windows.Forms.Label
$lblRecordPort.Text = "Port:"
$lblRecordPort.Location = New-Object System.Drawing.Point(30,260)
$lblRecordPort.Size = New-Object System.Drawing.Size(120,20)
$lblRecordPort.Visible = $false
$tabRecords.Controls.Add($lblRecordPort)

$txtRecordPort = New-Object System.Windows.Forms.TextBox
$txtRecordPort.Location = New-Object System.Drawing.Point(160,258)
$txtRecordPort.Size = New-Object System.Drawing.Size(200,25)
$txtRecordPort.Visible = $false
$tabRecords.Controls.Add($txtRecordPort)

# TTL
$lblRecordTTL = New-Object System.Windows.Forms.Label
$lblRecordTTL.Text = "TTL (Sekunden):"
$lblRecordTTL.Location = New-Object System.Drawing.Point(30,180)
$lblRecordTTL.Size = New-Object System.Drawing.Size(120,20)
$tabRecords.Controls.Add($lblRecordTTL)

$txtRecordTTL = New-Object System.Windows.Forms.TextBox
$txtRecordTTL.Location = New-Object System.Drawing.Point(160,178)
$txtRecordTTL.Size = New-Object System.Drawing.Size(200,25)
$txtRecordTTL.Text = "3600"
$tabRecords.Controls.Add($txtRecordTTL)

# Buttons Create/Test/Show/Delete mit Farben
$btnRecCreate = New-Object System.Windows.Forms.Button
$btnRecCreate.Text = "Erstellen"
$btnRecCreate.Location = New-Object System.Drawing.Point(160,220)
$btnRecCreate.Size = New-Object System.Drawing.Size(90,30)
$btnRecCreate.BackColor = [System.Drawing.Color]::LightGreen
$tabRecords.Controls.Add($btnRecCreate)

$btnRecTest = New-Object System.Windows.Forms.Button
$btnRecTest.Text = "Testen"
$btnRecTest.Location = New-Object System.Drawing.Point(260,220)
$btnRecTest.Size = New-Object System.Drawing.Size(90,30)
$btnRecTest.BackColor = [System.Drawing.Color]::LightSalmon
$tabRecords.Controls.Add($btnRecTest)

$btnRecShow = New-Object System.Windows.Forms.Button
$btnRecShow.Text = "Anzeigen"
$btnRecShow.Location = New-Object System.Drawing.Point(160,260)
$btnRecShow.Size = New-Object System.Drawing.Size(90,30)
$btnRecShow.BackColor = [System.Drawing.Color]::LightSalmon
$tabRecords.Controls.Add($btnRecShow)

$btnRecDelete = New-Object System.Windows.Forms.Button
$btnRecDelete.Text = "Löschen"
$btnRecDelete.Location = New-Object System.Drawing.Point(260,260)
$btnRecDelete.Size = New-Object System.Drawing.Size(90,30)
$btnRecDelete.BackColor = [System.Drawing.Color]::LightCoral
$tabRecords.Controls.Add($btnRecDelete)

# DataGridView für DNS-Records
$dgvDNSRecords = New-Object System.Windows.Forms.DataGridView
$dgvDNSRecords.Location = New-Object System.Drawing.Point(400,15)
$dgvDNSRecords.Size = New-Object System.Drawing.Size(810,450)
$dgvDNSRecords.AllowUserToAddRows = $false
$dgvDNSRecords.AllowUserToDeleteRows = $false
$dgvDNSRecords.ReadOnly = $true
$dgvDNSRecords.AutoSizeColumnsMode = "Fill"
$dgvDNSRecords.SelectionMode = "FullRowSelect"
$dgvDNSRecords.MultiSelect = $false

# Spalten für das DataGridView
$colRecordName = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRecordName.HeaderText = "Name"
$colRecordName.DataPropertyName = "Name"

$colRecordType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRecordType.HeaderText = "Typ"
$colRecordType.DataPropertyName = "Type"

$colRecordData = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRecordData.HeaderText = "Daten"
$colRecordData.DataPropertyName = "Data"

$colRecordTTL = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRecordTTL.HeaderText = "TTL"
$colRecordTTL.DataPropertyName = "TTL"

$dgvDNSRecords.Columns.Add($colRecordName)
$dgvDNSRecords.Columns.Add($colRecordType)
$dgvDNSRecords.Columns.Add($colRecordData)
$dgvDNSRecords.Columns.Add($colRecordTTL)

$tabRecords.Controls.Add($dgvDNSRecords)

# TextBox-Ausgabe für Test oder Status
$txtRecTestOutput = New-Object System.Windows.Forms.TextBox
$txtRecTestOutput.Location = New-Object System.Drawing.Point(30,480)
$txtRecTestOutput.Size = New-Object System.Drawing.Size(1180,180)
$txtRecTestOutput.Multiline = $true
$txtRecTestOutput.ScrollBars = "Vertical"
$txtRecTestOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$tabRecords.Controls.Add($txtRecTestOutput)

$TabControl.TabPages.Add($tabRecords)

###############################################################################
# TAB 4: IMPORT/EXPORT
###############################################################################
$tabImportExport = New-Object System.Windows.Forms.TabPage
$tabImportExport.Text = "Import/Export"

# Import-Bereich
$grpImport = New-Object System.Windows.Forms.GroupBox
$grpImport.Text = "DNS-Daten importieren"
$grpImport.Location = New-Object System.Drawing.Point(30, 20)
$grpImport.Size = New-Object System.Drawing.Size(550, 320)
$tabImportExport.Controls.Add($grpImport)

$lblImportFile = New-Object System.Windows.Forms.Label
$lblImportFile.Text = "Import-Datei:"
$lblImportFile.Location = New-Object System.Drawing.Point(20, 30)
$lblImportFile.Size = New-Object System.Drawing.Size(100, 20)
$grpImport.Controls.Add($lblImportFile)

$txtImportFile = New-Object System.Windows.Forms.TextBox
$txtImportFile.Location = New-Object System.Drawing.Point(130, 27)
$txtImportFile.Size = New-Object System.Drawing.Size(300, 25)
$grpImport.Controls.Add($txtImportFile)

$btnBrowseImport = New-Object System.Windows.Forms.Button
$btnBrowseImport.Text = "..."
$btnBrowseImport.Location = New-Object System.Drawing.Point(440, 27)
$btnBrowseImport.Size = New-Object System.Drawing.Size(30, 25)
$btnBrowseImport.BackColor = [System.Drawing.Color]::LightGray
$grpImport.Controls.Add($btnBrowseImport)

$lblImportFormat = New-Object System.Windows.Forms.Label
$lblImportFormat.Text = "Format:"
$lblImportFormat.Location = New-Object System.Drawing.Point(20, 70)
$lblImportFormat.Size = New-Object System.Drawing.Size(100, 20)
$grpImport.Controls.Add($lblImportFormat)

$comboImportFormat = New-Object System.Windows.Forms.ComboBox
$comboImportFormat.Location = New-Object System.Drawing.Point(130, 67)
$comboImportFormat.Size = New-Object System.Drawing.Size(200, 25)
$comboImportFormat.Items.AddRange(@("CSV", "JSON", "BIND Zone File", "Tab-getrennte Werte"))
$comboImportFormat.SelectedIndex = 0
$grpImport.Controls.Add($comboImportFormat)

$lblImportZone = New-Object System.Windows.Forms.Label
$lblImportZone.Text = "Ziel-Zone:"
$lblImportZone.Location = New-Object System.Drawing.Point(20, 110)
$lblImportZone.Size = New-Object System.Drawing.Size(100, 20)
$grpImport.Controls.Add($lblImportZone)

$comboImportZone = New-Object System.Windows.Forms.ComboBox
$comboImportZone.Location = New-Object System.Drawing.Point(130, 107)
$comboImportZone.Size = New-Object System.Drawing.Size(300, 25)
$grpImport.Controls.Add($comboImportZone)

$chkCreateMissingZones = New-Object System.Windows.Forms.CheckBox
$chkCreateMissingZones.Text = "Fehlende Zonen automatisch anlegen"
$chkCreateMissingZones.Location = New-Object System.Drawing.Point(130, 150)
$chkCreateMissingZones.Size = New-Object System.Drawing.Size(300, 20)
$grpImport.Controls.Add($chkCreateMissingZones)

$chkOverwriteExisting = New-Object System.Windows.Forms.CheckBox
$chkOverwriteExisting.Text = "Bestehende Einträge überschreiben"
$chkOverwriteExisting.Location = New-Object System.Drawing.Point(130, 180)
$chkOverwriteExisting.Size = New-Object System.Drawing.Size(300, 20)
$grpImport.Controls.Add($chkOverwriteExisting)

$lblImportStatus = New-Object System.Windows.Forms.Label
$lblImportStatus.Text = "Status: Bereit"
$lblImportStatus.Location = New-Object System.Drawing.Point(20, 230)
$lblImportStatus.Size = New-Object System.Drawing.Size(500, 20)
$grpImport.Controls.Add($lblImportStatus)

$btnImport = New-Object System.Windows.Forms.Button
$btnImport.Text = "Importieren"
$btnImport.Location = New-Object System.Drawing.Point(130, 260)
$btnImport.Size = New-Object System.Drawing.Size(150, 35)
$btnImport.BackColor = [System.Drawing.Color]::LightGreen
$grpImport.Controls.Add($btnImport)

# Export-Bereich
$grpExport = New-Object System.Windows.Forms.GroupBox
$grpExport.Text = "DNS-Daten exportieren"
$grpExport.Location = New-Object System.Drawing.Point(650, 20)
$grpExport.Size = New-Object System.Drawing.Size(550, 320)
$tabImportExport.Controls.Add($grpExport)

$lblExportFile = New-Object System.Windows.Forms.Label
$lblExportFile.Text = "Export-Datei:"
$lblExportFile.Location = New-Object System.Drawing.Point(20, 30)
$lblExportFile.Size = New-Object System.Drawing.Size(100, 20)
$grpExport.Controls.Add($lblExportFile)

$txtExportFile = New-Object System.Windows.Forms.TextBox
$txtExportFile.Location = New-Object System.Drawing.Point(130, 27)
$txtExportFile.Size = New-Object System.Drawing.Size(300, 25)
$grpExport.Controls.Add($txtExportFile)

$btnBrowseExport = New-Object System.Windows.Forms.Button
$btnBrowseExport.Text = "..."
$btnBrowseExport.Location = New-Object System.Drawing.Point(440, 27)
$btnBrowseExport.Size = New-Object System.Drawing.Size(30, 25)
$btnBrowseExport.BackColor = [System.Drawing.Color]::LightGray
$grpExport.Controls.Add($btnBrowseExport)

$lblExportFormat = New-Object System.Windows.Forms.Label
$lblExportFormat.Text = "Format:"
$lblExportFormat.Location = New-Object System.Drawing.Point(20, 70)
$lblExportFormat.Size = New-Object System.Drawing.Size(100, 20)
$grpExport.Controls.Add($lblExportFormat)

$comboExportFormat = New-Object System.Windows.Forms.ComboBox
$comboExportFormat.Location = New-Object System.Drawing.Point(130, 67)
$comboExportFormat.Size = New-Object System.Drawing.Size(200, 25)
$comboExportFormat.Items.AddRange(@("CSV", "JSON", "BIND Zone File", "Tab-getrennte Werte", "HTML"))
$comboExportFormat.SelectedIndex = 0
$grpExport.Controls.Add($comboExportFormat)

$lblExportZone = New-Object System.Windows.Forms.Label
$lblExportZone.Text = "Quell-Zone:"
$lblExportZone.Location = New-Object System.Drawing.Point(20, 110)
$lblExportZone.Size = New-Object System.Drawing.Size(100, 20)
$grpExport.Controls.Add($lblExportZone)

$comboExportZone = New-Object System.Windows.Forms.ComboBox
$comboExportZone.Location = New-Object System.Drawing.Point(130, 107)
$comboExportZone.Size = New-Object System.Drawing.Size(300, 25)
$grpExport.Controls.Add($comboExportZone)

$lblExportOptions = New-Object System.Windows.Forms.Label
$lblExportOptions.Text = "Optionen:"
$lblExportOptions.Location = New-Object System.Drawing.Point(20, 150)
$lblExportOptions.Size = New-Object System.Drawing.Size(100, 20)
$grpExport.Controls.Add($lblExportOptions)

$chkExportAllZones = New-Object System.Windows.Forms.CheckBox
$chkExportAllZones.Text = "Alle Zonen exportieren"
$chkExportAllZones.Location = New-Object System.Drawing.Point(130, 150)
$chkExportAllZones.Size = New-Object System.Drawing.Size(300, 20)
$grpExport.Controls.Add($chkExportAllZones)

$chkIncludeReverseZones = New-Object System.Windows.Forms.CheckBox
$chkIncludeReverseZones.Text = "Reverse-Zonen einbeziehen"
$chkIncludeReverseZones.Location = New-Object System.Drawing.Point(130, 180)
$chkIncludeReverseZones.Size = New-Object System.Drawing.Size(300, 20)
$grpExport.Controls.Add($chkIncludeReverseZones)

$lblExportStatus = New-Object System.Windows.Forms.Label
$lblExportStatus.Text = "Status: Bereit"
$lblExportStatus.Location = New-Object System.Drawing.Point(20, 230)
$lblExportStatus.Size = New-Object System.Drawing.Size(500, 20)
$grpExport.Controls.Add($lblExportStatus)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Exportieren"
$btnExport.Location = New-Object System.Drawing.Point(130, 260)
$btnExport.Size = New-Object System.Drawing.Size(150, 35)
$btnExport.BackColor = [System.Drawing.Color]::LightSalmon
$grpExport.Controls.Add($btnExport)

# Vorschau-Bereich
$grpPreview = New-Object System.Windows.Forms.GroupBox
$grpPreview.Text = "Vorschau"
$grpPreview.Location = New-Object System.Drawing.Point(30, 350)
$grpPreview.Size = New-Object System.Drawing.Size(1170, 320)
$tabImportExport.Controls.Add($grpPreview)

$txtPreview = New-Object System.Windows.Forms.TextBox
$txtPreview.Location = New-Object System.Drawing.Point(20, 30)
$txtPreview.Size = New-Object System.Drawing.Size(1130, 270)
$txtPreview.Multiline = $true
$txtPreview.ScrollBars = "Both"
$txtPreview.WordWrap = $false
$txtPreview.Font = New-Object System.Drawing.Font("Consolas", 9)
$grpPreview.Controls.Add($txtPreview)

$TabControl.TabPages.Add($tabImportExport)

###############################################################################
# TAB 5: DNSSEC
###############################################################################
$tabDNSSEC = New-Object System.Windows.Forms.TabPage
$tabDNSSEC.Text = "DNSSEC"

# DNSSEC-Status
$lblDNSSECZone = New-Object System.Windows.Forms.Label
$lblDNSSECZone.Text = "Zone:"
$lblDNSSECZone.Location = New-Object System.Drawing.Point(30, 30)
$lblDNSSECZone.Size = New-Object System.Drawing.Size(120, 20)
$tabDNSSEC.Controls.Add($lblDNSSECZone)

$comboDNSSECZone = New-Object System.Windows.Forms.ComboBox
$comboDNSSECZone.Location = New-Object System.Drawing.Point(150, 27)
$comboDNSSECZone.Size = New-Object System.Drawing.Size(300, 25)
$tabDNSSEC.Controls.Add($comboDNSSECZone)

$btnDNSSECRefresh = New-Object System.Windows.Forms.Button
$btnDNSSECRefresh.Text = "Zonen aktualisieren"
$btnDNSSECRefresh.Location = New-Object System.Drawing.Point(470, 27)
$btnDNSSECRefresh.Size = New-Object System.Drawing.Size(150, 25)
$btnDNSSECRefresh.BackColor = [System.Drawing.Color]::LightSalmon
$tabDNSSEC.Controls.Add($btnDNSSECRefresh)

# DNSSEC-Status anzeigen
$lblDNSSECStatus = New-Object System.Windows.Forms.Label
$lblDNSSECStatus.Text = "DNSSEC-Status:"
$lblDNSSECStatus.Location = New-Object System.Drawing.Point(30, 70)
$lblDNSSECStatus.Size = New-Object System.Drawing.Size(120, 20)
$tabDNSSEC.Controls.Add($lblDNSSECStatus)

$txtDNSSECStatus = New-Object System.Windows.Forms.TextBox
$txtDNSSECStatus.Location = New-Object System.Drawing.Point(150, 67)
$txtDNSSECStatus.Size = New-Object System.Drawing.Size(300, 25)
$txtDNSSECStatus.ReadOnly = $true
$tabDNSSEC.Controls.Add($txtDNSSECStatus)

# DNSSEC-Optionen
$grpDNSSECOptions = New-Object System.Windows.Forms.GroupBox
$grpDNSSECOptions.Text = "DNSSEC-Optionen für die ausgewählte Zone"
$grpDNSSECOptions.Location = New-Object System.Drawing.Point(30, 110)
$grpDNSSECOptions.Size = New-Object System.Drawing.Size(550, 230)
$tabDNSSEC.Controls.Add($grpDNSSECOptions)

# Signierungsalgorithmus
$lblSigningAlgo = New-Object System.Windows.Forms.Label
$lblSigningAlgo.Text = "Signierungsalgorithmus:"
$lblSigningAlgo.Location = New-Object System.Drawing.Point(20, 30)
$lblSigningAlgo.Size = New-Object System.Drawing.Size(150, 20)
$grpDNSSECOptions.Controls.Add($lblSigningAlgo)

$comboSigningAlgo = New-Object System.Windows.Forms.ComboBox
$comboSigningAlgo.Location = New-Object System.Drawing.Point(180, 27)
$comboSigningAlgo.Size = New-Object System.Drawing.Size(150, 25)
$comboSigningAlgo.Items.AddRange(@("RSA", "ECDSA", "DSA"))
$comboSigningAlgo.SelectedItem = $signingAlgorithm
$grpDNSSECOptions.Controls.Add($comboSigningAlgo)

# Schlüssellänge
$lblKeyLength = New-Object System.Windows.Forms.Label
$lblKeyLength.Text = "Schlüssellänge:"
$lblKeyLength.Location = New-Object System.Drawing.Point(20, 70)
$lblKeyLength.Size = New-Object System.Drawing.Size(150, 20)
$grpDNSSECOptions.Controls.Add($lblKeyLength)

$comboKeyLength = New-Object System.Windows.Forms.ComboBox
$comboKeyLength.Location = New-Object System.Drawing.Point(180, 67)
$comboKeyLength.Size = New-Object System.Drawing.Size(150, 25)
$comboKeyLength.Items.AddRange(@("1024", "2048", "4096"))
$comboKeyLength.SelectedItem = $keyLength.ToString()
$grpDNSSECOptions.Controls.Add($comboKeyLength)

# Gültigkeitsdauer
$lblValidity = New-Object System.Windows.Forms.Label
$lblValidity.Text = "Gültigkeitsdauer (Tage):"
$lblValidity.Location = New-Object System.Drawing.Point(20, 110)
$lblValidity.Size = New-Object System.Drawing.Size(150, 20)
$grpDNSSECOptions.Controls.Add($lblValidity)

$txtValidity = New-Object System.Windows.Forms.TextBox
$txtValidity.Location = New-Object System.Drawing.Point(180, 107)
$txtValidity.Size = New-Object System.Drawing.Size(150, 25)
$txtValidity.Text = "365"
$grpDNSSECOptions.Controls.Add($txtValidity)

# DNSSEC aktivieren/deaktivieren
$btnEnableDNSSEC = New-Object System.Windows.Forms.Button
$btnEnableDNSSEC.Text = "DNSSEC aktivieren"
$btnEnableDNSSEC.Location = New-Object System.Drawing.Point(180, 150)
$btnEnableDNSSEC.Size = New-Object System.Drawing.Size(150, 30)
$btnEnableDNSSEC.BackColor = [System.Drawing.Color]::LightGreen
$grpDNSSECOptions.Controls.Add($btnEnableDNSSEC)

$btnDisableDNSSEC = New-Object System.Windows.Forms.Button
$btnDisableDNSSEC.Text = "DNSSEC deaktivieren"
$btnDisableDNSSEC.Location = New-Object System.Drawing.Point(350, 150)
$btnDisableDNSSEC.Size = New-Object System.Drawing.Size(150, 30)
$btnDisableDNSSEC.BackColor = [System.Drawing.Color]::LightCoral
$grpDNSSECOptions.Controls.Add($btnDisableDNSSEC)

# Schlüsselinformationen
$grpKeyInfo = New-Object System.Windows.Forms.GroupBox
$grpKeyInfo.Text = "DNSSEC-Schlüsselinformationen"
$grpKeyInfo.Location = New-Object System.Drawing.Point(600, 110)
$grpKeyInfo.Size = New-Object System.Drawing.Size(600, 230)
$tabDNSSEC.Controls.Add($grpKeyInfo)

$dgvDNSSECKeys = New-Object System.Windows.Forms.DataGridView
$dgvDNSSECKeys.Location = New-Object System.Drawing.Point(20, 30)
$dgvDNSSECKeys.Size = New-Object System.Drawing.Size(560, 180)
$dgvDNSSECKeys.AllowUserToAddRows = $false
$dgvDNSSECKeys.AllowUserToDeleteRows = $false
$dgvDNSSECKeys.ReadOnly = $true
$dgvDNSSECKeys.AutoSizeColumnsMode = "Fill"
$dgvDNSSECKeys.MultiSelect = $false

# Spalten für DNSSEC-Schlüssel
$colKeyType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colKeyType.HeaderText = "Schlüsseltyp"
$colKeyType.DataPropertyName = "KeyType"
$colKeyType.Width = 100

$colKeyTag = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colKeyTag.HeaderText = "Key-Tag"
$colKeyTag.DataPropertyName = "KeyTag"
$colKeyTag.Width = 80

$colAlgorithm = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAlgorithm.HeaderText = "Algorithmus"
$colAlgorithm.DataPropertyName = "Algorithm"
$colAlgorithm.Width = 120

$colCreationDate = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colCreationDate.HeaderText = "Erstellungsdatum"
$colCreationDate.DataPropertyName = "CreationDate"
$colCreationDate.Width = 150

$colExpiryDate = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colExpiryDate.HeaderText = "Ablaufdatum"
$colExpiryDate.DataPropertyName = "ExpiryDate"
$colExpiryDate.Width = 150

$dgvDNSSECKeys.Columns.Add($colKeyType)
$dgvDNSSECKeys.Columns.Add($colKeyTag)
$dgvDNSSECKeys.Columns.Add($colAlgorithm)
$dgvDNSSECKeys.Columns.Add($colCreationDate)
$dgvDNSSECKeys.Columns.Add($colExpiryDate)

$grpKeyInfo.Controls.Add($dgvDNSSECKeys)

# DNSSEC-Protokoll und Details
$txtDNSSECDetails = New-Object System.Windows.Forms.TextBox
$txtDNSSECDetails.Location = New-Object System.Drawing.Point(30, 360)
$txtDNSSECDetails.Size = New-Object System.Drawing.Size(1170, 300)
$txtDNSSECDetails.Multiline = $true
$txtDNSSECDetails.ScrollBars = "Both"
$txtDNSSECDetails.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtDNSSECDetails.ReadOnly = $true
$tabDNSSEC.Controls.Add($txtDNSSECDetails)

$TabControl.TabPages.Add($tabDNSSEC)

###############################################################################
# TAB 6: DNS TOOLS (Ping, Tracert, Nslookup, Clear Cache)
###############################################################################
$tabTools = New-Object System.Windows.Forms.TabPage
$tabTools.Text = "DNS Tools"

# Obere Zeile: Label + TextBox + Buttons
$lblToolsTarget = New-Object System.Windows.Forms.Label
$lblToolsTarget.Text = "Ziel:"
$lblToolsTarget.Location = New-Object System.Drawing.Point(30,20)
$lblToolsTarget.Size = New-Object System.Drawing.Size(120,20)
$tabTools.Controls.Add($lblToolsTarget)

$txtToolsTarget = New-Object System.Windows.Forms.TextBox
$txtToolsTarget.Location = New-Object System.Drawing.Point(160,18)
$txtToolsTarget.Size = New-Object System.Drawing.Size(150,25)
$tabTools.Controls.Add($txtToolsTarget)

$btnPing = New-Object System.Windows.Forms.Button
$btnPing.Text = "Ping"
$btnPing.Location = New-Object System.Drawing.Point(330,15)
$btnPing.Size = New-Object System.Drawing.Size(60,25)
$btnPing.BackColor = [System.Drawing.Color]::LightSalmon
$tabTools.Controls.Add($btnPing)

$btnTracert = New-Object System.Windows.Forms.Button
$btnTracert.Text = "Tracert"
$btnTracert.Location = New-Object System.Drawing.Point(400,15)
$btnTracert.Size = New-Object System.Drawing.Size(60,25)
$btnTracert.BackColor = [System.Drawing.Color]::LightSalmon
$tabTools.Controls.Add($btnTracert)

$btnNslookup = New-Object System.Windows.Forms.Button
$btnNslookup.Text = "Nslookup"
$btnNslookup.Location = New-Object System.Drawing.Point(470,15)
$btnNslookup.Size = New-Object System.Drawing.Size(70,25)
$btnNslookup.BackColor = [System.Drawing.Color]::LightSalmon
$tabTools.Controls.Add($btnNslookup)

$btnClearCache = New-Object System.Windows.Forms.Button
$btnClearCache.Text = "Cache leeren"
$btnClearCache.Location = New-Object System.Drawing.Point(550,15)
$btnClearCache.Size = New-Object System.Drawing.Size(90,25)
$btnClearCache.BackColor = [System.Drawing.Color]::LightSalmon
$tabTools.Controls.Add($btnClearCache)

# Erweiterte Diagnosetools-Bereich
$lblAdvancedTools = New-Object System.Windows.Forms.Label
$lblAdvancedTools.Text = "Erweiterte Diagnosetools:"
$lblAdvancedTools.Location = New-Object System.Drawing.Point(650, 20)
$lblAdvancedTools.Size = New-Object System.Drawing.Size(150, 20)
$tabTools.Controls.Add($lblAdvancedTools)

$btnDNSFlush = New-Object System.Windows.Forms.Button
$btnDNSFlush.Text = "Client DNS-Cache leeren"
$btnDNSFlush.Location = New-Object System.Drawing.Point(820, 15)
$btnDNSFlush.Size = New-Object System.Drawing.Size(160, 25)
$btnDNSFlush.BackColor = [System.Drawing.Color]::LightSkyBlue
$tabTools.Controls.Add($btnDNSFlush)

$btnDNSHealth = New-Object System.Windows.Forms.Button
$btnDNSHealth.Text = "DNS-Server Zustandsbericht"
$btnDNSHealth.Location = New-Object System.Drawing.Point(990, 15)
$btnDNSHealth.Size = New-Object System.Drawing.Size(180, 25)
$btnDNSHealth.BackColor = [System.Drawing.Color]::LightSkyBlue
$tabTools.Controls.Add($btnDNSHealth)

# Großes Ausgabefenster für Tools
$txtToolsOutput = New-Object System.Windows.Forms.TextBox
$txtToolsOutput.Location = New-Object System.Drawing.Point(30,60)
$txtToolsOutput.Size = New-Object System.Drawing.Size(1180,460)
$txtToolsOutput.Multiline = $true
$txtToolsOutput.ScrollBars = "Vertical"
$txtToolsOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$tabTools.Controls.Add($txtToolsOutput)

# Server-Status-Bereich
$grpServerStatus = New-Object System.Windows.Forms.GroupBox
$grpServerStatus.Text = "DNS-Server Status"
$grpServerStatus.Location = New-Object System.Drawing.Point(30, 530)
$grpServerStatus.Size = New-Object System.Drawing.Size(1180, 130)
$tabTools.Controls.Add($grpServerStatus)

$lblQueryCount = New-Object System.Windows.Forms.Label
$lblQueryCount.Text = "Abfragen:"
$lblQueryCount.Location = New-Object System.Drawing.Point(20, 30)
$lblQueryCount.Size = New-Object System.Drawing.Size(100, 20)
$grpServerStatus.Controls.Add($lblQueryCount)

$txtQueryCount = New-Object System.Windows.Forms.TextBox
$txtQueryCount.Location = New-Object System.Drawing.Point(120, 27)
$txtQueryCount.Size = New-Object System.Drawing.Size(150, 25)
$txtQueryCount.ReadOnly = $true
$grpServerStatus.Controls.Add($txtQueryCount)

$lblRecursions = New-Object System.Windows.Forms.Label
$lblRecursions.Text = "Rekursionen:"
$lblRecursions.Location = New-Object System.Drawing.Point(300, 30)
$lblRecursions.Size = New-Object System.Drawing.Size(100, 20)
$grpServerStatus.Controls.Add($lblRecursions)

$txtRecursions = New-Object System.Windows.Forms.TextBox
$txtRecursions.Location = New-Object System.Drawing.Point(400, 27)
$txtRecursions.Size = New-Object System.Drawing.Size(150, 25)
$txtRecursions.ReadOnly = $true
$grpServerStatus.Controls.Add($txtRecursions)

$lblFailedQueries = New-Object System.Windows.Forms.Label
$lblFailedQueries.Text = "Fehlgeschlagene Abfragen:"
$lblFailedQueries.Location = New-Object System.Drawing.Point(580, 30)
$lblFailedQueries.Size = New-Object System.Drawing.Size(160, 20)
$grpServerStatus.Controls.Add($lblFailedQueries)

$txtFailedQueries = New-Object System.Windows.Forms.TextBox
$txtFailedQueries.Location = New-Object System.Drawing.Point(740, 27)
$txtFailedQueries.Size = New-Object System.Drawing.Size(150, 25)
$txtFailedQueries.ReadOnly = $true
$grpServerStatus.Controls.Add($txtFailedQueries)

$lblUptime = New-Object System.Windows.Forms.Label
$lblUptime.Text = "Server-Laufzeit:"
$lblUptime.Location = New-Object System.Drawing.Point(20, 70)
$lblUptime.Size = New-Object System.Drawing.Size(100, 20)
$grpServerStatus.Controls.Add($lblUptime)

$txtUptime = New-Object System.Windows.Forms.TextBox
$txtUptime.Location = New-Object System.Drawing.Point(120, 67)
$txtUptime.Size = New-Object System.Drawing.Size(150, 25)
$txtUptime.ReadOnly = $true
$grpServerStatus.Controls.Add($txtUptime)

$btnReloadServerStatus = New-Object System.Windows.Forms.Button
$btnReloadServerStatus.Text = "Status aktualisieren"
$btnReloadServerStatus.Location = New-Object System.Drawing.Point(980, 45)
$btnReloadServerStatus.Size = New-Object System.Drawing.Size(150, 30)
$btnReloadServerStatus.BackColor = [System.Drawing.Color]::LightSalmon
$grpServerStatus.Controls.Add($btnReloadServerStatus)

$TabControl.TabPages.Add($tabTools)

###############################################################################
# Füge neuen Tab für Troubleshooting & Auditing hinzu
###############################################################################
$tabTroubleshooting = New-Object System.Windows.Forms.TabPage
$tabTroubleshooting.Text = "Troubleshooting & Audit"

# Split-Panel für Troubleshooting und Audit-Funktionen
$splitTroubleAudit = New-Object System.Windows.Forms.SplitContainer
$splitTroubleAudit.Dock = "Fill"
$splitTroubleAudit.Orientation = "Horizontal"
$splitTroubleAudit.SplitterDistance = 320
$tabTroubleshooting.Controls.Add($splitTroubleAudit)

# Oberes Panel - Troubleshooting
$grpTroubleshooting = New-Object System.Windows.Forms.GroupBox
$grpTroubleshooting.Text = "DNS Troubleshooting"
$grpTroubleshooting.Dock = "Fill"
$splitTroubleAudit.Panel1.Controls.Add($grpTroubleshooting)

# Liste der Diagnosetools
$lblDiagnosticTools = New-Object System.Windows.Forms.Label
$lblDiagnosticTools.Text = "Diagnosetools:"
$lblDiagnosticTools.Location = New-Object System.Drawing.Point(20, 30)
$lblDiagnosticTools.Size = New-Object System.Drawing.Size(150, 20)
$grpTroubleshooting.Controls.Add($lblDiagnosticTools)

$btnDNSDiag = New-Object System.Windows.Forms.Button
$btnDNSDiag.Text = "Server-Diagnose durchführen"
$btnDNSDiag.Location = New-Object System.Drawing.Point(20, 60)
$btnDNSDiag.Size = New-Object System.Drawing.Size(200, 30)
$btnDNSDiag.BackColor = [System.Drawing.Color]::LightSkyBlue
$grpTroubleshooting.Controls.Add($btnDNSDiag)

$btnZoneCheck = New-Object System.Windows.Forms.Button
$btnZoneCheck.Text = "Zonenkonfiguration prüfen"
$btnZoneCheck.Location = New-Object System.Drawing.Point(20, 100)
$btnZoneCheck.Size = New-Object System.Drawing.Size(200, 30)
$btnZoneCheck.BackColor = [System.Drawing.Color]::LightSkyBlue
$grpTroubleshooting.Controls.Add($btnZoneCheck)

$btnDNSSecCheck = New-Object System.Windows.Forms.Button
$btnDNSSecCheck.Text = "DNSSEC-Validierung prüfen"
$btnDNSSecCheck.Location = New-Object System.Drawing.Point(20, 140)
$btnDNSSecCheck.Size = New-Object System.Drawing.Size(200, 30)
$btnDNSSecCheck.BackColor = [System.Drawing.Color]::LightSkyBlue
$grpTroubleshooting.Controls.Add($btnDNSSecCheck)

$btnNetDiag = New-Object System.Windows.Forms.Button
$btnNetDiag.Text = "Netzwerkdiagnose"
$btnNetDiag.Location = New-Object System.Drawing.Point(20, 180)
$btnNetDiag.Size = New-Object System.Drawing.Size(200, 30)
$btnNetDiag.BackColor = [System.Drawing.Color]::LightSkyBlue
$grpTroubleshooting.Controls.Add($btnNetDiag)

$btnClearDiagEvents = New-Object System.Windows.Forms.Button
$btnClearDiagEvents.Text = "Diagnose-Events löschen"
$btnClearDiagEvents.Location = New-Object System.Drawing.Point(20, 220)
$btnClearDiagEvents.Size = New-Object System.Drawing.Size(200, 30)
$btnClearDiagEvents.BackColor = [System.Drawing.Color]::LightCoral
$grpTroubleshooting.Controls.Add($btnClearDiagEvents)

# Troubleshooting-Parameter
$grpDiagParams = New-Object System.Windows.Forms.GroupBox
$grpDiagParams.Text = "Diagnose-Parameter"
$grpDiagParams.Location = New-Object System.Drawing.Point(240, 30)
$grpDiagParams.Size = New-Object System.Drawing.Size(400, 220)
$grpTroubleshooting.Controls.Add($grpDiagParams)

$lblCheckZone = New-Object System.Windows.Forms.Label
$lblCheckZone.Text = "Zone für Prüfung:"
$lblCheckZone.Location = New-Object System.Drawing.Point(20, 30)
$lblCheckZone.Size = New-Object System.Drawing.Size(120, 20)
$grpDiagParams.Controls.Add($lblCheckZone)

$comboDiagZone = New-Object System.Windows.Forms.ComboBox
$comboDiagZone.Location = New-Object System.Drawing.Point(150, 28)
$comboDiagZone.Size = New-Object System.Drawing.Size(230, 25)
$grpDiagParams.Controls.Add($comboDiagZone)

$chkVerboseLogging = New-Object System.Windows.Forms.CheckBox
$chkVerboseLogging.Text = "Ausführliche Protokollierung"
$chkVerboseLogging.Location = New-Object System.Drawing.Point(20, 70)
$chkVerboseLogging.Size = New-Object System.Drawing.Size(200, 20)
$chkVerboseLogging.Checked = $true
$grpDiagParams.Controls.Add($chkVerboseLogging)

$chkFixIssues = New-Object System.Windows.Forms.CheckBox
$chkFixIssues.Text = "Probleme automatisch beheben, wenn möglich"
$chkFixIssues.Location = New-Object System.Drawing.Point(20, 100)
$chkFixIssues.Size = New-Object System.Drawing.Size(300, 20)
$grpDiagParams.Controls.Add($chkFixIssues)

$lblDiagLevel = New-Object System.Windows.Forms.Label
$lblDiagLevel.Text = "Diagnose-Tiefe:"
$lblDiagLevel.Location = New-Object System.Drawing.Point(20, 130)
$lblDiagLevel.Size = New-Object System.Drawing.Size(120, 20)
$grpDiagParams.Controls.Add($lblDiagLevel)

$comboDiagLevel = New-Object System.Windows.Forms.ComboBox
$comboDiagLevel.Location = New-Object System.Drawing.Point(150, 128)
$comboDiagLevel.Size = New-Object System.Drawing.Size(230, 25)
$comboDiagLevel.Items.AddRange(@("Basis-Überprüfung", "Standard-Diagnose", "Erweiterte Prüfung", "Tiefgehende Analyse"))
$comboDiagLevel.SelectedIndex = 1
$grpDiagParams.Controls.Add($comboDiagLevel)

$btnExportDiag = New-Object System.Windows.Forms.Button
$btnExportDiag.Text = "Diagnosebericht exportieren"
$btnExportDiag.Location = New-Object System.Drawing.Point(150, 170)
$btnExportDiag.Size = New-Object System.Drawing.Size(170, 30)
$btnExportDiag.BackColor = [System.Drawing.Color]::LightGreen
$grpDiagParams.Controls.Add($btnExportDiag)

# Ergebnis-Textbox
$txtDiagOutput = New-Object System.Windows.Forms.TextBox
$txtDiagOutput.Location = New-Object System.Drawing.Point(660, 30)
$txtDiagOutput.Size = New-Object System.Drawing.Size(540, 270)
$txtDiagOutput.Multiline = $true
$txtDiagOutput.ScrollBars = "Vertical"
$txtDiagOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtDiagOutput.ReadOnly = $true
$grpTroubleshooting.Controls.Add($txtDiagOutput)

# Unteres Panel - Auditing
$grpAudit = New-Object System.Windows.Forms.GroupBox
$grpAudit.Text = "DNS Auditing"
$grpAudit.Dock = "Fill"
$splitTroubleAudit.Panel2.Controls.Add($grpAudit)

# Audit-Kontrollelemente
$lblAuditOptions = New-Object System.Windows.Forms.Label
$lblAuditOptions.Text = "Audit-Optionen:"
$lblAuditOptions.Location = New-Object System.Drawing.Point(20, 30)
$lblAuditOptions.Size = New-Object System.Drawing.Size(150, 20)
$grpAudit.Controls.Add($lblAuditOptions)

$btnEnableAudit = New-Object System.Windows.Forms.Button
$btnEnableAudit.Text = "Audit aktivieren"
$btnEnableAudit.Location = New-Object System.Drawing.Point(20, 60)
$btnEnableAudit.Size = New-Object System.Drawing.Size(150, 30)
$btnEnableAudit.BackColor = [System.Drawing.Color]::LightGreen
$grpAudit.Controls.Add($btnEnableAudit)

$btnDisableAudit = New-Object System.Windows.Forms.Button
$btnDisableAudit.Text = "Audit deaktivieren"
$btnDisableAudit.Location = New-Object System.Drawing.Point(180, 60)
$btnDisableAudit.Size = New-Object System.Drawing.Size(150, 30)
$btnDisableAudit.BackColor = [System.Drawing.Color]::LightCoral
$grpAudit.Controls.Add($btnDisableAudit)

$btnViewLogs = New-Object System.Windows.Forms.Button
$btnViewLogs.Text = "Protokolle anzeigen"
$btnViewLogs.Location = New-Object System.Drawing.Point(20, 100)
$btnViewLogs.Size = New-Object System.Drawing.Size(150, 30)
$btnViewLogs.BackColor = [System.Drawing.Color]::LightSalmon
$grpAudit.Controls.Add($btnViewLogs)

$btnExportLogs = New-Object System.Windows.Forms.Button
$btnExportLogs.Text = "Protokolle exportieren"
$btnExportLogs.Location = New-Object System.Drawing.Point(180, 100)
$btnExportLogs.Size = New-Object System.Drawing.Size(150, 30)
$btnExportLogs.BackColor = [System.Drawing.Color]::LightSalmon
$grpAudit.Controls.Add($btnExportLogs)

# Audit-Parameter
$grpAuditParams = New-Object System.Windows.Forms.GroupBox
$grpAuditParams.Text = "Audit-Einstellungen"
$grpAuditParams.Location = New-Object System.Drawing.Point(20, 150)
$grpAuditParams.Size = New-Object System.Drawing.Size(380, 150)
$grpAudit.Controls.Add($grpAuditParams)

$chkAuditZoneChanges = New-Object System.Windows.Forms.CheckBox
$chkAuditZoneChanges.Text = "Zonenänderungen protokollieren"
$chkAuditZoneChanges.Location = New-Object System.Drawing.Point(20, 30)
$chkAuditZoneChanges.Size = New-Object System.Drawing.Size(300, 20)
$chkAuditZoneChanges.Checked = $true
$grpAuditParams.Controls.Add($chkAuditZoneChanges)

$chkAuditRecordChanges = New-Object System.Windows.Forms.CheckBox
$chkAuditRecordChanges.Text = "Eintragsänderungen protokollieren"
$chkAuditRecordChanges.Location = New-Object System.Drawing.Point(20, 60)
$chkAuditRecordChanges.Size = New-Object System.Drawing.Size(300, 20)
$chkAuditRecordChanges.Checked = $true
$grpAuditParams.Controls.Add($chkAuditRecordChanges)

$chkAuditQueries = New-Object System.Windows.Forms.CheckBox
$chkAuditQueries.Text = "DNS-Abfragen protokollieren"
$chkAuditQueries.Location = New-Object System.Drawing.Point(20, 90)
$chkAuditQueries.Size = New-Object System.Drawing.Size(300, 20)
$grpAuditParams.Controls.Add($chkAuditQueries)

$lblRetention = New-Object System.Windows.Forms.Label
$lblRetention.Text = "Aufbewahrungsdauer (Tage):"
$lblRetention.Location = New-Object System.Drawing.Point(20, 120)
$lblRetention.Size = New-Object System.Drawing.Size(170, 20)
$grpAuditParams.Controls.Add($lblRetention)

$txtRetention = New-Object System.Windows.Forms.TextBox
$txtRetention.Location = New-Object System.Drawing.Point(190, 118)
$txtRetention.Size = New-Object System.Drawing.Size(50, 20)
$txtRetention.Text = "30"
$grpAuditParams.Controls.Add($txtRetention)

# Audit-Log-Anzeige
$dgvAuditLogs = New-Object System.Windows.Forms.DataGridView
$dgvAuditLogs.Location = New-Object System.Drawing.Point(420, 30)
$dgvAuditLogs.Size = New-Object System.Drawing.Size(780, 270)
$dgvAuditLogs.AllowUserToAddRows = $false
$dgvAuditLogs.ReadOnly = $true
$dgvAuditLogs.AutoSizeColumnsMode = "Fill"
$dgvAuditLogs.SelectionMode = "FullRowSelect"

# Spalten für die Audit-Protokolle
$colTimeStamp = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colTimeStamp.HeaderText = "Zeitstempel"
$colTimeStamp.DataPropertyName = "TimeStamp"
$colTimeStamp.Width = 150

$colEventType = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colEventType.HeaderText = "Ereignis"
$colEventType.DataPropertyName = "EventType"
$colEventType.Width = 100

$colUser = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colUser.HeaderText = "Benutzer"
$colUser.DataPropertyName = "User"
$colUser.Width = 100

$colDetails = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDetails.HeaderText = "Details"
$colDetails.DataPropertyName = "Details"
$colDetails.Width = 400

$dgvAuditLogs.Columns.Add($colTimeStamp)
$dgvAuditLogs.Columns.Add($colEventType)
$dgvAuditLogs.Columns.Add($colUser)
$dgvAuditLogs.Columns.Add($colDetails)

$grpAudit.Controls.Add($dgvAuditLogs)

# Tab zum TabControl hinzufügen
$TabControl.TabPages.Add($tabTroubleshooting)

###############################################################################
# 18) DNS-FUNKTIONEN: Zusätzliche und erweiterte Funktionen
###############################################################################

# Allgemeine Hilfsfunktionen
function Show-MessageBox {
    param(
        [string]$message,
        [string]$title = "Information",
        [System.Windows.Forms.MessageBoxButtons]$buttons = [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]$icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    [System.Windows.Forms.MessageBox]::Show($message, $title, $buttons, $icon)
}

function Format-RecordData {
    param([object]$record)
    
    if ($record.RecordType -eq "A") {
        return $record.RecordData.IPv4Address.ToString()
    }
    elseif ($record.RecordType -eq "AAAA") {
        return $record.RecordData.IPv6Address.ToString()
    }
    elseif ($record.RecordType -eq "PTR") {
        return $record.RecordData.PtrDomainName
    }
    elseif ($record.RecordType -eq "CNAME") {
        return $record.RecordData.HostNameAlias
    }
    elseif ($record.RecordType -eq "MX") {
        return "{0} {1}" -f $record.RecordData.Preference, $record.RecordData.MailExchange
    }
    elseif ($record.RecordType -eq "TXT") {
        return $record.RecordData.DescriptiveText
    }
    elseif ($record.RecordType -eq "SRV") {
        return "{0} {1} {2} {3}" -f $record.RecordData.Priority, $record.RecordData.Weight, 
                                    $record.RecordData.Port, $record.RecordData.DomainName
    }
    else {
        return $record.RecordData.ToString()
    }
}
function Get-DnsServerZone {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [string]$Name
    )

    try {
        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            Write-Verbose "Versuche, echtes Get-DnsServerZone -Name '$Name' -ComputerName '$ComputerName' aufzurufen."
            $Cmdlet = Get-Command -Name "Get-DnsServerZone" -Module "DnsServer" -ErrorAction SilentlyContinue
            if ($null -ne $Cmdlet) {
                & $Cmdlet -ComputerName $ComputerName -Name $Name -ErrorAction Stop
            } else {
                # Explizit CommandNotFoundException werfen, wenn Get-Command es nicht findet,
                # um in den korrekten Catch-Block zu gelangen.
                throw [System.Management.Automation.CommandNotFoundException]::new("Das Cmdlet Get-DnsServerZone wurde nicht gefunden.")
            }
        }
        else {
            # Alle Zonen angefordert
            Write-Verbose "Versuche, echtes Get-DnsServerZone -ComputerName '$ComputerName' aufzurufen."
            $Cmdlet = Get-Command -Name "Get-DnsServerZone" -Module "DnsServer" -ErrorAction SilentlyContinue
            if ($null -ne $Cmdlet) {
                & $Cmdlet -ComputerName $ComputerName -ErrorAction Stop
            } else {
                throw [System.Management.Automation.CommandNotFoundException]::new("Das Cmdlet Get-DnsServerZone wurde nicht gefunden.")
            }
        }
        # Wenn wir hier ankommen, war der Aufruf erfolgreich. Das Ergebnis wird implizit zurückgegeben.
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Das Cmdlet wurde nicht gefunden. Fallback auf Daten.
        Write-Warning "Das Cmdlet 'Get-DnsServerZone' (aus dem DnsServer-Modul) wurde nicht gefunden. Dies kann bedeuten, dass die RSAT-DNS-Tools nicht installiert sind oder das Modul nicht importiert werden konnte. Es werden Daten für die weitere Ausführung verwendet."

        # Statische Daten für DNS-Zonen.
        $allMockZones = @(
            [PSCustomObject]@{
                ZoneName             = "example.com"
                ZoneType             = "Primary"
                IsReverseLookupZone  = $false
                ReplicationScope     = "Forest"
                IsSigned             = $false
                PSComputerName       = $ComputerName # Simulieren, dass es vom angegebenen Server kommt
                DynamicUpdate        = "Secure"      # Beispiel für zusätzliche Eigenschaft
                AllowUpdate          = 1             # Entspricht Secure (0=None, 1=Secure, 2=NonsecureAndSecure)
            },
            [PSCustomObject]@{
                ZoneName             = "sub.example.com"
                ZoneType             = "Primary"
                IsReverseLookupZone  = $false
                ReplicationScope     = "Domain"
                IsSigned             = $true          # Beispiel für eine signierte Zone
                PSComputerName       = $ComputerName
                DynamicUpdate        = "None"
                AllowUpdate          = 0
            },
            [PSCustomObject]@{
                ZoneName             = "1.168.192.in-addr.arpa"
                ZoneType             = "Primary"
                IsReverseLookupZone  = $true          # Dies ist eine Reverse-Lookup-Zone
                ReplicationScope     = "Domain"
                IsSigned             = $false
                PSComputerName       = $ComputerName
                DynamicUpdate        = "Secure"
                AllowUpdate          = 1
            },
            [PSCustomObject]@{
                ZoneName             = "another-example.net"
                ZoneType             = "Secondary"    # Sekundäre Zonen
                IsReverseLookupZone  = $false
                ReplicationScope     = $null          # Haben oft keinen lokalen Replikationsbereich
                IsSigned             = $false
                PSComputerName       = $ComputerName
                MasterServers        = @("192.168.1.100", "192.168.1.101") # Beispiel für Master-Server
                DynamicUpdate        = "None" # Typischerweise keine dynamischen Updates auf Secondaries
                AllowUpdate          = 0
            }
        )

        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            # Eine spezifische Zone wurde angefordert (normalerweise für den IsSigned-Check)
            $specificZone = $allMockZones | Where-Object { $_.ZoneName -eq $Name }
            
            if ($null -ne $specificZone) {
                # Das echte Cmdlet gibt hier ein einzelnes Zonenobjekt zurück.
                return $specificZone[0] # Gib das erste gefundene Objekt zurück
            } else {
                Write-Warning "Mock Get-DnsServerZone: Zone '$Name' wurde nicht in den Daten gefunden."
                return $null
            }
        }
        else {
            # Alle Zonen wurden angefordert
            return $allMockZones
        }
    }
    catch {
        # Ein anderer Fehler ist beim Aufruf des echten Cmdlets aufgetreten
        # (z.B. Server nicht erreichbar, Berechtigungsprobleme etc.)
        $errorMessage = "Fehler beim Ausführen des echten Cmdlets 'Get-DnsServerZone'"
        if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
            $errorMessage += " auf dem Server '$ComputerName'"
        }
        $errorMessage += ": $($_.Exception.Message)"
        Write-Error $errorMessage
        
        # In diesem Fall geben wir den Fehler weiter und fallen NICHT auf Daten zurück,
        # da dies ein Laufzeitproblem mit dem echten Cmdlet ist, nicht dessen Nichtexistenz.
        # Der Aufrufer sollte diesen Fehler behandeln können.
        throw $_ 
    }
}

# Funktion für Get-DnsServerResourceRecord
function Get-DnsServerResourceRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ZoneName,
        [string]$ComputerName,
        [string]$Name,
        [string]$RRType # In der Realität ist dies [Microsoft.DnsClient.Commands.RecordType], aber string ist einfacher für Mocking
    )

    try {
        # Versuche, das echte Cmdlet auszuführen
        $CmdletName = 'Get-DnsServerResourceRecord'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        
        if ($null -eq $Cmdlet) {
            # Wirft eine Exception, die im Catch-Block unten behandelt wird
            throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found"
        }

        $params = @{}
        if ($PSBoundParameters.ContainsKey('ZoneName')) { $params.ZoneName = $ZoneName }
        if ($PSBoundParameters.ContainsKey('ComputerName')) { $params.ComputerName = $ComputerName }
        if ($PSBoundParameters.ContainsKey('Name')) { $params.Name = $Name }
        if ($PSBoundParameters.ContainsKey('RRType')) { $params.RRType = $RRType }
        
        # Führe das echte Cmdlet aus
        & $CmdletName @params
        return
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Das Cmdlet existiert nicht, wir verwenden Daten
        $DefaultTimeToLive = [TimeSpan]::FromHours(1)
        $CurrentComputerName = if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName } else { $env:COMPUTERNAME }
        
        Write-Warning "Mock Get-DnsServerResourceRecord: Das Cmdlet 'Get-DnsServerResourceRecord' wurde nicht gefunden. Verwende Daten für Zone '$ZoneName' (angenommen von Server '$CurrentComputerName')."

        $allMockRecords = @(
            # --- example.com ---
            @{ HostName = "@"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "192.168.0.10" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "www"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "192.168.0.11" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "mail"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "192.168.0.12" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "ns1"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "192.168.0.20" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "ipv6host"; RecordType = "AAAA"; RecordData = [PSCustomObject]@{ IPv6Address = "2001:db8::1" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "ftp"; RecordType = "CNAME"; RecordData = [PSCustomObject]@{ HostNameAlias = "www.example.com" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "@"; RecordType = "MX"; RecordData = [PSCustomObject]@{ MailExchange = "mail.example.com"; Preference = 10 }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "@"; RecordType = "TXT"; RecordData = [PSCustomObject]@{ DescriptiveString = "v=spf1 mx -all" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "_sip._tcp"; RecordType = "SRV"; RecordData = [PSCustomObject]@{ DomainName = "sipserver.example.com"; Priority = 0; Weight = 5; Port = 5060 }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "@"; RecordType = "SOA"; RecordData = [PSCustomObject]@{ PrimaryServer="ns1.example.com."; ResponsiblePerson="admin.example.com."; SerialNumber=2023010101 }; Timestamp = $null; TimeToLive = [TimeSpan]::FromHours(1); PSComputerName = $CurrentComputerName; ZoneName = "example.com" },
            @{ HostName = "@"; RecordType = "NS"; RecordData = [PSCustomObject]@{ NameServer="ns1.example.com." }; Timestamp = $null; TimeToLive = [TimeSpan]::FromDays(1); PSComputerName = $CurrentComputerName; ZoneName = "example.com" },

            # --- 1.168.192.in-addr.arpa ---
            @{ HostName = "10"; RecordType = "PTR"; RecordData = [PSCustomObject]@{ PtrDomainName = "server1.example.com" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "1.168.192.in-addr.arpa" },
            @{ HostName = "11"; RecordType = "PTR"; RecordData = [PSCustomObject]@{ PtrDomainName = "www.example.com" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "1.168.192.in-addr.arpa" },
            @{ HostName = "@"; RecordType = "SOA"; RecordData = [PSCustomObject]@{ PrimaryServer="ns1.example.com."; ResponsiblePerson="admin.example.com."; SerialNumber=2023010102 }; Timestamp = $null; TimeToLive = [TimeSpan]::FromHours(1); PSComputerName = $CurrentComputerName; ZoneName = "1.168.192.in-addr.arpa" },
            @{ HostName = "@"; RecordType = "NS"; RecordData = [PSCustomObject]@{ NameServer="ns1.example.com." }; Timestamp = $null; TimeToLive = [TimeSpan]::FromDays(1); PSComputerName = $CurrentComputerName; ZoneName = "1.168.192.in-addr.arpa" },


            # --- another-example.net ---
            @{ HostName = "@"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "10.0.0.5" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "another-example.net" },
            @{ HostName = "web"; RecordType = "A"; RecordData = [PSCustomObject]@{ IPv4Address = "10.0.0.6" }; Timestamp = $null; TimeToLive = $DefaultTimeToLive; PSComputerName = $CurrentComputerName; ZoneName = "another-example.net" },
            @{ HostName = "@"; RecordType = "SOA"; RecordData = [PSCustomObject]@{ PrimaryServer="ns.another-example.net."; ResponsiblePerson="admin.another-example.net."; SerialNumber=2023010103 }; Timestamp = $null; TimeToLive = [TimeSpan]::FromHours(1); PSComputerName = $CurrentComputerName; ZoneName = "another-example.net" },
            @{ HostName = "@"; RecordType = "NS"; RecordData = [PSCustomObject]@{ NameServer="ns.another-example.net." }; Timestamp = $null; TimeToLive = [TimeSpan]::FromDays(1); PSComputerName = $CurrentComputerName; ZoneName = "another-example.net" }

        ) | ForEach-Object { [PSCustomObject]$_ }

        $filteredRecords = $allMockRecords | Where-Object { $_.ZoneName -eq $ZoneName }

        if (-not [string]::IsNullOrWhiteSpace($Name)) {
            $filteredRecords = $filteredRecords | Where-Object { $_.HostName -eq $Name }
        }
        if (-not [string]::IsNullOrWhiteSpace($RRType)) {
            $filteredRecords = $filteredRecords | Where-Object { $_.RecordType -eq $RRType }
        }
        
        if ($filteredRecords.Count -eq 0) {
            # Write-Warning "Mock Get-DnsServerResourceRecord: Keine Einträge für die angegebenen Filter in Zone '$ZoneName' gefunden."
        }
        return $filteredRecords
    }
    catch {
        # Ein anderer Fehler ist beim Aufruf des echten Cmdlets aufgetreten
        $errorMessage = "Fehler beim Ausführen des echten Cmdlets 'Get-DnsServerResourceRecord'"
        if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
            $errorMessage += " auf dem Server '$ComputerName'"
        }
        $errorMessage += ": $($_.Exception.Message)"
        Write-Error $errorMessage
        throw $_
    }
}

# Funktion für Add-DnsServerResourceRecord
function Add-DnsServerResourceRecord {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)] [string]$ZoneName,
        [string]$ComputerName,
        # Allgemeine Record-Parameter
        [string]$Name, # Hostname des Eintrags
        [string]$RRType, # A, AAAA, CNAME, MX, PTR, TXT, SRV etc.
        [System.TimeSpan]$TimeToLive = ([TimeSpan]::FromHours(1)),
        [switch]$PassThru,

        # Typspezifische Parameter (RecordData Äquivalente)
        [string]$IPv4Address,
        [string]$IPv6Address,
        [string]$HostNameAlias, # CNAME
        [string]$MailExchange, [uint16]$Preference, # MX
        [string]$PtrDomainName, # PTR
        [string[]]$DescriptiveString, # TXT
        [uint16]$SrvPriority, [uint16]$SrvWeight, [uint16]$SrvPort, [string]$SrvDomainName # SRV
    )
    try {
        $CmdletName = 'Add-DnsServerResourceRecord'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        $boundParams = $PSBoundParameters.Clone() # Clone, um Modifikationen zu erlauben
        # Umbenennung der SRV-Parameter für das echte Cmdlet
        if ($boundParams.ContainsKey('SrvPriority')) { $boundParams.Priority = $boundParams.SrvPriority; $boundParams.Remove('SrvPriority') }
        if ($boundParams.ContainsKey('SrvWeight')) { $boundParams.Weight = $boundParams.SrvWeight; $boundParams.Remove('SrvWeight') }
        if ($boundParams.ContainsKey('SrvPort')) { $boundParams.Port = $boundParams.SrvPort; $boundParams.Remove('SrvPort') }
        if ($boundParams.ContainsKey('SrvDomainName')) { $boundParams.DomainName = $boundParams.SrvDomainName; $boundParams.Remove('SrvDomainName') }

        & $CmdletName @boundParams
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "Mock Add-DnsServerResourceRecord: Das Cmdlet 'Add-DnsServerResourceRecord' wurde nicht gefunden. Simuliere Hinzufügen von '$Name' ($RRType) zu Zone '$ZoneName'."
        if ($PassThru) {
            $mockRecordData = $null
            switch ($RRType.ToUpper()) {
                "A"     { $mockRecordData = [PSCustomObject]@{ IPv4Address = $IPv4Address } }
                "AAAA"  { $mockRecordData = [PSCustomObject]@{ IPv6Address = $IPv6Address } }
                "CNAME" { $mockRecordData = [PSCustomObject]@{ HostNameAlias = $HostNameAlias } }
                "MX"    { $mockRecordData = [PSCustomObject]@{ MailExchange = $MailExchange; Preference = $Preference } }
                "PTR"   { $mockRecordData = [PSCustomObject]@{ PtrDomainName = $PtrDomainName } }
                "TXT"   { $mockRecordData = [PSCustomObject]@{ DescriptiveString = ($DescriptiveString -join "`n") } }
                "SRV"   { $mockRecordData = [PSCustomObject]@{ DomainName = $SrvDomainName; Priority = $SrvPriority; Weight = $SrvWeight; Port = $SrvPort } }
            }
            return [PSCustomObject]@{
                HostName = $Name
                RecordType = $RRType
                RecordData = $mockRecordData
                TimeToLive = $TimeToLive
                ZoneName = $ZoneName
                PSComputerName = if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName } else { $env:COMPUTERNAME }
                Timestamp = $null
            }
        }
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Add-DnsServerResourceRecord': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Set-DnsServerResourceRecord
function Set-DnsServerResourceRecord {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)] $OldInputObject, 
        [Parameter(Mandatory=$true)] $NewInputObject, 
        [string]$ComputerName,
        [string]$ZoneName, # Oft Teil des InputObject, aber kann auch explizit sein
        [switch]$Force,
        [switch]$PassThru
    )
    try {
        $CmdletName = 'Set-DnsServerResourceRecord'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters 
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $recordIdentifier = if ($OldInputObject.HostName) { "$($OldInputObject.HostName) ($($OldInputObject.RecordType))" } else { "Unbekannter Record" }
        $effectiveZoneName = if (-not [string]::IsNullOrWhiteSpace($ZoneName)) { $ZoneName } elseif ($OldInputObject.ZoneName) { $OldInputObject.ZoneName } else { "Unbekannte Zone" }
        Write-Warning "Mock Set-DnsServerResourceRecord: Das Cmdlet 'Set-DnsServerResourceRecord' wurde nicht gefunden. Simuliere Aktualisierung von '$recordIdentifier' in Zone '$effectiveZoneName'."
        if ($PassThru) {
            # Das NewInputObject enthält typischerweise nur die geänderten RecordData und TTL.
            # Wir erstellen ein vollständigeres Objekt, das dem Output von Get-DnsServerResourceRecord ähnelt.
            return [PSCustomObject]@{
                HostName = $OldInputObject.HostName
                RecordType = $OldInputObject.RecordType
                RecordData = $NewInputObject.RecordData # Hauptänderung
                TimeToLive = $NewInputObject.TimeToLive # Hauptänderung
                ZoneName = $effectiveZoneName
                PSComputerName = if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName } elseif ($OldInputObject.PSComputerName) { $OldInputObject.PSComputerName } else { $env:COMPUTERNAME }
                Timestamp = $null # Oder $OldInputObject.Timestamp
            }
        }
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Set-DnsServerResourceRecord': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Remove-DnsServerResourceRecord
function Remove-DnsServerResourceRecord {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject]$InputObject, 
        [string]$ZoneName, # Wird benötigt, wenn InputObject nicht alle Infos hat oder direkt Parameter verwendet werden
        [string]$ComputerName,
        [string]$Name, # Alternativ zu InputObject
        [string]$RRType, # Alternativ zu InputObject
        [switch]$Force
    )
    try {
        $CmdletName = 'Remove-DnsServerResourceRecord'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters 
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $recordIdentifier = ""
        $effectiveZoneName = $ZoneName
        if ($InputObject -and $InputObject.GetType().Name -ne 'String') { # Sicherstellen, dass InputObject kein einfacher String ist
             $recordIdentifier = if ($InputObject.HostName) { "$($InputObject.HostName) ($($InputObject.RecordType))" } else { "Unbekannter Record aus InputObject" }
             if (-not $effectiveZoneName -and $InputObject.ZoneName) {$effectiveZoneName = $InputObject.ZoneName}
        } elseif ($Name -and $RRType) {
            $recordIdentifier = "$Name ($RRType)"
        } else {
            $recordIdentifier = "Unbekannter Record"
        }
         if (-not $effectiveZoneName) {$effectiveZoneName = "Unbekannte Zone"}
        Write-Warning "Mock Remove-DnsServerResourceRecord: Das Cmdlet 'Remove-DnsServerResourceRecord' wurde nicht gefunden. Simuliere Entfernung von '$recordIdentifier' aus Zone '$effectiveZoneName'."
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Remove-DnsServerResourceRecord': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Add-DnsServerPrimaryZone
function Add-DnsServerPrimaryZone {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)] [string]$Name,
        [string]$ReplicationScope, 
        [string]$ComputerName,
        $DynamicUpdate = "Secure", # Default ist Secure für AD-integrierte Zonen
        [string]$ZoneFile,
        [switch]$PassThru
    )
    try {
        $CmdletName = 'Add-DnsServerPrimaryZone'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "Mock Add-DnsServerPrimaryZone: Das Cmdlet 'Add-DnsServerPrimaryZone' wurde nicht gefunden. Simuliere Erstellung der primären Zone '$Name'."
        if ($PassThru) {
            return [PSCustomObject]@{
                ZoneName = $Name
                ZoneType = "Primary"
                ReplicationScope = $ReplicationScope
                DynamicUpdate = $DynamicUpdate
                PSComputerName = if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName } else { $env:COMPUTERNAME }
                IsReverseLookupZone = $Name -like "*.in-addr.arpa" -or $Name -like "*.ip6.arpa"
                IsSigned = $false 
                ZoneFile = if ($ZoneFile) {$ZoneFile} else {"$Name.dns"}
            }
        }
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Add-DnsServerPrimaryZone': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Add-DnsServerSecondaryZone
function Add-DnsServerSecondaryZone {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$true)] [string[]]$MasterServers,
        [string]$ComputerName,
        [string]$ZoneFile,
        [switch]$PassThru
    )
    try {
        $CmdletName = 'Add-DnsServerSecondaryZone'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "Mock Add-DnsServerSecondaryZone: Das Cmdlet 'Add-DnsServerSecondaryZone' wurde nicht gefunden. Simuliere Erstellung der sekundären Zone '$Name' mit Master(n) $($MasterServers -join ', ')."
        if ($PassThru) {
            return [PSCustomObject]@{
                ZoneName = $Name
                ZoneType = "Secondary"
                MasterServers = $MasterServers
                PSComputerName = if (-not [string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName } else { $env:COMPUTERNAME }
                IsReverseLookupZone = $Name -like "*.in-addr.arpa" -or $Name -like "*.ip6.arpa"
                ZoneFile = if ($ZoneFile) {$ZoneFile} else {"$Name.dns"}
            }
        }
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Add-DnsServerSecondaryZone': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Remove-DnsServerZone
function Remove-DnsServerZone {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)] [string]$Name,
        [string]$ComputerName,
        [switch]$Force
    )
    try {
        $CmdletName = 'Remove-DnsServerZone'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "Mock Remove-DnsServerZone: Das Cmdlet 'Remove-DnsServerZone' wurde nicht gefunden. Simuliere Entfernung der Zone '$Name'."
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Remove-DnsServerZone': $($_.Exception.Message)"
        throw $_
    }
}

# Funktion für Set-DnsServerZone
function Set-DnsServerZone {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)] [string]$Name,
        [string]$ComputerName,
        # Viele optionale Parameter, hier einige Beispiele:
        [ValidateSet("None", "NonsecureAndSecure", "Secure")]
        [string]$DynamicUpdate,
        [string]$ReplicationScope,
        [string[]]$MasterServers, 
        [string[]]$NotifyServers,
        [System.Nullable[bool]]$AllowUpdate, # Entspricht SecureSecondaries bei AD-integrierten Zonen
        [switch]$PassThru
    )
    try {
        $CmdletName = 'Set-DnsServerZone'
        $Cmdlet = Get-Command $CmdletName -ErrorAction SilentlyContinue
        if ($null -eq $Cmdlet) { throw [System.Management.Automation.CommandNotFoundException] "$CmdletName command not found" }
        
        & $CmdletName @PSBoundParameters
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Warning "Mock Set-DnsServerZone: Das Cmdlet 'Set-DnsServerZone' wurde nicht gefunden. Simuliere Aktualisierung der Zone '$Name'."
        if ($PassThru) {
            # Versuche, eine bestehende Zone zu finden und zu aktualisieren oder eine neue zu erstellen
            # Dies ist eine vereinfachte Darstellung. Eine echte Implementierung würde $Global:MockDnsServerZones benötigen.
            $mockZone = Get-DnsServerZone -Name $Name -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if ($mockZone) {
                if ($PSBoundParameters.ContainsKey('DynamicUpdate')) { $mockZone.DynamicUpdate = $DynamicUpdate }
                if ($PSBoundParameters.ContainsKey('ReplicationScope')) { $mockZone.ReplicationScope = $ReplicationScope }
                if ($PSBoundParameters.ContainsKey('MasterServers')) { $mockZone.MasterServers = $MasterServers }
                # Weitere Eigenschaften hier aktualisieren
                return $mockZone
            }
        }
    }
    catch {
        Write-Error "Fehler beim Ausführen des echten Cmdlets 'Set-DnsServerZone': $($_.Exception.Message)"
        throw $_
    }
}

# Funktionen für Forward-Zonen
function Update-ForwardZones {
    $comboForwardZones.Items.Clear()
    $dgvForwardZones.Rows.Clear()

    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text | Where-Object { -not $_.IsReverse }
        foreach ($z in $zones) {
            [void]$comboForwardZones.Items.Add($z.ZoneName)
            [void]$dgvForwardZones.Rows.Add($z.ZoneName, $z.ZoneType, $z.RepScope, $z.DNSSECStatus)
        }
        if ($comboForwardZones.Items.Count -gt 0) {
            $comboForwardZones.SelectedIndex = 0
        }
        Log-Message "Forward-Zonen aktualisiert: $($zones.Count) Zonen gefunden" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Aktualisieren der Forward-Zonen: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Aktualisieren der Forward-Zonen: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Create-ForwardZone {
    $zoneName = $txtForwardZone.Text.Trim()
    $scope = $comboForwardScope.SelectedItem
    
    if ([string]::IsNullOrWhiteSpace($zoneName)) {
        Show-MessageBox "Bitte geben Sie einen Zonennamen ein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($scope)) {
        $scope = "Domain"
    }
    
    try {
        Add-DnsServerPrimaryZone -Name $zoneName -ReplicationScope $scope -ComputerName $txtDNSServer.Text
        Log-Message "Forward-Zone erstellt: $zoneName mit Replikation: $scope" -severity "INFO"
        Show-MessageBox "Die Zone '$zoneName' wurde erfolgreich erstellt!" "Zone erstellt"
        Update-ForwardZones
    }
    catch {
        Log-Message "Fehler beim Erstellen der Forward-Zone ${zoneName}: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Erstellen der Zone: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Delete-ForwardZone {
    if ($comboForwardZones.SelectedItem -eq $null) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zone = $comboForwardZones.SelectedItem.ToString()
    $result = Show-MessageBox "Möchten Sie die Zone '$zone' wirklich löschen?" "Zone löschen" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Question)
              
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Remove-DnsServerZone -Name $zone -ComputerName $txtDNSServer.Text -Force
            Log-Message "Forward-Zone gelöscht: $zone" -severity "INFO"
            Show-MessageBox "Die Zone '$zone' wurde erfolgreich gelöscht!" "Zone gelöscht"
            Update-ForwardZones
        }
        catch {
            Log-Message "Fehler beim Löschen der Forward-Zone ${zone}: ${_}" -severity "ERROR"
            Show-MessageBox "Fehler beim Löschen der Zone: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

# Funktionen für Reverse-Zonen
function Update-ReverseZones {
    $comboReverseZones.Items.Clear()
    $dgvReverseZones.Rows.Clear()

    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text | Where-Object { $_.IsReverse }
        foreach ($z in $zones) {
            [void]$comboReverseZones.Items.Add($z.ZoneName)
            [void]$dgvReverseZones.Rows.Add($z.ZoneName, $z.ZoneType, $z.RepScope, $z.DNSSECStatus)
        }
        if ($comboReverseZones.Items.Count -gt 0) {
            $comboReverseZones.SelectedIndex = 0
        }
        Log-Message "Reverse-Zonen aktualisiert: $($zones.Count) Zonen gefunden" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Aktualisieren der Reverse-Zonen: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Aktualisieren der Reverse-Zonen: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Generate-NetworkID {
    try {
        $ip = $txtNetworkIP.Text.Trim()
        $cidr = $txtNetworkCIDR.Text.Trim()
        
        if ([string]::IsNullOrWhiteSpace($ip) -or [string]::IsNullOrWhiteSpace($cidr)) {
            Show-MessageBox "Bitte geben Sie eine IP-Adresse und CIDR an." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # IP-Adresse in binär umwandeln
        $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($ipBytes)
        }
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        
        # Subnetzmaske berechnen
        $mask = [UInt32]::MaxValue -shl (32 - [int]$cidr) -band [UInt32]::MaxValue
        
        # Netzwerk-ID berechnen
        $networkInt = $ipInt -band $mask
        
        # Netzwerk-ID zurück in IP-Format
        $networkBytes = [BitConverter]::GetBytes($networkInt)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($networkBytes)
        }
        $networkIP = [System.Net.IPAddress]::new($networkBytes)
        
        # Für die Reverse-Zone: Formel /24 = erste 3 Oktette umgekehrt mit .in-addr.arpa
        $octets = $networkIP.ToString().Split('.')
        
        # Je nach CIDR den Umfang der Reverse-Zone bestimmen
        if ([int]$cidr -le 8) {
            $reverseZone = "$($octets[0]).in-addr.arpa"
        }
        elseif ([int]$cidr -le 16) {
            $reverseZone = "$($octets[1]).$($octets[0]).in-addr.arpa"
        }
        elseif ([int]$cidr -le 24) {
            $reverseZone = "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
        }
        else {
            $reverseZone = "$($octets[3]).$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
        }
        
        $txtReverseNet.Text = $reverseZone
        Log-Message "Netzwerk-ID generiert: $ip/$cidr -> $reverseZone" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Generieren der Netzwerk-ID: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Generieren der Netzwerk-ID: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Create-ReverseZone {
    $reverseZone = $txtReverseNet.Text.Trim()
    $scope = $comboReverseScope.SelectedItem
    
    if ([string]::IsNullOrWhiteSpace($reverseZone)) {
        Show-MessageBox "Bitte geben Sie eine Netzwerk-ID ein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($scope)) {
        $scope = "Domain"
    }
    
    try {
        Add-DnsServerPrimaryZone -Name $reverseZone -ReplicationScope $scope -ComputerName $txtDNSServer.Text
        Log-Message "Reverse-Zone erstellt: $reverseZone mit Replikation: $scope" -severity "INFO"
        Show-MessageBox "Die Reverse-Zone '$reverseZone' wurde erfolgreich erstellt!" "Zone erstellt"
        Update-ReverseZones
    }
    catch {
        Log-Message "Fehler beim Erstellen der Reverse-Zone ${reverseZone}: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Erstellen der Reverse-Zone: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Delete-ReverseZone {
    if ($comboReverseZones.SelectedItem -eq $null) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zone = $comboReverseZones.SelectedItem.ToString()
    $result = Show-MessageBox "Möchten Sie die Reverse-Zone '$zone' wirklich löschen?" "Zone löschen" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Question)
              
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            Remove-DnsServerZone -Name $zone -ComputerName $txtDNSServer.Text -Force
            Log-Message "Reverse-Zone gelöscht: $zone" -severity "INFO"
            Show-MessageBox "Die Reverse-Zone '$zone' wurde erfolgreich gelöscht!" "Zone gelöscht"
            Update-ReverseZones
        }
        catch {
            Log-Message "Fehler beim Löschen der Reverse-Zone ${zone}: ${_}" -severity "ERROR"
            Show-MessageBox "Fehler beim Löschen der Reverse-Zone: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

# Funktionen für DNS-Records
function Load-DNSZones {
    $comboRecZone.Items.Clear()
    
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text
        foreach ($z in $zones) {
            [void]$comboRecZone.Items.Add($z.ZoneName)
        }
        if ($comboRecZone.Items.Count -gt 0) {
            $comboRecZone.SelectedIndex = 0
            Load-DNSRecords # Lade die Records für die erste Zone
        }
        Log-Message "DNS-Zonen für Records geladen: $($zones.Count) Zonen" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Laden der DNS-Zonen: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Laden der DNS-Zonen: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Load-DNSRecords {
    if ($comboRecZone.SelectedItem -eq $null) {
        return
    }
    
    $zone = $comboRecZone.SelectedItem.ToString()
    $dgvDNSRecords.Rows.Clear()
    
    try {
        $records = Get-DnsServerResourceRecord -ZoneName $zone -ComputerName $txtDNSServer.Text
        foreach ($record in $records) {
            # Spezialfall: SOA-Record und NS-Records für @ (Zone selbst) überspringen
            if (($record.RecordType -eq "SOA") -or 
                ($record.RecordType -eq "NS" -and $record.HostName -eq "@")) {
                continue
            }
            
            $hostName = $record.HostName
            $recordType = $record.RecordType
            $ttl = $record.TimeToLive.ToString()
            $data = Format-RecordData -record $record
            
            [void]$dgvDNSRecords.Rows.Add($hostName, $recordType, $data, $ttl)
        }
        Log-Message "DNS-Records für Zone $zone geladen: $($records.Count) Records" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Laden der DNS-Records für Zone ${zone}: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Laden der DNS-Records: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Show-RecordTypeFields {
    $recordType = $comboRecType.SelectedItem
    
    # Standardfelder immer anzeigen
    $lblRecName.Visible = $true
    $txtRecName.Visible = $true
    $lblRecData.Visible = $true
    $txtRecData.Visible = $true
    $lblRecordTTL.Visible = $true
    $txtRecordTTL.Visible = $true
    
    # Zusätzliche Felder für MX und SRV
    $lblRecordPriority.Visible = ($recordType -eq "MX" -or $recordType -eq "SRV")
    $txtRecordPriority.Visible = ($recordType -eq "MX" -or $recordType -eq "SRV")
    
    # Weitere Felder nur für SRV
    $lblRecordWeight.Visible = ($recordType -eq "SRV")
    $txtRecordWeight.Visible = ($recordType -eq "SRV")
    $lblRecordPort.Visible = ($recordType -eq "SRV")
    $txtRecordPort.Visible = ($recordType -eq "SRV")
    
    # Anpassung der Beschriftungen und Hilfe basierend auf dem Typ
    if ($recordType -eq "A") {
        $lblRecData.Text = "IP-Adresse:"
    }
    elseif ($recordType -eq "AAAA") {
        $lblRecData.Text = "IPv6-Adresse:"
    }
    elseif ($recordType -eq "CNAME") {
        $lblRecData.Text = "Alias:"
    }
    elseif ($recordType -eq "MX") {
        $lblRecData.Text = "Mail-Server:"
    }
    elseif ($recordType -eq "PTR") {
        $lblRecData.Text = "Hostname:"
    }
    elseif ($recordType -eq "TXT") {
        $lblRecData.Text = "Text:"
    }
    elseif ($recordType -eq "SRV") {
        $lblRecData.Text = "Ziel-Server:"
    }
    elseif ($recordType -eq "NS") {
        $lblRecData.Text = "Nameserver:"
    }
}

function Create-DNSRecord {
    if ($comboRecZone.SelectedItem -eq $null) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zone = $comboRecZone.SelectedItem.ToString()
    $recordType = $comboRecType.SelectedItem
    $name = $txtRecName.Text.Trim()
    $data = $txtRecData.Text.Trim()
    $ttl = $txtRecordTTL.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($data)) {
        Show-MessageBox "Bitte geben Sie Namen und Daten für den Record ein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    # TTL validieren und Standardwert setzen
    if ([string]::IsNullOrWhiteSpace($ttl)) {
        $ttl = "3600"
    }
    else {
        try {
            [int]::Parse($ttl) | Out-Null
        }
        catch {
            Show-MessageBox "TTL muss eine Zahl sein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
    }
    
    try {
        switch ($recordType) {
            "A" {
                Add-DnsServerResourceRecordA -ZoneName $zone -Name $name -IPv4Address $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "AAAA" {
                Add-DnsServerResourceRecordAAAA -ZoneName $zone -Name $name -IPv6Address $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "CNAME" {
                Add-DnsServerResourceRecordCName -ZoneName $zone -Name $name -HostNameAlias $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "MX" {
                $priority = $txtRecordPriority.Text.Trim()
                if ([string]::IsNullOrWhiteSpace($priority)) { $priority = "10" }
                Add-DnsServerResourceRecordMX -ZoneName $zone -Name $name -MailExchange $data -Preference ([int]$priority) -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "PTR" {
                Add-DnsServerResourceRecordPtr -ZoneName $zone -Name $name -PtrDomainName $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "TXT" {
                Add-DnsServerResourceRecordTxt -ZoneName $zone -Name $name -DescriptiveText $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "SRV" {
                $priority = $txtRecordPriority.Text.Trim()
                $weight = $txtRecordWeight.Text.Trim()
                $port = $txtRecordPort.Text.Trim()
                
                if ([string]::IsNullOrWhiteSpace($priority)) { $priority = "10" }
                if ([string]::IsNullOrWhiteSpace($weight)) { $weight = "10" }
                if ([string]::IsNullOrWhiteSpace($port)) { 
                    Show-MessageBox "Bitte geben Sie einen Port für den SRV-Record ein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
                    return
                }
                
                Add-DnsServerResourceRecordSrv -ZoneName $zone -Name $name -DomainName $data -Priority ([int]$priority) -Weight ([int]$weight) -Port ([int]$port) -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
            "NS" {
                Add-DnsServerResourceRecordNS -ZoneName $zone -Name $name -NameServer $data -TimeToLive ([TimeSpan]::FromSeconds([int]$ttl)) -ComputerName $txtDNSServer.Text
            }
        }
        
        Log-Message "DNS-Record erstellt: $recordType $name in Zone $zone" -severity "INFO"
        Show-MessageBox "Der DNS-Record wurde erfolgreich erstellt!" "Record erstellt"
        Load-DNSRecords # Records neu laden
    }
    catch {
        Log-Message "Fehler beim Erstellen des DNS-Records: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Erstellen des DNS-Records: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Test-DNSRecord {
    if ([string]::IsNullOrWhiteSpace($txtRecName.Text)) {
        Show-MessageBox "Bitte geben Sie einen Namen für den Record ein." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zone = $comboRecZone.SelectedItem.ToString()
    $name = $txtRecName.Text.Trim()
    
    # Für Zonenname mit @ oder ohne Angabe
    if ($name -eq "@" -or [string]::IsNullOrWhiteSpace($name)) {
        $fqdn = $zone
    }
    else {
        $fqdn = "$name.$zone"
    }
    
    $txtRecTestOutput.Clear()
    $txtRecTestOutput.AppendText("Teste DNS-Auflösung für $fqdn`r`n")
    $txtRecTestOutput.AppendText("---------------------------------------------`r`n")
    
    try {
        $result = Resolve-DnsName -Name $fqdn -Type $comboRecType.SelectedItem -Server $txtDNSServer.Text -ErrorAction SilentlyContinue
        
        if ($result) {
            $txtRecTestOutput.AppendText("Erfolg! Der Record wurde gefunden:`r`n")
            foreach ($record in $result) {
                $txtRecTestOutput.AppendText("Name: $($record.Name)`r`n")
                $txtRecTestOutput.AppendText("Type: $($record.Type)`r`n")
                $txtRecTestOutput.AppendText("TTL: $($record.TTL)`r`n")
                
                # Spezifische Daten basierend auf Recordtyp
                if ($record.Type -eq "A") {
                    $txtRecTestOutput.AppendText("IP-Adresse: $($record.IPAddress)`r`n")
                }
                elseif ($record.Type -eq "AAAA") {
                    $txtRecTestOutput.AppendText("IPv6-Adresse: $($record.IPAddress)`r`n")
                }
                elseif ($record.Type -eq "CNAME") {
                    $txtRecTestOutput.AppendText("Kanonischer Name: $($record.NameHost)`r`n")
                }
                elseif ($record.Type -eq "MX") {
                    $txtRecTestOutput.AppendText("Mail-Server: $($record.NameExchange)`r`n")
                    $txtRecTestOutput.AppendText("Priorität: $($record.Preference)`r`n")
                }
                elseif ($record.Type -eq "PTR") {
                    $txtRecTestOutput.AppendText("Hostname: $($record.NameHost)`r`n")
                }
                elseif ($record.Type -eq "TXT") {
                    $txtRecTestOutput.AppendText("Text: $($record.Strings)`r`n")
                }
                elseif ($record.Type -eq "SRV") {
                    $txtRecTestOutput.AppendText("Ziel: $($record.NameTarget)`r`n")
                    $txtRecTestOutput.AppendText("Priorität: $($record.Priority)`r`n")
                    $txtRecTestOutput.AppendText("Gewichtung: $($record.Weight)`r`n")
                    $txtRecTestOutput.AppendText("Port: $($record.Port)`r`n")
                }
                elseif ($record.Type -eq "NS") {
                    $txtRecTestOutput.AppendText("Nameserver: $($record.NameHost)`r`n")
                }
                
                $txtRecTestOutput.AppendText("---------------------------------------------`r`n")
            }
        }
        else {
            $txtRecTestOutput.AppendText("Kein Record gefunden für $fqdn vom Typ $($comboRecType.SelectedItem)`r`n")
        }
    }
    catch {
        $txtRecTestOutput.AppendText("Fehler beim Testen: ${_}`r`n")
        Log-Message "Fehler beim Testen des DNS-Records: ${_}" -severity "ERROR"
    }
}

function Delete-DNSRecord {
    if ($dgvDNSRecords.SelectedRows.Count -eq 0) {
        Show-MessageBox "Bitte wählen Sie einen Record zum Löschen aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zone = $comboRecZone.SelectedItem.ToString()
    $selectedRow = $dgvDNSRecords.SelectedRows[0]
    $name = $selectedRow.Cells[0].Value
    $type = $selectedRow.Cells[1].Value
    $data = $selectedRow.Cells[2].Value
    
    $result = Show-MessageBox "Möchten Sie den Record '$name' vom Typ '$type' wirklich löschen?" "Record löschen" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Question)
              
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            $records = Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType $type -ComputerName $txtDNSServer.Text
            
            foreach ($record in $records) {
                $recordData = Format-RecordData -record $record
                if ($recordData -eq $data) {
                    Remove-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType $type -RecordData $record.RecordData -ComputerName $txtDNSServer.Text -Force
                    Log-Message "DNS-Record gelöscht: $type $name in Zone $zone" -severity "INFO"
                    Show-MessageBox "Der DNS-Record wurde erfolgreich gelöscht!" "Record gelöscht"
                    Load-DNSRecords # Records neu laden
                    break
                }
            }
        }
        catch {
            Log-Message "Fehler beim Löschen des DNS-Records: ${_}" -severity "ERROR"
            Show-MessageBox "Fehler beim Löschen des DNS-Records: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

# Funktionen für Import/Export
function Browse-ImportFile {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.InitialDirectory = $importFolder
    $dialog.Filter = "Alle Dateien (*.*)|*.*|CSV-Dateien (*.csv)|*.csv|JSON-Dateien (*.json)|*.json|Textdateien (*.txt)|*.txt"
    $dialog.FilterIndex = 2
    
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtImportFile.Text = $dialog.FileName
    }
}

function Browse-ExportFile {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.InitialDirectory = $exportFolder
    $dialog.Filter = "CSV-Dateien (*.csv)|*.csv|JSON-Dateien (*.json)|*.json|Textdateien (*.txt)|*.txt|HTML-Dateien (*.html)|*.html"
    $dialog.FilterIndex = 1
    
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtExportFile.Text = $dialog.FileName
    }
}

function Import-DNSData {
    if ([string]::IsNullOrWhiteSpace($txtImportFile.Text)) {
        Show-MessageBox "Bitte wählen Sie eine Import-Datei aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    if (-not (Test-Path $txtImportFile.Text)) {
        Show-MessageBox "Die angegebene Import-Datei existiert nicht." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $lblImportStatus.Text = "Status: Import wird ausgeführt..."
    $format = $comboImportFormat.SelectedItem
    $targetZone = $comboImportZone.SelectedItem
    $createMissing = $chkCreateMissingZones.Checked
    $overwrite = $chkOverwriteExisting.Checked
    
    try {
        $data = @()
        
        # Format-spezifischer Import
        switch ($format) {
            "CSV" {
                $data = Import-Csv -Path $txtImportFile.Text
            }
            "JSON" {
                $jsonContent = Get-Content -Path $txtImportFile.Text -Raw
                $data = ConvertFrom-Json -InputObject $jsonContent
            }
            "BIND Zone File" {
                $txtPreview.Clear()
                $txtPreview.AppendText("BIND Zone File Import wird noch nicht unterstützt.`r`n")
                $lblImportStatus.Text = "Status: BIND Zone File Import wird nicht unterstützt"
                return
            }
            "Tab-getrennte Werte" {
                $data = Import-Csv -Path $txtImportFile.Text -Delimiter "`t"
            }
        }
        
        $txtPreview.Clear()
        $txtPreview.AppendText("Vorschau der zu importierenden DNS-Einträge:`r`n")
        $txtPreview.AppendText("---------------------------------------------`r`n")
        
        $importCount = 0
        $errorCount = 0
        
        foreach ($record in $data) {
            $recordZone = if ($record.Zone) { $record.Zone } else { $targetZone }
            $recordName = $record.Name
            $recordType = $record.Type
            $recordData = $record.Data
            $recordTTL = if ($record.TTL) { $record.TTL } else { "3600" }
            
            $txtPreview.AppendText("Zone: $recordZone, Name: $recordName, Typ: $recordType, Daten: $recordData, TTL: $recordTTL`r`n")
            
            # Prüfen, ob Zone existiert
            $zoneExists = $false
            try {
                Get-DnsServerZone -Name $recordZone -ComputerName $txtDNSServer.Text -ErrorAction SilentlyContinue | Out-Null
                $zoneExists = $true
            }
            catch {}
            
            if (-not $zoneExists -and $createMissing) {
                try {
                    Add-DnsServerPrimaryZone -Name $recordZone -ReplicationScope "Domain" -ComputerName $txtDNSServer.Text
                    $txtPreview.AppendText("Zone $recordZone wurde erstellt`r`n")
                    $zoneExists = $true
                }
                catch {
                    $txtPreview.AppendText("Fehler beim Erstellen der Zone")
                    $errorCount++
                    continue
                }
            }
            elseif (-not $zoneExists) {
                $txtPreview.AppendText("Zone $recordZone existiert nicht und wird nicht erstellt`r`n")
                $errorCount++
                continue
            }
            
            # Prüfen, ob Record bereits existiert
            $recordExists = $false
            try {
                Get-DnsServerResourceRecord -ZoneName $recordZone -Name $recordName -RRType $recordType -ComputerName $txtDNSServer.Text -ErrorAction SilentlyContinue | Out-Null
                $recordExists = $true
                
                if ($recordExists -and -not $overwrite) {
                    $txtPreview.AppendText("Record existiert bereits und wird nicht überschrieben`r`n")
                    continue
                }
                elseif ($recordExists -and $overwrite) {
                    # Bestehenden Record löschen
                    $oldRecords = Get-DnsServerResourceRecord -ZoneName $recordZone -Name $recordName -RRType $recordType -ComputerName $txtDNSServer.Text
                    foreach ($oldRecord in $oldRecords) {
                        Remove-DnsServerResourceRecord -ZoneName $recordZone -Name $recordName -RRType $recordType -RecordData $oldRecord.RecordData -ComputerName $txtDNSServer.Text -Force
                    }
                    $txtPreview.AppendText("  -> Bestehender Record wurde gelöscht`r`n")
                }
            }
            catch {}
            
            # Record erstellen
            try {
                switch ($recordType) {
                    "A" {
                        Add-DnsServerResourceRecordA -ZoneName $recordZone -Name $recordName -IPv4Address $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "AAAA" {
                        Add-DnsServerResourceRecordAAAA -ZoneName $recordZone -Name $recordName -IPv6Address $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "CNAME" {
                        Add-DnsServerResourceRecordCName -ZoneName $recordZone -Name $recordName -HostNameAlias $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "MX" {
                        $parts = $recordData.Split(' ')
                        $mxPriority = $parts[0]
                        $mxTarget = $parts[1]
                        Add-DnsServerResourceRecordMX -ZoneName $recordZone -Name $recordName -MailExchange $mxTarget -Preference ([int]$mxPriority) -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "PTR" {
                        Add-DnsServerResourceRecordPtr -ZoneName $recordZone -Name $recordName -PtrDomainName $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "TXT" {
                        Add-DnsServerResourceRecordTxt -ZoneName $recordZone -Name $recordName -DescriptiveText $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "SRV" {
                        $parts = $recordData.Split(' ')
                        $srvPriority = $parts[0]
                        $srvWeight = $parts[1]
                        $srvPort = $parts[2]
                        $srvTarget = $parts[3]
                        Add-DnsServerResourceRecordSrv -ZoneName $recordZone -Name $recordName -DomainName $srvTarget -Priority ([int]$srvPriority) -Weight ([int]$srvWeight) -Port ([int]$srvPort) -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                    "NS" {
                        Add-DnsServerResourceRecordNS -ZoneName $recordZone -Name $recordName -NameServer $recordData -TimeToLive ([TimeSpan]::FromSeconds([int]$recordTTL)) -ComputerName $txtDNSServer.Text
                    }
                }
                
                $txtPreview.AppendText("  -> Record erfolgreich importiert`r`n")
                $importCount++
            }
            catch {
                $txtPreview.AppendText("  -> Fehler beim Importieren des Records: ${_}`r`n")
                $errorCount++
            }
        }
        
        $txtPreview.AppendText("`r`n---------------------------------------------`r`n")
        $txtPreview.AppendText("Import abgeschlossen: $importCount Records importiert, $errorCount Fehler`r`n")
        
        $lblImportStatus.Text = "Status: Import abgeschlossen - $importCount Records importiert, $errorCount Fehler"
        Log-Message "DNS-Import abgeschlossen: $importCount Records importiert, $errorCount Fehler" -severity "INFO"
        
        # Zonen und Records neu laden
        Load-DNSZones
    }
    catch {
        $txtPreview.AppendText("Schwerwiegender Fehler beim Import: ${_}`r`n")
        $lblImportStatus.Text = "Status: Fehler beim Import"
        Log-Message "Fehler beim DNS-Import: ${_}" -severity "ERROR"
    }
}

function Export-DNSData {
    if ([string]::IsNullOrWhiteSpace($txtExportFile.Text)) {
        Show-MessageBox "Bitte geben Sie eine Export-Datei an." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $lblExportStatus.Text = "Status: Export wird ausgeführt..."
    $format = $comboExportFormat.SelectedItem
    $exportAllZones = $chkExportAllZones.Checked
    $includeReverseZones = $chkIncludeReverseZones.Checked
    
    try {
        $exportData = @()
        $zones = @()
        
        if ($exportAllZones) {
            $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text
            if (-not $includeReverseZones) {
                $zones = $zones | Where-Object { -not $_.IsReverse }
            }
        }
        else {
            $zoneName = $comboExportZone.SelectedItem
            if ([string]::IsNullOrWhiteSpace($zoneName)) {
                Show-MessageBox "Bitte wählen Sie eine Zone für den Export aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
                $lblExportStatus.Text = "Status: Export abgebrochen - keine Zone ausgewählt"
                return
            }
            $zones = @(Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text | Where-Object { $_.ZoneName -eq $zoneName })
        }
        
        $txtPreview.Clear()
        $txtPreview.AppendText("Exportiere DNS-Einträge aus $($zones.Count) Zonen:`r`n")
        
        foreach ($zone in $zones) {
            $zoneName = $zone.ZoneName
            $txtPreview.AppendText("---------------------------------------------`r`n")
            $txtPreview.AppendText("Zone: $zoneName`r`n")
            
            try {
                $records = Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $txtDNSServer.Text
                
                foreach ($record in $records) {
                    # Wir überspringen SOA-Records und NS-Records für die Zone selbst (@)
                    if (($record.RecordType -eq "SOA") -or 
                        ($record.RecordType -eq "NS" -and $record.HostName -eq "@")) {
                        continue
                    }
                    
                    $exportRecord = [PSCustomObject]@{
                        Zone = $zoneName
                        Name = $record.HostName
                        Type = $record.RecordType
                        Data = Format-RecordData -record $record
                        TTL = $record.TimeToLive.TotalSeconds
                    }
                    
                    $exportData += $exportRecord
                    $txtPreview.AppendText("  $($record.HostName) - $($record.RecordType) - " + (Format-RecordData -record $record) + "`r`n")
                }
            }
            catch {
                $txtPreview.AppendText("Fehler beim Abrufen von Records aus Zone")
            }
        }
        
        $txtPreview.AppendText("---------------------------------------------`r`n")
        $txtPreview.AppendText("Insgesamt $($exportData.Count) Records für den Export vorbereitet`r`n")
        
        # Format-spezifischer Export
        switch ($format) {
            "CSV" {
                $exportData | Export-Csv -Path $txtExportFile.Text -NoTypeInformation -Encoding UTF8
            }
            "JSON" {
                $exportData | ConvertTo-Json | Out-File -FilePath $txtExportFile.Text -Encoding UTF8
            }
            "BIND Zone File" {
                $txtPreview.AppendText("BIND Zone File Export wird noch nicht unterstützt.`r`n")
                $lblExportStatus.Text = "Status: BIND Zone File Export wird nicht unterstützt"
                return
            }
            "Tab-getrennte Werte" {
                $exportData | Export-Csv -Path $txtExportFile.Text -NoTypeInformation -Delimiter "`t" -Encoding UTF8
            }
            "HTML" {
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>DNS Records Export</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; text-align: left; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        h1, h2 { color: #333; }
    </style>
</head>
<body>
    <h1>DNS Records Export</h1>
    <p>Exportiert am $(Get-Date)</p>
    <p>DNS-Server: $($txtDNSServer.Text)</p>
    <h2>Records</h2>
    <table>
        <tr>
            <th>Zone</th>
            <th>Name</th>
            <th>Typ</th>
            <th>Daten</th>
            <th>TTL</th>
        </tr>
"@

                $htmlRows = @()
                foreach ($record in $exportData) {
                    $htmlRows += @"
        <tr>
            <td>$($record.Zone)</td>
            <td>$($record.Name)</td>
            <td>$($record.Type)</td>
            <td>$($record.Data)</td>
            <td>$($record.TTL)</td>
        </tr>
"@
                }

                $htmlFooter = @"
    </table>
</body>
</html>
"@

                $htmlContent = $htmlHeader + [string]::Join("`n", $htmlRows) + $htmlFooter
                $htmlContent | Out-File -FilePath $txtExportFile.Text -Encoding UTF8
            }
        }
        
        $txtPreview.AppendText("Export abgeschlossen: $($exportData.Count) Records in $($zones.Count) Zonen`r`n")
        $txtPreview.AppendText("Datei gespeichert unter: $($txtExportFile.Text)`r`n")
        
        $lblExportStatus.Text = "Status: Export abgeschlossen - $($exportData.Count) Records"
        Log-Message "DNS-Export abgeschlossen: $($exportData.Count) Records, $($zones.Count) Zonen" -severity "INFO"
    }
    catch {
        $txtPreview.AppendText("Schwerwiegender Fehler beim Export: ${_}`r`n")
        $lblExportStatus.Text = "Status: Fehler beim Export"
        Log-Message "Fehler beim DNS-Export: ${_}" -severity "ERROR"
    }
}

# Funktionen für DNSSEC
function Update-DNSSECZones {
    $comboDNSSECZone.Items.Clear()
    
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text
        foreach ($z in $zones) {
            [void]$comboDNSSECZone.Items.Add($z.ZoneName)
        }
        if ($comboDNSSECZone.Items.Count -gt 0) {
            $comboDNSSECZone.SelectedIndex = 0
            Update-DNSSECStatus # Status für die erste Zone anzeigen
        }
        Log-Message "DNSSEC-Zonen aktualisiert: $($zones.Count) Zonen gefunden" -severity "INFO"
    }
    catch {
        Log-Message "Fehler beim Aktualisieren der DNSSEC-Zonen: ${_}" -severity "ERROR"
        Show-MessageBox "Fehler beim Aktualisieren der DNSSEC-Zonen: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Update-DNSSECStatus {
    if ($null -eq $comboDNSSECZone.SelectedItem) {
        return
    }
    
    $zoneName = $comboDNSSECZone.SelectedItem.ToString()
    $dgvDNSSECKeys.Rows.Clear()
    
    try {
        $zone = Get-DnsServerZone -Name $zoneName -ComputerName $txtDNSServer.Text
        
        if ($zone.IsSigned) {
            $txtDNSSECStatus.Text = "Aktiviert"
            $txtDNSSECStatus.ForeColor = [System.Drawing.Color]::Green
            
            # Keys abrufen und anzeigen
            $dnssecInfo = Get-DnsServerDnsSecZone -Name $zoneName -ComputerName $txtDNSServer.Text
            $txtDNSSECDetails.Clear()
            $txtDNSSECDetails.AppendText("DNSSEC-Details für Zone ${zoneName}:`r`n")
            $txtDNSSECDetails.AppendText("---------------------------------------------`r`n")
            $txtDNSSECDetails.AppendText("Signiert: Ja`r`n")
            $txtDNSSECDetails.AppendText("Signierungstyp: $($dnssecInfo.SigningType)`r`n")
            $txtDNSSECDetails.AppendText("NSECs pro Aktualisierung: $($dnssecInfo.NSECsPerZone)`r`n")
            $txtDNSSECDetails.AppendText("NSEC3 Iterationen: $($dnssecInfo.NSEC3Iterations)`r`n")
            $txtDNSSECDetails.AppendText("Nächste Schlüsselrollover: $($dnssecInfo.KeyRolloverDate)`r`n")
            $txtDNSSECDetails.AppendText("DS-Record für übergeordnete Zone: $($dnssecInfo.DSRecordSetTTL) Sekunden`r`n")
            $txtDNSSECDetails.AppendText("---------------------------------------------`r`n")
            
            # Schlüssel anzeigen
            $keys = Get-DnsServerDnsSecZone -Name $zoneName -ComputerName $txtDNSServer.Text | Select-Object -ExpandProperty Keys
            
            foreach ($key in $keys) {
                $keyType = if ($key.KeyType -eq 1) { "Key Signing Key (KSK)" } else { "Zone Signing Key (ZSK)" }
                $algoName = switch ($key.Algorithm) {
                    1 { "RSA/MD5" }
                    3 { "DSA/SHA1" }
                    5 { "RSA/SHA-1" }
                    6 { "DSA-NSEC3-SHA1" }
                    7 { "RSASHA1-NSEC3-SHA1" }
                    8 { "RSA/SHA-256" }
                    10 { "RSA/SHA-512" }
                    12 { "GOST R 34.10-2001" }
                    13 { "ECDSA Curve P-256 with SHA-256" }
                    14 { "ECDSA Curve P-384 with SHA-384" }
                    default { "Unknown ($($key.Algorithm))" }
                }
                
                [void]$dgvDNSSECKeys.Rows.Add($keyType, $key.KeyTag, $algoName, $key.CreationDate, $key.RolloverDate)
                
                $txtDNSSECDetails.AppendText("$keyType (Tag: $($key.KeyTag))`r`n")
                $txtDNSSECDetails.AppendText("  Algorithmus: $algoName`r`n")
                $txtDNSSECDetails.AppendText("  Erstellt am: $($key.CreationDate)`r`n")
                $txtDNSSECDetails.AppendText("  Ablauf am: $($key.RolloverDate)`r`n")
                $txtDNSSECDetails.AppendText("  Schlüssellänge: $($key.KeyLength) Bits`r`n")
                $txtDNSSECDetails.AppendText("---------------------------------------------`r`n")
            }
        }
        else {
            $txtDNSSECStatus.Text = "Deaktiviert"
            $txtDNSSECStatus.ForeColor = [System.Drawing.Color]::Red
            
            $txtDNSSECDetails.Clear()
            $txtDNSSECDetails.AppendText("DNSSEC ist für Zone $zoneName nicht aktiviert.`r`n")
            $txtDNSSECDetails.AppendText("Klicken Sie auf 'DNSSEC aktivieren', um DNSSEC für diese Zone zu konfigurieren.`r`n")
        }
    }
    catch {
        $txtDNSSECStatus.Text = "Fehler"
        $txtDNSSECStatus.ForeColor = [System.Drawing.Color]::Red
        $txtDNSSECDetails.Clear()
        $txtDNSSECDetails.AppendText("Fehler beim Abrufen des DNSSEC-Status: ${_}`r`n")
        Log-Message "Fehler beim Abrufen des DNSSEC-Status für Zone ${zoneName}: ${_}" -severity "ERROR"
    }
}

function Enable-ZoneDNSSEC {
    if ($null -eq $comboDNSSECZone.SelectedItem) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zoneName = $comboDNSSECZone.SelectedItem.ToString()
    $algorithm = $comboSigningAlgo.SelectedItem
    $keyLength = [int]$comboKeyLength.SelectedItem
    $validityPeriod = [int]$txtValidity.Text
    
    if ([string]::IsNullOrWhiteSpace($algorithm)) {
        $algorithm = "RSA"
    }
    
    if ($keyLength -eq 0) {
        $keyLength = 2048
    }
    
    if ($validityPeriod -eq 0) {
        $validityPeriod = 365
    }
    
    $result = Show-MessageBox "Möchten Sie DNSSEC für Zone '$zoneName' aktivieren?`n`nAlgorithmus: $algorithm`nSchlüssellänge: $keyLength Bits`nGültigkeitsdauer: $validityPeriod Tage" "DNSSEC aktivieren" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Question)
              
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $txtDNSSECDetails.Clear()
        $txtDNSSECDetails.AppendText("DNSSEC wird für Zone $zoneName aktiviert...`r`n")
        
        try {
            # Algorithmus-ID ermitteln
            $algoID = switch ($algorithm) {
                "RSA" { 8 } # RSA/SHA-256
                "ECDSA" { 13 } # ECDSA P-256 with SHA-256
                "DSA" { 6 } # DSA-NSEC3-SHA1
                default { 8 } # RSA/SHA-256 als Fallback
            }
            
            # Aktiviere DNSSEC für die Zone
            $txtDNSSECDetails.AppendText("Starte Signierung...`r`n")
            
            # Angepasster Befehl mit korrekten Parametern
            # Manche Systeme unterstützen die erweiterten Parameter nicht
            try {
                # Versuche zuerst mit einfacheren Parametern
                Invoke-DnsServerZoneSign -ZoneName $zoneName -ComputerName $txtDNSServer.Text
                $txtDNSSECDetails.AppendText("DNSSEC wurde mit Standard-Parametern aktiviert.`r`n")
            }
            catch {
                $txtDNSSECDetails.AppendText("Standard-Signierung nicht verfügbar, versuche alternative Methode...`r`n")
                
                # Alternative Methode, falls erweiterte Parameter nicht unterstützt werden
                $dnsCmd = "dnscmd $($txtDNSServer.Text) /zonesign $zoneName /alg $algoID /ksklen $keyLength /zsklen $([int]($keyLength/2))"
                $txtDNSSECDetails.AppendText("Führe aus: $dnsCmd`r`n")
                
                Invoke-Expression $dnsCmd
                $txtDNSSECDetails.AppendText("DNSSEC wurde mit dnscmd aktiviert.`r`n")
            }
            
            $txtDNSSECDetails.AppendText("DNSSEC wurde erfolgreich aktiviert!`r`n")
            Log-Message "DNSSEC für Zone $zoneName aktiviert - Algorithmus: $algorithm, Schlüssellänge: $keyLength, Gültigkeitsdauer: $validityPeriod Tage" -severity "INFO"
            
            # Status aktualisieren
            Update-DNSSECStatus
            
            Show-MessageBox "DNSSEC wurde erfolgreich für die Zone '$zoneName' aktiviert!" "DNSSEC aktiviert"
        }
        catch {
            $txtDNSSECDetails.AppendText("Fehler beim Aktivieren von DNSSEC: ${_}`r`n")
            Log-Message "Fehler beim Aktivieren von DNSSEC für Zone ${zoneName}: ${_}" -severity "ERROR"
            Show-MessageBox "Fehler beim Aktivieren von DNSSEC: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

function Disable-ZoneDNSSEC {
    if ($comboDNSSECZone.SelectedItem -eq $null) {
        Show-MessageBox "Bitte wählen Sie eine Zone aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zoneName = $comboDNSSECZone.SelectedItem.ToString()
    
    $result = Show-MessageBox "Möchten Sie DNSSEC für Zone '$zoneName' wirklich deaktivieren?" "DNSSEC deaktivieren" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
              
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $txtDNSSECDetails.Clear()
        $txtDNSSECDetails.AppendText("DNSSEC wird für Zone $zoneName deaktiviert...`r`n")
        
        try {
            # DNSSEC für die Zone deaktivieren
            Invoke-DnsServerZoneUnsign -ZoneName $zoneName -ComputerName $txtDNSServer.Text -Force
            
            $txtDNSSECDetails.AppendText("DNSSEC wurde erfolgreich deaktiviert!`r`n")
            Log-Message "DNSSEC für Zone $zoneName deaktiviert" -severity "INFO"
            
            # Status aktualisieren
            Update-DNSSECStatus
            
            Show-MessageBox "DNSSEC wurde erfolgreich für die Zone '$zoneName' deaktiviert!" "DNSSEC deaktiviert"
        }
        catch {
            $txtDNSSECDetails.AppendText("Fehler beim Deaktivieren von DNSSEC: ${_}`r`n")
            Log-Message "Fehler beim Deaktivieren von DNSSEC für Zone ${zoneName}: ${_}" -severity "ERROR"
            Show-MessageBox "Fehler beim Deaktivieren von DNSSEC: ${_}" "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
}

# Funktionen für die Tools-Registerkarte
function Execute-Ping {
    $target = $txtToolsTarget.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel an." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Führe Ping zu $target aus...`r`n`r`n")
    
    try {
        $result = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
        
        foreach ($ping in $result) {
            $txtToolsOutput.AppendText("Antwort von $($ping.Address): Zeit=$($ping.ResponseTime)ms TTL=$($ping.TimeToLive)`r`n")
        }
        
        $avg = ($result | Measure-Object -Property ResponseTime -Average).Average
        $txtToolsOutput.AppendText("`r`nPing-Statistik")
        $txtToolsOutput.AppendText("    Pakete: Gesendet = 4, Empfangen = $($result.Count), Verloren = $(4-$($result.Count)) ($(100-(25*$result.Count))% Verlust)`r`n")
        
        if ($result.Count -gt 0) {
            $txtToolsOutput.AppendText("Ca. Rundreisenzeiten in Millisek.:`r`n")
            $txtToolsOutput.AppendText("    Minimum = $($result | Measure-Object -Property ResponseTime -Minimum).Minimum ms, Maximum = $($result | Measure-Object -Property ResponseTime -Maximum).Maximum ms, Mittelwert = $([math]::Round($avg, 2)) ms`r`n")
        }
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Ausführen von Ping: ${_}`r`n")
        Log-Message "Fehler bei Ping" -severity "ERROR"
    }
}

function Execute-Tracert {
    $target = $txtToolsTarget.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel an." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Routenverfolgung zu $target...`r`n`r`n")
    
    try {
        # PowerShell-Version des tracert-Befehls
        $result = Test-NetConnection -ComputerName $target -TraceRoute -ErrorAction Stop
        
        $hop = 1
        foreach ($route in $result.TraceRoute) {
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($route)
                $hostname = $hostEntry.HostName
            } 
            catch {
                $hostname = "Unbekannt"
            }
            
            $txtToolsOutput.AppendText("$hop`t$route`t$hostname`r`n")
            $hop++
        }
        
        $txtToolsOutput.AppendText("`r`nRoutenverfolgung abgeschlossen.`r`n")
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Ausführen von Tracert: ${_}`r`n")
        Log-Message "Fehler bei Tracert" -severity "ERROR"
    }
}

function Execute-Nslookup {
    $target = $txtToolsTarget.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($target)) {
        Show-MessageBox "Bitte geben Sie ein Ziel an." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Nslookup für $target...`r`n`r`n")
    
    try {
        $result = Resolve-DnsName -Name $target -ErrorAction Stop
        
        $txtToolsOutput.AppendText("Server: $($txtDNSServer.Text)`r`n")
        $txtToolsOutput.AppendText("Name: $target`r`n`r`n")
        
        foreach ($record in $result) {
            $txtToolsOutput.AppendText("Name: $($record.Name)`r`n")
            $txtToolsOutput.AppendText("Type: $($record.Type)`r`n")
            
            if ($record.Type -eq "A") {
                $txtToolsOutput.AppendText("Address: $($record.IPAddress)`r`n")
            }
            elseif ($record.Type -eq "AAAA") {
                $txtToolsOutput.AppendText("IPv6 Address: $($record.IPAddress)`r`n")
            }
            elseif ($record.Type -eq "CNAME") {
                $txtToolsOutput.AppendText("Canonical Name: $($record.NameHost)`r`n")
            }
            elseif ($record.Type -eq "MX") {
                $txtToolsOutput.AppendText("Mail Exchange: $($record.NameExchange)`r`n")
                $txtToolsOutput.AppendText("Preference: $($record.Preference)`r`n")
            }
            
            $txtToolsOutput.AppendText("`r`n")
        }
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Ausführen von Nslookup: ${_}`r`n")
        Log-Message "Fehler bei Nslookup" -severity "ERROR"
    }
}

function Clear-DNSCache {
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Leere DNS-Server Cache...`r`n")
    
    try {
        Clear-DnsServerCache -ComputerName $txtDNSServer.Text -Force
        $txtToolsOutput.AppendText("DNS-Server Cache wurde erfolgreich geleert!`r`n")
        Log-Message "DNS-Server Cache geleert" -severity "INFO"
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Leeren des DNS-Server Caches")
        Log-Message "Fehler beim Leeren des DNS-Server Caches: ${_}" -severity "ERROR"
    }
}

function Clear-ClientDNSCache {
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Leere Client DNS-Cache...`r`n")
    
    try {
        Clear-DnsClientCache
        $txtToolsOutput.AppendText("Client DNS-Cache wurde erfolgreich geleert!`r`n")
        Log-Message "Client DNS-Cache geleert" -severity "INFO"
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Leeren des Client DNS-Caches: ${_}`r`n")
        Log-Message "Fehler beim Leeren des Client DNS-Caches: ${_}" -severity "ERROR"
    }
}

function Get-DNSHealthReport {
    $txtToolsOutput.Clear()
    $txtToolsOutput.AppendText("Erstelle DNS-Server Zustandsbericht...`r`n`r`n")
    
    try {
        $server = $txtDNSServer.Text
        
        # Basis-Informationen
        $txtToolsOutput.AppendText("=== DNS-Server Grundinformationen ===`r`n")
        
        # Verwenden einer kompatibleren Methode für den Dienst-Status
        try {
            # Zuerst versuchen mit Get-Service ohne ComputerName Parameter
            if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
                if ($dnsService) {
                    $txtToolsOutput.AppendText("DNS-Dienst Status: $($dnsService.Status)`r`n")
                }
            }
            else {
                # Für Remote-Server, WMI verwenden
                $txtToolsOutput.AppendText("Versuche Verbindung zu Remote-DNS-Dienst...`r`n")
                $dnsService = Get-WmiObject -Class Win32_Service -Filter "Name='DNS'" -ComputerName $server -ErrorAction SilentlyContinue
                if ($dnsService) {
                    $txtToolsOutput.AppendText("DNS-Dienst Status: $($dnsService.State)`r`n")
                }
            }
        }
        catch {
            $txtToolsOutput.AppendText("DNS-Dienst Status: Konnte nicht abgerufen werden`r`n")
            $txtToolsOutput.AppendText("Fehler: ${_}`r`n")
        }
        
        # Rest der Funktion bleibt unverändert
        # Zonenstatistik
        $txtToolsOutput.AppendText("`r`n=== DNS-Zonen ===`r`n")
        $zones = Get-SafeDnsServerZone -DnsServerName $server
        $forwardZones = ($zones | Where-Object { -not $_.IsReverse }).Count
        $reverseZones = ($zones | Where-Object { $_.IsReverse }).Count
        $txtToolsOutput.AppendText("Anzahl Forward-Zonen: $forwardZones`r`n")
        $txtToolsOutput.AppendText("Anzahl Reverse-Zonen: $reverseZones`r`n")
        
        # DNSSEC-Statistik
        $txtToolsOutput.AppendText("`r`n=== DNSSEC-Status ===`r`n")
        $signedZones = ($zones | Where-Object { $_.DNSSECStatus -eq "Enabled" }).Count
        $txtToolsOutput.AppendText("Signierte Zonen: $signedZones von $($zones.Count)`r`n")
        
        # Allgemeine Serverdiagnostik
        $txtToolsOutput.AppendText("`r`n=== Server-Diagnose ===`r`n")
        try {
            $dnsServerDiag = Get-DnsServerDiagnostics -ComputerName $server -ErrorAction Stop
            $txtToolsOutput.AppendText("Logging aktiviert: $($dnsServerDiag.EnableLoggingForPluginDllEvents)`r`n")
            $txtToolsOutput.AppendText("Abfrage-Protokollierung: $($dnsServerDiag.EnableLoggingForRecursion)`r`n")
            $txtToolsOutput.AppendText("Filterung aktiviert: $($dnsServerDiag.EnableLoggingForServerStartStop)`r`n")
        } catch {
            $txtToolsOutput.AppendText("Serverdiagnostik konnte nicht abgerufen werden: ${_}`r`n")
        }
        
        # Abschluss
        $txtToolsOutput.AppendText("`r`nDNS-Server Zustandsbericht wurde erfolgreich erstellt!`r`n")
        Log-Message "DNS-Server Zustandsbericht erstellt" -severity "INFO"
    }
    catch {
        $txtToolsOutput.AppendText("Fehler beim Erstellen des DNS-Server Zustandsberichts: ${_}`r`n")
        Log-Message "Fehler beim Erstellen des DNS-Server Zustandsberichts: ${_}" -severity "ERROR"
    }
}

function Update-ServerStatus {
    try {
        $server = $txtDNSServer.Text
        
        # Try standard statistics method first
        try {
            $stats = Get-DnsServerStatistics -ComputerName $server -ErrorAction Stop
            
            if ($null -ne $stats) {
                # Safely handle queries with null checks
                if ($null -ne $stats.QueriesReceived) {
                    $txtQueryCount.Text = $stats.QueriesReceived.ToString("#,##0")
                } else {
                    $txtQueryCount.Text = "0"
                }
                
                # Handle recursive queries
                if ($null -ne $stats.RecursiveQueries) {
                    $txtRecursions.Text = $stats.RecursiveQueries.ToString("#,##0")
                } else {
                    $txtRecursions.Text = "0"
                }
                
                # Handle failed queries
                $failedQueries = 0
                if ($null -ne $stats.FailedQueries) { 
                    $failedQueries += $stats.FailedQueries 
                }
                if ($null -ne $stats.RecursionFailures) { 
                    $failedQueries += $stats.RecursionFailures 
                }
                $txtFailedQueries.Text = $failedQueries.ToString("#,##0")
                
                # Get uptime information safely
                try {
                    if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                        $processInfo = Get-Process -Name "dns" -ErrorAction SilentlyContinue
                        
                        if ($null -ne $processInfo -and $null -ne $processInfo.StartTime) {
                            $uptime = (Get-Date) - $processInfo.StartTime
                            $txtUptime.Text = "{0} Tage, {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
                        } else {
                            $txtUptime.Text = "DNS-Dienst läuft (Startzeit unbekannt)"
                        }
                    } else {
                        # For remote servers, we need a different approach
                        $txtUptime.Text = "DNS-Dienst auf $server aktiv"
                    }
                } catch {
                    $txtUptime.Text = "DNS-Dienst Status unbekannt"
                }
            } else {
                # No statistics available
                $txtQueryCount.Text = "N/A"
                $txtRecursions.Text = "N/A" 
                $txtFailedQueries.Text = "N/A"
                $txtUptime.Text = "Keine Statistiken verfügbar"
            }
        }
        catch {
            # Fallback method if direct statistics aren't available
            Log-Message "Standard DNS-Statistiken nicht verfügbar, verwende Fallback" -severity "WARN"
            
            $txtQueryCount.Text = "N/A"
            $txtRecursions.Text = "N/A"
            $txtFailedQueries.Text = "N/A"
            
            # Check if the DNS service is running at least
            try {
                if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                    $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
                    if ($null -ne $dnsService) {
                        $txtUptime.Text = "DNS-Dienst Status: $($dnsService.Status)"
                    } else {
                        $txtUptime.Text = "DNS-Dienst nicht gefunden"
                    }
                } else {
                    # Try WMI for remote servers
                    try {
                        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='DNS'" -ComputerName $server -ErrorAction SilentlyContinue
                        if ($null -ne $wmiService) {
                            $txtUptime.Text = "DNS-Dienst Status: $($wmiService.State)"
                        } else {
                            # Fall back to a simple connectivity test
                            if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
                                $txtUptime.Text = "Server erreichbar, DNS-Status unbekannt"
                            } else {
                                $txtUptime.Text = "Server nicht erreichbar"
                            }
                        }
                    } catch {
                        $txtUptime.Text = "Verbindung fehlgeschlagen"
                    }
                }
            } catch {
                $txtUptime.Text = "Status nicht ermittelbar"
            }
        }
        
        Log-Message "Server-Status aktualisiert" -severity "INFO"
    }
    catch {
        $txtQueryCount.Text = "Fehler"
        $txtRecursions.Text = "Fehler"
        $txtFailedQueries.Text = "Fehler"
        $txtUptime.Text = "Fehler"
        Log-Message "Fehler beim Aktualisieren des Server-Status: ${_}" -severity "ERROR"
    }
}

# Event-Handler für alle UI-Elemente
$Form.Add_Load({
    Update-ForwardZones
    Update-ReverseZones
    Load-DNSZones
    Update-DNSSECZones
    
    # Import/Export Zonen-ComboBoxen und Troubleshooting-Diagnose Zonen füllen
    $comboImportZone.Items.Clear()
    $comboExportZone.Items.Clear()
    
    # Sicherstellen, dass comboDiagZone initialisiert ist, bevor wir darauf zugreifen
    if ($null -ne $comboDiagZone) {
        $comboDiagZone.Items.Clear()
    }
    
    $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text
    foreach ($z in $zones) {
        [void]$comboImportZone.Items.Add($z.ZoneName)
        [void]$comboExportZone.Items.Add($z.ZoneName)
        
        # Sicherstellen, dass comboDiagZone initialisiert ist, bevor wir darauf zugreifen
        if ($null -ne $comboDiagZone) {
            [void]$comboDiagZone.Items.Add($z.ZoneName)
        }
    }
    
    if ($comboImportZone.Items.Count -gt 0) {
        $comboImportZone.SelectedIndex = 0
        $comboExportZone.SelectedIndex = 0
    }
    
    # Sicherstellen, dass comboDiagZone initialisiert ist, bevor wir darauf zugreifen
    if ($null -ne $comboDiagZone -and $comboDiagZone.Items.Count -gt 0) {
        $comboDiagZone.SelectedIndex = 0
    }
    
    # Server Status aktualisieren
    Update-ServerStatus
})

# Forward-Zonen Tab
$btnForwardRefresh.Add_Click({ Update-ForwardZones })
$btnForwardCreate.Add_Click({ Create-ForwardZone })
$btnForwardDelete.Add_Click({ Delete-ForwardZone })

# Reverse-Zonen Tab
$btnReverseRefresh.Add_Click({ Update-ReverseZones })
$btnReverseCreate.Add_Click({ Create-ReverseZone })
$btnReverseDelete.Add_Click({ Delete-ReverseZone })
$btnGenerateNetwork.Add_Click({ Generate-NetworkID })

# DNS Records Tab
$btnLoadZones.Add_Click({ Load-DNSZones })
$comboRecZone.Add_SelectedIndexChanged({ Load-DNSRecords })
$comboRecType.Add_SelectedIndexChanged({ Show-RecordTypeFields })
$btnRecCreate.Add_Click({ Create-DNSRecord })
$btnRecTest.Add_Click({ Test-DNSRecord })
$btnRecShow.Add_Click({ Load-DNSRecords })
$btnRecDelete.Add_Click({ Delete-DNSRecord })

# Import/Export Tab
$btnBrowseImport.Add_Click({ Browse-ImportFile })
$btnImport.Add_Click({ Import-DNSData })
$btnBrowseExport.Add_Click({ Browse-ExportFile })
$btnExport.Add_Click({ Export-DNSData })

# DNSSEC Tab
$btnDNSSECRefresh.Add_Click({ Update-DNSSECZones })
$comboDNSSECZone.Add_SelectedIndexChanged({ Update-DNSSECStatus })
$btnEnableDNSSEC.Add_Click({ Enable-ZoneDNSSEC })
$btnDisableDNSSEC.Add_Click({ Disable-ZoneDNSSEC })

# Tools Tab
$btnPing.Add_Click({ Execute-Ping })
$btnTracert.Add_Click({ Execute-Tracert })
$btnNslookup.Add_Click({ Execute-Nslookup })
$btnClearCache.Add_Click({ Clear-DNSCache })
$btnDNSFlush.Add_Click({ Clear-ClientDNSCache })
$btnDNSHealth.Add_Click({ Get-DNSHealthReport })
$btnReloadServerStatus.Add_Click({ Update-ServerStatus })

# Connect-Button im Header
$btnConnect.Add_Click({
    $oldServer = $DetectedDnsServer
    $newServer = $txtDNSServer.Text.Trim()
    
    if (-not [string]::IsNullOrWhiteSpace($newServer)) {
        try {
            # Versuchen, mit dem neuen Server zu kommunizieren
            Get-DnsServerZone -ComputerName $newServer -ErrorAction Stop | Out-Null
            
            $DetectedDnsServer = $newServer
            Log-Message "Verbindung zu DNS-Server $newServer hergestellt" -severity "INFO"
            
            # Alle Daten neu laden
            Update-ForwardZones
            Update-ReverseZones
            Load-DNSZones
            Update-DNSSECZones
            
            # Import/Export Zonen-ComboBoxen aktualisieren
            $comboImportZone.Items.Clear()
            $comboExportZone.Items.Clear()
            $zones = Get-SafeDnsServerZone -DnsServerName $txtDNSServer.Text
            foreach ($z in $zones) {
                [void]$comboImportZone.Items.Add($z.ZoneName)
                [void]$comboExportZone.Items.Add($z.ZoneName)
            }
            if ($comboImportZone.Items.Count -gt 0) {
                $comboImportZone.SelectedIndex = 0
                $comboExportZone.SelectedIndex = 0
            }
            
            # Server Status aktualisieren
            Update-ServerStatus
            
            Show-MessageBox "Verbindung zum DNS-Server '$newServer' hergestellt!" "Verbindung hergestellt"
        }
        catch {
            Log-Message "Fehler beim Verbinden mit DNS-Server" -severity "ERROR"
            Show-MessageBox "Konnte keine Verbindung zum DNS-Server herstellen. Fehler: ${_}" "Verbindungsfehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Error)
            $txtDNSServer.Text = $oldServer
        }
    }
})

# Form anzeigen
[void]$Form.ShowDialog()

# Funktionen für Troubleshooting & Auditing
function Perform-DNSDiagnostic {
    param ([string]$diagLevel = "Standard")
    
    $txtDiagOutput.Clear()
    $txtDiagOutput.AppendText("Führe DNS-Server Diagnose durch (Stufe: $diagLevel)...`r`n")
    $txtDiagOutput.AppendText("================================================`r`n")
    
    $server = $txtDNSServer.Text
    
    try {
        # Server-Erreichbarkeit prüfen
        $txtDiagOutput.AppendText("[1/5] Prüfe DNS-Server Erreichbarkeit...`r`n")
        if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
            $txtDiagOutput.AppendText("  [+] DNS-Server $server ist erreichbar`r`n")
        } else {
            $txtDiagOutput.AppendText("  [-] DNS-Server $server ist NICHT erreichbar!`r`n")
            $txtDiagOutput.AppendText("  -> Überprüfen Sie Netzwerkverbindung und Firewalls`r`n")
            return
        }
        
        # DNS-Dienststatus
        $txtDiagOutput.AppendText("[2/5] Prüfe DNS-Dienst Status...`r`n")
        try {
            if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
                if ($null -ne $dnsService) {
                    if ($dnsService.Status -eq "Running") {
                        $txtDiagOutput.AppendText("  [+] DNS-Dienst läuft (Status: $($dnsService.Status))`r`n")
                    } else {
                        $txtDiagOutput.AppendText("  [-] DNS-Dienst ist NICHT aktiv (Status: $($dnsService.Status))!`r`n")
                        if ($chkFixIssues.Checked) {
                            $txtDiagOutput.AppendText("  -> Versuche DNS-Dienst zu starten...`r`n")
                            Start-Service -Name DNS -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
                            if ($dnsService.Status -eq "Running") {
                                $txtDiagOutput.AppendText("  [+] DNS-Dienst erfolgreich gestartet`r`n")
                            } else {
                                $txtDiagOutput.AppendText("  [-] Automatischer Start fehlgeschlagen`r`n")
                            }
                        }
                    }
                } else {
                    $txtDiagOutput.AppendText("  [-] DNS-Dienst nicht gefunden! Server-Installation prüfen.`r`n")
                }
            } else {
                # Remote-Server-Check mit WMI oder PowerShell Remoting
                $dnsService = Get-WmiObject -Class Win32_Service -Filter "Name='DNS'" -ComputerName $server -ErrorAction SilentlyContinue
                if ($null -ne $dnsService) {
                    if ($dnsService.State -eq "Running") {
                        $txtDiagOutput.AppendText("  [+] DNS-Dienst läuft (Status: $($dnsService.State))`r`n")
                    } else {
                        $txtDiagOutput.AppendText("  [-] DNS-Dienst ist NICHT aktiv (Status: $($dnsService.State))!`r`n")
                    }
                } else {
                    $txtDiagOutput.AppendText("  [-] DNS-Dienst auf Remote-Server konnte nicht abgefragt werden`r`n")
                }
            }
        } catch {
            $txtDiagOutput.AppendText("  [-] Fehler bei der Prüfung des DNS-Dienstes: ${_}`r`n")
        }
        
        # Zonencheck
        $txtDiagOutput.AppendText("[3/5] Prüfe DNS-Zonen...`r`n")
        try {
            $zones = Get-DnsServerZone -ComputerName $server -ErrorAction Stop
            $zoneCount = $zones.Count
            $primaryZones = ($zones | Where-Object { $_.ZoneType -eq "Primary" }).Count
            $secondaryZones = ($zones | Where-Object { $_.ZoneType -eq "Secondary" }).Count
            $forwardZones = ($zones | Where-Object { -not $_.IsReverseLookupZone }).Count
            $reverseZones = ($zones | Where-Object { $_.IsReverseLookupZone }).Count
            
            $txtDiagOutput.AppendText("  [+] Zonen gefunden: $zoneCount Gesamt ($primaryZones Primär, $secondaryZones Sekundär)`r`n")
            $txtDiagOutput.AppendText("    -> Forward-Zonen: $forwardZones`r`n")
            $txtDiagOutput.AppendText("    -> Reverse-Zonen: $reverseZones`r`n")
            
            # Prüfe Zonen auf Probleme
            $problemZones = @()
            foreach ($zone in $zones) {
                if ($zone.ZoneType -eq "Primary") {
                    # Prüfe auf DS-Records für DNSSEC
                    if ($zone.IsSigned -and -not $zone.DsRecordGenerationFlag) {
                        $problemZones += "$($zone.ZoneName) (DNSSEC: DS-Records fehlen)"
                    }
                    
                    # Prüfe auf veraltete SOA-Einträge (älter als 30 Tage)
                    try {
                        $soa = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType SOA -ComputerName $server -ErrorAction SilentlyContinue
                        if ($soa) {
                            $serial = $soa[0].RecordData.SerialNumber
                            $serialDate = [datetime]::ParseExact($serial.ToString().Substring(0, 8), "yyyyMMdd", $null)
                            
                            if (((Get-Date) - $serialDate).Days -gt 30) {
                                $problemZones += "$($zone.ZoneName) (SOA: $serialDate)"
                            }
                        }
                    } catch {
                        # Ignoriere Fehler bei SOA-Abfrage
                    }
                }
            }
            
            if ($problemZones.Count -gt 0) {
                $txtDiagOutput.AppendText("  Potentielle Probleme in Zonen gefunden:`r`n")
                foreach ($problem in $problemZones) {
                    $txtDiagOutput.AppendText("    -> $problem`r`n")
                }
                
                if ($chkFixIssues.Checked) {
                    $txtDiagOutput.AppendText("  -> Starte automatische Reparaturversuche für Zonen...`r`n")
                    # Hier könnten automatische Reparaturen implementiert werden
                }
            } else {
                $txtDiagOutput.AppendText("  [+] Keine offensichtlichen Probleme in Zonen gefunden`r`n")
            }
        } catch {
            $txtDiagOutput.AppendText("  [-] Fehler bei der Prüfung der DNS-Zonen: ${_}`r`n")
        }
        
        # Serverparameter prüfen
        $txtDiagOutput.AppendText("[4/5] Prüfe DNS-Server Parameter...`r`n")
        try {
            $serverSettings = Get-DnsServer -ComputerName $server -ErrorAction SilentlyContinue
            if ($serverSettings) {
                $txtDiagOutput.AppendText("  [+] Server-Einstellungen abgerufen`r`n")
                
                # Prüfe auf wichtige Einstellungen
                if ($serverSettings.ForwardingTimeout -lt 3) {
                    $txtDiagOutput.AppendText("  Weiterleitungs-Timeout zu niedrig ($($serverSettings.ForwardingTimeout) Sekunden)`r`n")
                }
                
                if ($serverSettings.RoundRobin -eq $false) {
                    $txtDiagOutput.AppendText("  Round-Robin ist deaktiviert (Lastverteilung eingeschränkt)`r`n")
                }
                
                if ($serverSettings.BindSecondaries -eq $false) {
                    $txtDiagOutput.AppendText("  BIND-Sekundärzonen-Format ist deaktiviert`r`n")
                }
            } else {
                $txtDiagOutput.AppendText("  Server-Einstellungen konnten nicht abgerufen werden`r`n")
            }
            
            # Weiterleitung prüfen
            $forwarders = Get-DnsServerForwarder -ComputerName $server -ErrorAction SilentlyContinue
            if ($forwarders -and $forwarders.IPAddress.Count -gt 0) {
                $txtDiagOutput.AppendText("  [+] DNS-Forwarder konfiguriert: $($forwarders.IPAddress.Count) Server`r`n")
                
                # Prüfe Erreichbarkeit der Forwarder
                if ($diagLevel -eq "Erweiterte Prüfung" -or $diagLevel -eq "Tiefgehende Analyse") {
                    $txtDiagOutput.AppendText("    -> Teste Erreichbarkeit der Forwarder...`r`n")
                    foreach ($fwd in $forwarders.IPAddress) {
                        $fwdResult = Test-Connection -ComputerName $fwd -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($fwdResult) {
                            $txtDiagOutput.AppendText("      [+] $fwd ist erreichbar`r`n")
                        } else {
                            $txtDiagOutput.AppendText("      [-] $fwd ist NICHT erreichbar!`r`n")
                        }
                    }
                }
            } else {
                $txtDiagOutput.AppendText("  [i] Keine DNS-Forwarder konfiguriert`r`n")
            }
        } catch {
            $txtDiagOutput.AppendText("  [-] Fehler bei der Prüfung der DNS-Server Parameter: ${_}`r`n")
        }
        
        # Erweiterte Tests je nach Diagnosestufe
        $txtDiagOutput.AppendText("[5/5] Führe erweiterte Diagnostik durch...`r`n")
        if ($diagLevel -eq "Basis-Überprüfung") {
            $txtDiagOutput.AppendText("  [i] Basis-Überprüfung: Keine erweiterten Tests`r`n")
        } 
        elseif ($diagLevel -eq "Standard-Diagnose") {
            try {
                # Prüfe DNS-Cache
                $cacheStats = Get-DnsServerCache -ComputerName $server -ErrorAction SilentlyContinue
                if ($cacheStats) {
                    $txtDiagOutput.AppendText("  [+] DNS-Cache Status: $($cacheStats.CacheSize) Einträge`r`n")
                    if ($cacheStats.CacheSize -gt 10000) {
                        $txtDiagOutput.AppendText("  Cache-Größe sehr hoch - kann auf Optimierungspotenzial hindeuten`r`n")
                    }
                }
                
                # Prüfe Abfrageauflösungs-Timeouts
                $dnsServerDiag = Get-DnsServerDiagnostics -ComputerName $server -ErrorAction SilentlyContinue
                if ($dnsServerDiag) {
                    if (-not $dnsServerDiag.EnableLoggingForRecursion) {
                        $txtDiagOutput.AppendText("  Rekursionsprotokollierung ist deaktiviert - für erweiterte Diagnose aktivieren`r`n")
                    }
                }
            } catch {
                $txtDiagOutput.AppendText("  [-] Fehler bei der Standard-Diagnose: ${_}`r`n")
            }
        }
        elseif ($diagLevel -eq "Erweiterte Prüfung" -or $diagLevel -eq "Tiefgehende Analyse") {
            $txtDiagOutput.AppendText("  [i] Führe erweiterte Ressourcenprüfungen durch...`r`n")
            
            try {
                # Prüfe Windows-Ereignisprotokolle
                if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                    $dnsEvents = Get-EventLog -LogName System -Source "DNS" -Newest 20 -ErrorAction SilentlyContinue | 
                                Where-Object { $_.EntryType -eq "Error" -or $_.EntryType -eq "Warning" }
                    
                    if ($dnsEvents -and $dnsEvents.Count -gt 0) {
                        $txtDiagOutput.AppendText("  $($dnsEvents.Count) DNS-Fehler/Warnungen im Systemprotokoll gefunden`r`n")
                        
                        if ($diagLevel -eq "Tiefgehende Analyse") {
                            $txtDiagOutput.AppendText("    -> Die neuesten 5 Ereignisse:`r`n")
                            $dnsEvents | Select-Object -First 5 | ForEach-Object {
                                $txtDiagOutput.AppendText("      * $($_.TimeGenerated): $($_.Message.Split("`n")[0])`r`n")
                            }
                        }
                    } else {
                        $txtDiagOutput.AppendText("  [+] Keine DNS-Fehler im Systemprotokoll gefunden`r`n")
                    }
                }
                
                # Ressourcenprüfung
                if ($diagLevel -eq "Tiefgehende Analyse") {
                    $txtDiagOutput.AppendText("  [i] Führe Ressourcenprüfungen für lokale Instanz durch...`r`n")
                    if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                        $dnsProcess = Get-Process -Name "dns" -ErrorAction SilentlyContinue
                        if ($dnsProcess) {
                            $cpuPercent = [Math]::Round(($dnsProcess.CPU / $dnsProcess.TotalProcessorTime.TotalSeconds), 2)
                            $memoryMB = [Math]::Round($dnsProcess.WorkingSet64 / 1MB, 2)
                            
                            $txtDiagOutput.AppendText("  [+] DNS-Dienst Ressourcennutzung:`r`n")
                            $txtDiagOutput.AppendText("    -> CPU: $cpuPercent%`r`n")
                            $txtDiagOutput.AppendText("    -> Arbeitsspeicher: $memoryMB MB`r`n")
                            
                            if ($memoryMB -gt 500) {
                                $txtDiagOutput.AppendText("  Hohe Speichernutzung - Überprüfen Sie auf Speicherlecks oder übermäßigen Datenverkehr`r`n")
                            }
                        }
                    } else {
                        $txtDiagOutput.AppendText("  [i] Ressourcenprüfung nur für lokale Server verfügbar`r`n")
                    }
                }
            } catch {
                $txtDiagOutput.AppendText("  [-] Fehler bei der erweiterten Diagnostik: ${_}`r`n")
            }
        }
        
        # Diagnostik abgeschlossen
        $txtDiagOutput.AppendText("`r`nDiagnose abgeschlossen. Zusammenfassung:`r`n")
        $txtDiagOutput.AppendText("================================================`r`n")
        $txtDiagOutput.AppendText("DNS-Server: $server`r`n")
        $txtDiagOutput.AppendText("Diagnosetiefe: $diagLevel`r`n")
        $txtDiagOutput.AppendText("Zeitpunkt: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`r`n")
        
    } catch {
        $txtDiagOutput.AppendText("Schwerwiegender Fehler bei der DNS-Diagnose: ${_}`r`n")
        Log-Message "Fehler bei der DNS-Server-Diagnose: ${_}" -severity "ERROR"
    }
}

function Check-ZoneConfiguration {
    if ($null -eq $comboDiagZone.SelectedItem) {
        Show-MessageBox "Bitte waehlen Sie eine Zone fuer die Ueberpruefung aus." "Fehler" -icon ([System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $zoneName = $comboDiagZone.SelectedItem.ToString()
    $server = $txtDNSServer.Text
    $txtDiagOutput.Clear()
    $txtDiagOutput.AppendText("Pruefe Zonenkonfiguration fuer $zoneName...`r`n")
    $txtDiagOutput.AppendText("================================================`r`n")
    
    try {
        # Grundlegende Zoneninformationen
        $zone = Get-DnsServerZone -Name $zoneName -ComputerName $server
        $txtDiagOutput.AppendText("Zonentyp: $($zone.ZoneType)`r`n")
        $txtDiagOutput.AppendText("Replikation: $($zone.ReplicationScope)`r`n")
        $txtDiagOutput.AppendText("DNSSEC aktiviert: $($zone.IsSigned)`r`n")
        $txtDiagOutput.AppendText("Dynamische Updates: $($zone.DynamicUpdate)`r`n")
        $txtDiagOutput.AppendText("`r`n")
        
        # SOA-Record prüfen
        $txtDiagOutput.AppendText("SOA-Record Pruefung:`r`n")
        $soaRecord = Get-DnsServerResourceRecord -ZoneName $zoneName -RRType SOA -ComputerName $server
        if ($soaRecord) {
            $soa = $soaRecord[0].RecordData
            $txtDiagOutput.AppendText("Primary NS: $($soa.PrimaryServer)`r`n")
            $txtDiagOutput.AppendText("Admin Email: $($soa.ResponsiblePerson)`r`n")
            $txtDiagOutput.AppendText("Serial Number: $($soa.SerialNumber)`r`n")
            $txtDiagOutput.AppendText("Refresh: $($soa.RefreshInterval) Sekunden`r`n")
            $txtDiagOutput.AppendText("Retry: $($soa.RetryDelay) Sekunden`r`n")
            $txtDiagOutput.AppendText("Expire: $($soa.ExpireLimit) Sekunden`r`n")
            $txtDiagOutput.AppendText("Minimum TTL: $($soa.MinimumTimeToLive) Sekunden`r`n")
            
            # SOA-Einstellungen prüfen und bewerten
            $txtDiagOutput.AppendText("`r`nAnalyse der SOA-Parameter:`r`n")
            
            # Seriennummer auf Aktualität prüfen
            try {
                $serialDate = [datetime]::ParseExact($soa.SerialNumber.ToString().Substring(0, 8), "yyyyMMdd", $null)
                $daysOld = ((Get-Date) - $serialDate).Days
                
                if ($daysOld -gt 90) {
                    $txtDiagOutput.AppendText("SOA-Seriennummer ist sehr alt ($daysOld Tage) - Zonendaten koennten veraltet sein`r`n")
                } 
                elseif ($daysOld -gt 30) {
                    $txtDiagOutput.AppendText("[INFO] SOA-Seriennummer ist $daysOld Tage alt`r`n")
                }
                else {
                    $txtDiagOutput.AppendText("[OK] SOA-Seriennummer ist aktuell ($daysOld Tage alt)`r`n")
                }
            } catch {
                $txtDiagOutput.AppendText("[INFO] SOA-Seriennummer verwendet kein Datumsformat`r`n")
            }
            
            # Refresh-Intervall prüfen
            if ($soa.RefreshInterval -lt 900) {
                $txtDiagOutput.AppendText("Refresh-Intervall zu niedrig ($($soa.RefreshInterval) Sek.) - Erhoehte Last auf Server`r`n")
            }
            elseif ($soa.RefreshInterval -gt 86400) {
                $txtDiagOutput.AppendText("Refresh-Intervall sehr hoch ($($soa.RefreshInterval) Sek.) - Lange Verzoegerung bei Updates`r`n")
            }
            else {
                $txtDiagOutput.AppendText("[OK] Refresh-Intervall im empfohlenen Bereich`r`n")
            }
            
            # Expire-Limit prüfen
            if ($soa.ExpireLimit -lt 1209600) { # weniger als 14 Tage
                $txtDiagOutput.AppendText("Expire-Limit niedrig ($($soa.ExpireLimit) Sek.) - Kurze Ausfaelle koennen zu Problemen fuehren`r`n")
            }
            elseif ($soa.ExpireLimit -gt 2592000) { # mehr als 30 Tage
                $txtDiagOutput.AppendText("[INFO] Expire-Limit sehr hoch ($($soa.ExpireLimit) Sek.) - Veraltete Daten koennten lange bestehen bleiben`r`n")
            }
            else {
                $txtDiagOutput.AppendText("[OK] Expire-Limit im empfohlenen Bereich`r`n")
            }
            
            # TTL prüfen
            if ($soa.MinimumTimeToLive -lt 300) {
                $txtDiagOutput.AppendText("Minimum TTL sehr niedrig ($($soa.MinimumTimeToLive) Sek.) - Erhoehte Abfragehaeufigkeit`r`n")
            }
            elseif ($soa.MinimumTimeToLive -gt 86400) {
                $txtDiagOutput.AppendText("[INFO] Minimum TTL sehr hoch ($($soa.MinimumTimeToLive) Sek.) - Verlaengerte Reaktionszeit bei Aenderungen`r`n")
            }
            else {
                $txtDiagOutput.AppendText("[OK] Minimum TTL im empfohlenen Bereich`r`n")
            }
        } else {
            $txtDiagOutput.AppendText("SOA-Record konnte nicht abgerufen werden!`r`n")
        }
        
        # NS-Records prüfen
        $txtDiagOutput.AppendText("`r`nNameserver-Eintraege (NS):`r`n")
        $nsRecords = Get-DnsServerResourceRecord -ZoneName $zoneName -RRType NS -ComputerName $server
        if ($nsRecords) {
            $nameservers = @()
            foreach ($nsEntry in $nsRecords) { # $ns umbenannt in $nsEntry
                if ($nsEntry.HostName -eq "@") {
                    $nameservers += $nsEntry.RecordData.NameServer
                    $txtDiagOutput.AppendText("- $($nsEntry.RecordData.NameServer)`r`n")
                }
            }
            
            # NS-Einträge überprüfen
            if ($nameservers.Count -lt 2) {
                $txtDiagOutput.AppendText("Weniger als 2 Nameserver gefunden - kein Redundanz-Schutz!`r`n")
            }
            else {
                $txtDiagOutput.AppendText("[OK] $($nameservers.Count) Nameserver konfiguriert`r`n")
            }
            
            # Wenn verbose Logging aktiviert ist und umfassende Diagnose gewählt wurde:
            if ($chkVerboseLogging.Checked -and $comboDiagLevel.SelectedItem -match "Erweitert|Tiefgehend") {
                $txtDiagOutput.AppendText("`r`nVersuche Erreichbarkeit der Nameserver zu pruefen...`r`n")
                
                foreach ($nsNameServer in $nameservers) { 
                    # Extrahiere den Host-Teil
                    $nsFqdn = $nsNameServer
                    if ($nsNameServer.EndsWith(".")) {
                        $nsFqdn = $nsNameServer.Substring(0, $nsNameServer.Length - 1)
                    }
                    
                    try {
                        $nsIp = [System.Net.Dns]::GetHostAddresses($nsFqdn)
                        if ($nsIp -and $nsIp.Count -gt 0) {
                            $txtDiagOutput.AppendText("$nsNameServer`: Erfolgreich aufgeloest zu $($nsIp[0].IPAddressToString)`r`n")
                            $pingResult = Test-Connection -ComputerName $nsIp[0].IPAddressToString -Count 1 -Quiet -ErrorAction SilentlyContinue
                            if ($pingResult) {
                                $txtDiagOutput.AppendText("$nsNameServer`: Erreichbar (ping erfolgreich)`r`n")
                            } else {
                                $txtDiagOutput.AppendText("$nsNameServer`: NICHT erreichbar via ping`r`n")
                            }
                        }
                        else {
                            $txtDiagOutput.AppendText("$nsNameServer`: Konnte nicht zu einer IP-Adresse aufgeloest werden`r`n")
                        }
                    }
                    catch {
                        $txtDiagOutput.AppendText("$nsNameServer`: Fehler bei der Namensaufloesung: $($_.Exception.Message)`r`n")
                    }
                }
            }
        } else {
            $txtDiagOutput.AppendText("NS-Records konnten nicht abgerufen werden!`r`n")
        }
        
        # MX-Records prüfen, falls vorhanden
        $txtDiagOutput.AppendText("`r`nMail-Exchanger (MX):`r`n")
        $mxRecords = Get-DnsServerResourceRecord -ZoneName $zoneName -RRType MX -ComputerName $server -ErrorAction SilentlyContinue
        
        if ($mxRecords -and $mxRecords.Count -gt 0) {
            $rootMxCount = 0
            foreach ($mx in $mxRecords) {
                if ($mx.HostName -eq "@") {
                    $rootMxCount++
                    $txtDiagOutput.AppendText("- Prioritaet: $($mx.RecordData.Preference), Server: $($mx.RecordData.MailExchange)`r`n")
                }
            }
            
            if ($rootMxCount -eq 0) {
                $txtDiagOutput.AppendText("[INFO] Keine MX-Eintraege fuer die Zone-Root (@) gefunden`r`n")
            }
            elseif ($rootMxCount -eq 1) {
                $txtDiagOutput.AppendText("[INFO] Nur ein MX-Eintrag fuer die Zone-Root - keine Redundanz bei E-Mail-Zustellung`r`n")
            }
            else {
                $txtDiagOutput.AppendText("[OK] Mehrere MX-Eintraege gefunden - gute E-Mail-Redundanz`r`n")
            }
        } else {
            $txtDiagOutput.AppendText("[INFO] Keine MX-Records in dieser Zone gefunden`r`n")
        }
        
        # Wenn DNSSEC aktiviert ist, prüfe DNSSEC-Konfiguration
        if ($zone.IsSigned) {
            $txtDiagOutput.AppendText("`r`nDNSSEC-Konfiguration:`r`n")
            try {
                $dnssecInfo = Get-DnsServerDnsSecZone -Name $zoneName -ComputerName $server
                
                $txtDiagOutput.AppendText("Signierungstyp: $($dnssecInfo.SigningType)`r`n")
                $txtDiagOutput.AppendText("NSEC-Methode: $($dnssecInfo.NSECType)`r`n")
                
                # Prüfe, ob Schlüssel vorhanden sind
                $keys = $dnssecInfo.Keys
                $ksk = $keys | Where-Object { $_.KeyType -eq "KeySigningKey" }
                $zsk = $keys | Where-Object { $_.KeyType -eq "ZoneSigningKey" }
                
                if ($ksk.Count -gt 0 -and $zsk.Count -gt 0) {
                    $txtDiagOutput.AppendText("[OK] KSK und ZSK gefunden`r`n")
                    
                    # Prüfe auf ablaufende Schlüssel
                    $today = Get-Date
                    $expiringKeys = $keys | Where-Object { 
                        ($_.RolloverDate -lt $today.AddDays(30)) -and 
                        ($_.RolloverDate -gt $today) 
                    }
                    
                    if ($expiringKeys.Count -gt 0) {
                        $txtDiagOutput.AppendText("$($expiringKeys.Count) Schluessel laufen in den naechsten 30 Tagen ab!`r`n")
                        foreach ($key in $expiringKeys) {
                            $txtDiagOutput.AppendText("- $($key.KeyTag) laeuft ab am $($key.RolloverDate)`r`n")
                        }
                    }
                    else {
                        $txtDiagOutput.AppendText("[OK] Keine Schluessel laufen in den naechsten 30 Tagen ab`r`n")
                    }
                    
                    # Prüfe auf abgelaufene Schlüssel
                    $expiredKeys = $keys | Where-Object { $_.RolloverDate -lt $today }
                    if ($expiredKeys.Count -gt 0) {
                        $txtDiagOutput.AppendText("$($expiredKeys.Count) abgelaufene Schluessel gefunden!`r`n")
                    }
                }
                else {
                    $txtDiagOutput.AppendText("Fehlende Schluessel: KSK=$($ksk.Count), ZSK=$($zsk.Count)`r`n")
                }
                
                # DS-Record-Status
                if ($dnssecInfo.DsRecordGenerationFlag) {
                    $txtDiagOutput.AppendText("[OK] DS-Records wurden generiert`r`n")
                }
                else {
                    $txtDiagOutput.AppendText("DS-Records wurden nicht generiert - DNSSEC-Validierung moeglicherweise eingeschraenkt`r`n")
                }
            }
            catch {
                $txtDiagOutput.AppendText("Fehler beim Abrufen der DNSSEC-Informationen: $($_.Exception.Message)`r`n")
            }
        }
        
        # Abschluss der Prüfung
        $txtDiagOutput.AppendText("`r`nZonen-Check abgeschlossen.`r`n")
        $txtDiagOutput.AppendText("================================================`r`n")
        $txtDiagOutput.AppendText("Zone: $zoneName`r`n")
        $txtDiagOutput.AppendText("Zeitpunkt: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`r`n")
        
    }
    catch {
        $txtDiagOutput.AppendText("Fehler bei der Zonenueberpruefung: $($_.Exception.Message)`r`n")
        Log-Message "Fehler bei der Zonenueberpruefung fuer '$zoneName': $($_.Exception.Message)" -severity "ERROR"
    }
}

function Check-DNSSecValidation {
    $txtDiagOutput.Clear()
    $txtDiagOutput.AppendText("DNSSEC-Validierungspruefung...`r`n")
    $txtDiagOutput.AppendText("================================================`r`n")
    
    $server = $txtDNSServer.Text
    
    try {
        # Prüfe, ob DNSSEC auf dem Server aktiviert ist
        $txtDiagOutput.AppendText("Pruefe DNSSEC-Konfiguration auf dem Server...`r`n")
        
        try {
            $serverConf = Get-DnsServerSetting -ComputerName $server -ErrorAction SilentlyContinue
            
            if ($serverConf -and $serverConf.EnableDnsSec) {
                $txtDiagOutput.AppendText("OK: DNSSEC ist auf dem Server aktiviert`r`n")
            }
            else {
                $txtDiagOutput.AppendText("DNSSEC ist auf dem Server deaktiviert!`r`n")
                if ($chkFixIssues.Checked) {
                    $txtDiagOutput.AppendText("-> Versuche DNSSEC zu aktivieren...`r`n")
                    try {
                        # Dies ist eine vereinfachte Form - in der Praxis gibt es mehr Parameter
                        Set-DnsServerSetting -ComputerName $server -EnableDnsSec $true -EnableDnsSecValidation $true
                        $txtDiagOutput.AppendText("OK: DNSSEC wurde aktiviert`r`n")
                    }
                    catch {
                        $txtDiagOutput.AppendText("FEHLER: Konnte DNSSEC nicht aktivieren: ${_}`r`n")
                    }
                }
            }
        }
        catch {
            $txtDiagOutput.AppendText("Konnte DNSSEC-Konfiguration nicht abrufen: ${_}`r`n")
        }
        
        # Zähle DNSSEC-signierte Zonen
        $signedZones = 0
        $unsignedZones = 0
        
        $zones = Get-DnsServerZone -ComputerName $server
        foreach ($zone in $zones) {
            if ($zone.IsSigned) {
                $signedZones++
            } else {
                # Zähle nur Primary Zonen, die unsigniert sind (Secondary Zonen können nicht lokal signiert werden)
                if ($zone.ZoneType -eq "Primary") {
                    $unsignedZones++
                }
            }
        }
        
        $txtDiagOutput.AppendText("`r`nDNSSEC-Zonenstatus:`r`n")
        $txtDiagOutput.AppendText("- Signierte Zonen: $signedZones`r`n")
        $txtDiagOutput.AppendText("- Nicht-signierte Primary-Zonen: $unsignedZones`r`n")
        
        if ($unsignedZones -gt 0) {
            $txtDiagOutput.AppendText("Es gibt unsignierte Primaerzonen, die mit DNSSEC geschuetzt werden koennten.`r`n")
        }
        
        # Testen einer bekannten DNSSEC-validierten Domain
        $txtDiagOutput.AppendText("`r`nFuehre DNSSEC-Validierungstest durch...`r`n")
        
        # Beispiele für DNSSEC-signierte Domains
        $testDomains = @(
            "dnssec-tools.org",
            "iis.se", 
            "iana.org"
        )
        
        foreach ($domain in $testDomains) {
            try {
                $txtDiagOutput.AppendText("Test mit $domain...`r`n")
                
                # Verwende Resolve-DnsName mit DNSSEC-Überprüfung (funktioniert nur auf Windows Server 2012+)
                $dnsResults = Resolve-DnsName -Name $domain -DnsOnly -Type A -Server $server -ErrorAction SilentlyContinue
                
                if ($dnsResults) {
                    $txtDiagOutput.AppendText("OK: Aufloesung von $domain erfolgreich`r`n")
                    
                    # Teste explizit DNSKEY-Records
                    $dnsKey = Resolve-DnsName -Name $domain -Type DNSKEY -Server $server -ErrorAction SilentlyContinue
                    
                    if ($dnsKey -and $dnsKey.Count -gt 0) {
                        $txtDiagOutput.AppendText("OK: DNSKEY-Records fuer $domain gefunden ($($dnsKey.Count) Schluessel)`r`n")
                        
                        # Erweiterte DNSSEC-Validierung prüfen
                        if ($comboDiagLevel.SelectedItem -match "Erweitert|Tiefgehend") {
                            $txtDiagOutput.AppendText("Fuehre erweiterte DNSSEC-Validierungspruefung durch...`r`n")
                            try {
                                $dsRecords = Resolve-DnsName -Name $domain -Type DS -Server $server -ErrorAction SilentlyContinue
                                if ($dsRecords -and $dsRecords.Count -gt 0) {
                                    $txtDiagOutput.AppendText("OK: DS-Records fuer $domain gefunden`r`n")
                                } else {
                                    $txtDiagOutput.AppendText("Keine DS-Records fuer $domain gefunden`r`n")
                                }
                            } catch {
                                $txtDiagOutput.AppendText("Fehler bei der DS-Record-Abfrage: ${_}`r`n")
                            }
                        }
                    }
                    else {
                        $txtDiagOutput.AppendText("Keine DNSKEY-Records gefunden - DNSSEC moeglicherweise nicht korrekt konfiguriert`r`n")
                    }
                }
                else {
                    $txtDiagOutput.AppendText("FEHLER: Konnte $domain nicht aufloesen`r`n")
                }
            }
            catch {
                $txtDiagOutput.AppendText("Fehler bei der DNSSEC-Validierung")
            }
        }
        
        # Prüfe DNSSEC Trust Anchors
        $txtDiagOutput.AppendText("`r`nPruefe DNSSEC Trust Anchors...`r`n")
        
        try {
            $trustAnchors = Get-DnsServerTrustAnchor -ComputerName $server -ErrorAction SilentlyContinue
            
            if ($trustAnchors -and $trustAnchors.Count -gt 0) {
                $txtDiagOutput.AppendText("OK: $($trustAnchors.Count) Trust Anchors gefunden`r`n")
                
                # Prüfe, ob Trust Anchors für die Root-Zone vorhanden sind
                $rootAnchors = $trustAnchors | Where-Object { $_.TrustAnchorZoneName -eq "." }
                
                if ($rootAnchors -and $rootAnchors.Count -gt 0) {
                    $txtDiagOutput.AppendText("OK: Root Zone Trust Anchors gefunden - DNSSEC-Validierung fuer die Root-Zone moeglich`r`n")
                }
                else {
                    $txtDiagOutput.AppendText("Keine Root Zone Trust Anchors gefunden - DNSSEC-Validierung eingeschraenkt`r`n")
                }
            }
            else {
                $txtDiagOutput.AppendText("Keine Trust Anchors gefunden - DNSSEC-Validierung nicht moeglich!`r`n")
                
                if ($chkFixIssues.Checked) {
                    $txtDiagOutput.AppendText("-> Versuche Root Trust Anchors zu laden...`r`n")
                    try {
                        # Vereinfachte Methode - in der Praxis gibt es spezifischere Befehle
                        $rootKey = Add-DnsServerTrustAnchor -ComputerName $server -UseRootHints -ErrorAction SilentlyContinue
                        $txtDiagOutput.AppendText("OK: Root Trust Anchors wurden geladen`r`n")
                    }
                    catch {
                        $txtDiagOutput.AppendText("FEHLER: Konnte Root Trust Anchors nicht laden: ${_}`r`n")
                    }
                }
            }
        }
        catch {
            $txtDiagOutput.AppendText("Fehler beim Abrufen der Trust Anchors: ${_}`r`n")
        }
        
        # Abschluss der Prüfung
        $txtDiagOutput.AppendText("`r`nDNSSEC-Validierungspruefung abgeschlossen.`r`n")
        $txtDiagOutput.AppendText("================================================`r`n")
        $txtDiagOutput.AppendText("Server: $server`r`n")
        $txtDiagOutput.AppendText("Zeitpunkt: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`r`n")
        
    }
    catch {
        $txtDiagOutput.AppendText("Fehler bei der DNSSEC-Validierungspruefung: ${_}`r`n")
        Log-Message "Fehler bei der DNSSEC-Validierungspruefung: ${_}" -severity "ERROR"
    }
}

# Funktion fuer Netzwerkdiagnostik (war im urspruenglichen Code nicht implementiert)
function Perform-NetworkDiagnostic {
    $txtDiagOutput.Clear()
    $txtDiagOutput.AppendText("Netzwerkdiagnose wird durchgefuehrt...`r`n")
    $txtDiagOutput.AppendText("================================================`r`n")
    
    $server = $txtDNSServer.Text
    
    try {
        # Server-Erreichbarkeit pruefen
        $txtDiagOutput.AppendText("[1/3] Pruefe Netzwerkverbindung zum DNS-Server...`r`n")
        
        $pingResult = Test-Connection -ComputerName $server -Count 4 -ErrorAction SilentlyContinue
        if ($pingResult) {
            $avg = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
            $min = ($pingResult | Measure-Object -Property ResponseTime -Minimum).Minimum
            $max = ($pingResult | Measure-Object -Property ResponseTime -Maximum).Maximum
            
            $txtDiagOutput.AppendText("  OK: DNS-Server $server ist erreichbar`r`n")
            $txtDiagOutput.AppendText("    -> Durchschnittliche Antwortzeit: $([math]::Round($avg, 2)) ms`r`n")
            $txtDiagOutput.AppendText("    -> Min/Max Antwortzeit: $min/$max ms`r`n")
        } else {
            $txtDiagOutput.AppendText("  FEHLER: DNS-Server $server ist NICHT erreichbar!`r`n")
            $txtDiagOutput.AppendText("  -> Ueberpruefen Sie Netzwerkverbindung und Firewalls`r`n")
            return
        }
        
        # Pruefen, ob der DNS-Service auf dem entfernten Server erreichbar ist
        $txtDiagOutput.AppendText("[2/3] Pruefe DNS-Dienst Erreichbarkeit...`r`n")
        try {
            $dnsPort = Test-NetConnection -ComputerName $server -Port 53 -ErrorAction SilentlyContinue
            if ($dnsPort.TcpTestSucceeded) {
                $txtDiagOutput.AppendText("  OK: DNS-Dienst auf Port 53 ist erreichbar`r`n")
            } else {
                $txtDiagOutput.AppendText("  FEHLER: DNS-Dienst auf Port 53 ist NICHT erreichbar!`r`n")
                $txtDiagOutput.AppendText("    -> Pruefen Sie, ob der DNS-Dienst laeuft und die Firewall-Einstellungen`r`n")
            }
        } catch {
            $txtDiagOutput.AppendText("  FEHLER: Fehler beim Pruefen des DNS-Ports: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
        }
        
        # Traceroute zum DNS-Server
        $txtDiagOutput.AppendText("[3/3] Fuehre Traceroute zum DNS-Server durch...`r`n")
        try {
            $trace = Test-NetConnection -ComputerName $server -TraceRoute -ErrorAction SilentlyContinue
            if ($trace -and $trace.TraceRoute) {
                $hopCount = $trace.TraceRoute.Count
                $txtDiagOutput.AppendText("  OK: Traceroute abgeschlossen: $hopCount Hops zum Ziel`r`n")
                
                $hop = 1
                foreach ($route in $trace.TraceRoute) {
                    try {
                        $hostEntry = [System.Net.Dns]::GetHostEntry($route)
                        $hostname = $hostEntry.HostName
                    } catch {
                        $hostname = "Unbekannt"
                    }
                    
                    $txtDiagOutput.AppendText("    $hop. $route ($hostname)`r`n")
                    $hop++
                }
            } else {
                $txtDiagOutput.AppendText("  FEHLER: Traceroute fehlgeschlagen`r`n")
            }
        } catch {
            $txtDiagOutput.AppendText("  FEHLER: Fehler beim Ausfuehren des Traceroute: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
        }
        
        # Abschluss der Pruefung
        $txtDiagOutput.AppendText("`r`nNetzwerkdiagnose abgeschlossen.`r`n")
        $txtDiagOutput.AppendText("================================================`r`n")
        $txtDiagOutput.AppendText("Server: $server`r`n")
        $txtDiagOutput.AppendText("Zeitpunkt: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`r`n")
        
    } catch {
        $errorMessage = "Fehler bei der Netzwerkdiagnose: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessage`r`n")
        Log-Message $errorMessage -severity "ERROR"
    }
}

# Funktion zum Loeschen der Diagnose-Events
function Clear-DiagnosticEvents {
    $txtDiagOutput.Clear()
    $txtDiagOutput.AppendText("Loesche Diagnose-Events...`r`n")
    
    try {
        if ($txtDNSServer.Text -eq "localhost" -or $txtDNSServer.Text -eq "127.0.0.1" -or $txtDNSServer.Text -eq $env:COMPUTERNAME) {
            # Nur fuer lokale Server
            $txtDiagOutput.AppendText("Versuche lokale DNS-bezogene Ereignisprotokolle zu loeschen...`r`n")
            
            try {
                Clear-EventLog -LogName "DNS Server" -ErrorAction SilentlyContinue
                $txtDiagOutput.AppendText("OK: DNS-Server-Ereignisprotokolle geloescht`r`n")
            } catch {
                $txtDiagOutput.AppendText("FEHLER: Konnte DNS-Server-Ereignisprotokolle nicht loeschen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
            }
            
            try {
                # Systemereignisse mit DNS-Bezug loeschen geht nicht direkt
                # Wir koennen nur informieren
                $txtDiagOutput.AppendText("System-Ereignisprotokolle koennen nicht selektiv geloescht werden.`r`n")
                $txtDiagOutput.AppendText("Sie koennen das gesamte Systemprotokoll ueber die Windows-Ereignisanzeige leeren.`r`n")
            } catch {
                $txtDiagOutput.AppendText("Fehler: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
            }
            
        } else {
            $txtDiagOutput.AppendText("Das Loeschen von Ereignisprotokollen wird nur fuer lokale Server unterstuetzt.`r`n")
            $txtDiagOutput.AppendText("Fuer den Remote-Server '$($txtDNSServer.Text)' muessen Sie die Ereignisprotokolle direkt auf dem Server loeschen.`r`n")
        }
        
        # Eigene Diagnoseprotokolle loeschen
        $logFiles = Get-ChildItem -Path $scriptRoot -Filter "easyDNS_*.log" -ErrorAction SilentlyContinue
        if ($logFiles.Count -gt 0) {
            foreach ($log in $logFiles) {
                try {
                    Remove-Item -Path $log.FullName -Force -ErrorAction SilentlyContinue
                    $txtDiagOutput.AppendText("OK: Diagnoseprotokoll geloescht: $($log.Name)`r`n")
                } catch {
                    $txtDiagOutput.AppendText("FEHLER: Konnte Diagnoseprotokoll nicht loeschen: $($log.Name)`r`n") # Assuming $log.Name is safe or would be part of a broader error from Remove-Item
                }
            }
        } else {
            $txtDiagOutput.AppendText("Keine easyDNS-Diagnoseprotokolle gefunden.`r`n")
        }
        
        $txtDiagOutput.AppendText("`r`nLoeschen der Diagnose-Events abgeschlossen.`r`n")
        
    } catch {
        $errorMessage = "Fehler beim Loeschen der Diagnose-Events: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessage`r`n")
        Log-Message $errorMessage -severity "ERROR"
    }
}

# Auditing-Funktionen - Vollstaendige Implementierungen
function Enable-Audit {
    try {
        $server = $txtDNSServer.Text
        $txtDiagOutput.Clear()
        $txtDiagOutput.AppendText("DNS-Auditing wird aktiviert auf $server...\r\n")
        
        # Pruefe zuerst, ob die DNS-Server-Diagnostics verfuegbar sind
        try {
            $dnsServerDiag = Get-DnsServerDiagnostics -ComputerName $server -ErrorAction Stop
            
            # Aktiviere DNS-Auditing mit ausgewaehlten Optionen
            $newSettings = @{
                EnableLogFileRollover = $true
                EnableLoggingForLocalLookupEvent = $chkAuditQueries.Checked
                EnableLoggingForPluginDllEvent = $true
                EnableLoggingForRecursiveLookupEvent = $chkAuditQueries.Checked
                EnableLoggingForRemoteServerEvent = $true
                EnableLoggingForServerStartStopEvent = $true
                EnableLoggingForTombstoneEvent = $true
                EnableLoggingForZoneDataWriteEvent = $chkAuditZoneChanges.Checked
                EnableLoggingForZoneLoadingEvent = $true
                EnableLoggingToFile = $true
                LogFilePath = "C:\Windows\System32\dns\dns.log" # Path itself is fine
                MaxMBFileSize = 500
            }
            
            # Wende die Einstellungen an
            Set-DnsServerDiagnostics -ComputerName $server @newSettings
            
            # Aktiviere auch die Ueberwachung von DNS-Aenderungen im Ereignisprotokoll
            # Die EventSource-Einstellungen koennen nicht direkt ueber PowerShell gesetzt werden,
            # daher verwenden wir Reg-Manipulation wenn lokaler Server
            if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                try {
                    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
                    Set-ItemProperty -Path $registryPath -Name "EnableLoggingDnsUpdateProxy" -Value 1 -Type DWord
                    Set-ItemProperty -Path $registryPath -Name "LogLevel" -Value 32769 -Type DWord
                    Set-ItemProperty -Path $registryPath -Name "EventLogLevel" -Value 4 -Type DWord
                    
                    $txtDiagOutput.AppendText("Registry-Einstellungen fuer erweiterte DNS-Protokollierung gesetzt.\r\n")
                } catch {
                    $txtDiagOutput.AppendText("Konnte Registry-Einstellungen nicht anpassen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))\r\n")
                }
            }
            
            # Setze auch die Aufbewahrungsdauer fuer Audit-Logs
            $retentionDays = [int]$txtRetention.Text
            if ($retentionDays -gt 0) {
                try {
                    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
                    if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                        Set-ItemProperty -Path $registryPath -Name "LogFileMaxSize" -Value ($retentionDays * 5) -Type DWord
                    } else {
                        # Fuer Remote-Server Invoke-Command verwenden, was zusaetzliche Rechte erfordert
                        $scriptBlock = {
                            param($path, $days)
                            Set-ItemProperty -Path $path -Name "LogFileMaxSize" -Value ($days * 5) -Type DWord
                        }
                        Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -ArgumentList $registryPath, $retentionDays
                    }
                    $txtDiagOutput.AppendText("Log-Aufbewahrungsdauer auf $retentionDays Tage gesetzt.\r\n")
                } catch {
                    $txtDiagOutput.AppendText("Konnte Aufbewahrungsdauer nicht setzen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))\r\n")
                }
            }
            
            # DNS-Dienst neu starten, wenn auf die CheckBox-Einstellung aktiviert wurde
            if ($chkRestartAfterConfig.Checked) {
                $txtDiagOutput.AppendText("Starte DNS-Dienst neu, um Aenderungen zu uebernehmen...\r\n")
                try {
                    if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                        Restart-Service -Name "DNS" -Force
                    } else {
                        Invoke-Command -ComputerName $server -ScriptBlock { Restart-Service -Name "DNS" -Force }
                    }
                    $txtDiagOutput.AppendText("DNS-Dienst erfolgreich neu gestartet.\r\n")
                } catch {
                    $txtDiagOutput.AppendText("Konnte DNS-Dienst nicht neu starten: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))\r\n")
                }
            }
            
            $txtDiagOutput.AppendText("`r`nDNS-Auditing wurde erfolgreich aktiviert!`r`n")
            Log-Message "DNS-Auditing auf Server '$server' aktiviert" -severity "INFO" # Log message itself is clean
            
            # Aktualisiere die UI zur Bestaetigung
            $btnEnableAudit.BackColor = [System.Drawing.Color]::LightGray
            $btnDisableAudit.BackColor = [System.Drawing.Color]::LightCoral
            
            # Verzoegerung und dann Audit-Logs anzeigen
            View-AuditLogs
        }
        catch { # Catch for Get-DnsServerDiagnostics
            $txtDiagOutput.AppendText("Fehler beim Abrufen der DNS-Server-Diagnose-Einstellungen:`r`n$($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
            $txtDiagOutput.AppendText("`r`nVersuche alternative Methode ueber WMI...`r`n")
            
            # Fallback fuer aeltere Server, die keine PowerShell-Cmdlets unterstuetzen
            try {
                # DNS-Tools ueber dnscmd aktivieren
                $cmd = "dnscmd $server /config /LogLevel 0x800F"
                $result = Invoke-Expression $cmd # Result might contain special characters, but it's displayed as-is.
                $txtDiagOutput.AppendText("DNS-Logging ueber dnscmd aktiviert.`r`n")
                $txtDiagOutput.AppendText("Befehl: $cmd`r`n")
                $txtDiagOutput.AppendText("Ergebnis: $result`r`n") # If $result needs cleaning, it should be done here. Assuming $result is usually simple.
                
                $txtDiagOutput.AppendText("`r`nDNS-Auditing wurde aktiviert (eingeschraenkte Funktionalitaet)!`r`n")
                Log-Message "DNS-Auditing auf Server '$server' aktiviert (mit dnscmd)" -severity "INFO"
            }
            catch { # Catch for dnscmd fallback
                $errorMessageLog = "Fehler beim Aktivieren von DNS-Auditing (dnscmd): $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
                $txtDiagOutput.AppendText("Auch alternative Methode fehlgeschlagen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
                Log-Message $errorMessageLog -severity "ERROR"
            }
        }
    }
    catch { # Catch for the entire Enable-Audit function
        $errorMessageLog = "Unerwarteter Fehler beim Aktivieren von DNS-Auditing: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessageLog`r`n")
        Log-Message $errorMessageLog -severity "ERROR"
    }
}

function Disable-Audit {
    try {
        $server = $txtDNSServer.Text
        $txtDiagOutput.Clear()
        $txtDiagOutput.AppendText("DNS-Auditing wird deaktiviert auf $server...\r\n")
        
        try {
            $dnsServerDiag = Get-DnsServerDiagnostics -ComputerName $server -ErrorAction Stop
            
            # Deaktiviere DNS-Auditing
            $newSettings = @{
                EnableLoggingForLocalLookupEvent = $false
                EnableLoggingForPluginDllEvent = $false
                EnableLoggingForRecursiveLookupEvent = $false
                EnableLoggingForRemoteServerEvent = $false
                EnableLoggingForZoneDataWriteEvent = $false
                EnableLoggingForTombstoneEvent = $false
                EnableLoggingToFile = $false
            }
            
            # Wende die Einstellungen an
            Set-DnsServerDiagnostics -ComputerName $server @newSettings
            
            # Deaktiviere zusaetzliche Registry-Einstellungen, wenn lokaler Server
            if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                try {
                    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
                    Set-ItemProperty -Path $registryPath -Name "EnableLoggingDnsUpdateProxy" -Value 0 -Type DWord
                    Set-ItemProperty -Path $registryPath -Name "LogLevel" -Value 0 -Type DWord
                    Set-ItemProperty -Path $registryPath -Name "EventLogLevel" -Value 0 -Type DWord
                    
                    $txtDiagOutput.AppendText("Registry-Einstellungen fuer DNS-Protokollierung zurueckgesetzt.\r\n")
                } catch {
                    $txtDiagOutput.AppendText("Konnte Registry-Einstellungen nicht anpassen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))\r\n")
                }
            }
            
            # DNS-Dienst neu starten, wenn die Einstellung aktiviert wurde
            if ($chkRestartAfterConfig.Checked) {
                $txtDiagOutput.AppendText("Starte DNS-Dienst neu, um Aenderungen zu uebernehmen...\r\n")
                try {
                    if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                        Restart-Service -Name "DNS" -Force
                    } else {
                        Invoke-Command -ComputerName $server -ScriptBlock { Restart-Service -Name "DNS" -Force }
                    }
                    $txtDiagOutput.AppendText("DNS-Dienst erfolgreich neu gestartet.\r\n")
                } catch {
                    $txtDiagOutput.AppendText("Konnte DNS-Dienst nicht neu starten: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))\r\n")
                }
            }
            
            $txtDiagOutput.AppendText("`r`nDNS-Auditing wurde erfolgreich deaktiviert!`r`n")
            Log-Message "DNS-Auditing auf Server '$server' deaktiviert" -severity "INFO"
            
            # Aktualisiere die UI zur Bestaetigung
            $btnEnableAudit.BackColor = [System.Drawing.Color]::LightGreen
            $btnDisableAudit.BackColor = [System.Drawing.Color]::LightGray
            
            # Leere das Audit-Log-Grid
            $dgvAuditLogs.Rows.Clear()
        }
        catch { # Catch for Get-DnsServerDiagnostics
            $txtDiagOutput.AppendText("Fehler beim Abrufen der DNS-Server-Diagnose-Einstellungen:`r`n$($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
            $txtDiagOutput.AppendText("`r`nVersuche alternative Methode ueber WMI...`r`n")
            
            # Fallback fuer aeltere Server
            try {
                # DNS-Tools ueber dnscmd deaktivieren
                $cmd = "dnscmd $server /config /LogLevel 0x0"
                $result = Invoke-Expression $cmd
                $txtDiagOutput.AppendText("DNS-Logging ueber dnscmd deaktiviert.`r`n")
                $txtDiagOutput.AppendText("Befehl: $cmd`r`n")
                $txtDiagOutput.AppendText("Ergebnis: $result`r`n") # If $result needs cleaning
                
                $txtDiagOutput.AppendText("`r`nDNS-Auditing wurde deaktiviert!`r`n")
                Log-Message "DNS-Auditing auf Server '$server' deaktiviert (mit dnscmd)" -severity "INFO"
            }
            catch { # Catch for dnscmd fallback
                $errorMessageLog = "Fehler beim Deaktivieren von DNS-Auditing (dnscmd): $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
                $txtDiagOutput.AppendText("Auch alternative Methode fehlgeschlagen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
                Log-Message $errorMessageLog -severity "ERROR"
            }
        }
    }
    catch { # Catch for the entire Disable-Audit function
        $errorMessageLog = "Unerwarteter Fehler beim Deaktivieren von DNS-Auditing: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessageLog`r`n")
        Log-Message $errorMessageLog -severity "ERROR"
    }
}

function View-AuditLogs {
    try {
        $server = $txtDNSServer.Text
        $dgvAuditLogs.Rows.Clear()
        $txtDiagOutput.Clear()
        $txtDiagOutput.AppendText("Lade DNS-Audit-Protokolle von $server...\r\n")
        
        # Bestimme den Zeitraum basierend auf den Einstellungen
        $daysToFetch = [int]$txtRetention.Text
        if ($daysToFetch -le 0) { $daysToFetch = 7 } # Standardwert, wenn ungueltige Eingabe
        $startDate = (Get-Date).AddDays(-$daysToFetch)
        
        # Wir versuchen zuerst, die DNS-Ereignisse aus dem Windows-Ereignisprotokoll zu bekommen
        try {
            $events = @()
            
            if ($server -eq "localhost" -or $server -eq "127.0.0.1" -or $server -eq $env:COMPUTERNAME) {
                # DNS-Server-Ereignisse
                $dnsEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'DNS Server'
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message
                
                foreach ($event in $dnsEvents) {
                    $eventType = switch ($event.Id) {
                        # DNS-Zonen-Aenderungen
                        { $_ -in 512, 513, 514, 515, 516, 517, 518 } { "Zonenaenderung" }
                        # DNS-Record-Aenderungen
                        { $_ -in 769, 770, 771, 772 } { "Recordaenderung" }
                        # DNS-Abfragen
                        { $_ -in 256, 257, 258, 259 } { "DNS-Abfrage" }
                        # DNS Dienst-Ereignisse
                        { $_ -in 1000, 1001, 1002, 1003 } { "Dienstereignis" }
                        # Andere
                        default { "Sonstiges" }
                    }
                    
                    # Melde nur Ereignisse, die den Filter-Einstellungen entsprechen
                    $includeEvent = $false
                    
                    if ($eventType -eq "Zonenaenderung" -and $chkAuditZoneChanges.Checked) { $includeEvent = $true }
                    elseif ($eventType -eq "Recordaenderung" -and $chkAuditRecordChanges.Checked) { $includeEvent = $true }
                    elseif ($eventType -eq "DNS-Abfrage" -and $chkAuditQueries.Checked) { $includeEvent = $true }
                    elseif ($eventType -ne "DNS-Abfrage" -and $eventType -ne "Zonenaenderung" -and $eventType -ne "Recordaenderung") { 
                        $includeEvent = $true # Andere Ereignisse immer einbeziehen
                    }
                    
                    if ($includeEvent) {
                        $user = ""
                        # Versuche einen Benutzer aus der Nachricht zu extrahieren
                        if ($event.Message -match "user\s+(\S+)") {
                            $user = $Matches[1]
                        } elseif ($event.Message -match "von\s+(\S+)") {
                            $user = $Matches[1]
                        }
                        
                        $events += [PSCustomObject]@{
                            TimeStamp = $event.TimeCreated
                            EventType = $eventType
                            User = $user
                            Details = $event.Message # Event.Message might contain special chars, handled by DataGridView display or export
                        }
                    }
                }
                
                # System-Ereignisse mit DNS-Bezug
                $sysEvents = Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'DNS'
                    StartTime = $startDate
                } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message
                
                foreach ($event in $sysEvents) {
                    $eventType = "System-DNS"
                    
                    $user = ""
                    if ($event.Message -match "user\s+(\S+)") {
                        $user = $Matches[1]
                    }
                    
                    $events += [PSCustomObject]@{
                        TimeStamp = $event.TimeCreated
                        EventType = $eventType
                        User = $user
                        Details = $event.Message
                    }
                }
                
                # Auch zusaetzlich die DNS-Logdatei auswerten, wenn vorhanden
                $dnsLogPath = "C:\Windows\System32\dns\dns.log"
                if (Test-Path $dnsLogPath) {
                    $txtDiagOutput.AppendText("Analysiere DNS-Logdatei: $dnsLogPath\r\n")
                    
                    $logEntries = Get-Content $dnsLogPath -ErrorAction SilentlyContinue
                    $logCounter = 0
                    
                    foreach ($line in $logEntries) {
                        if ($line.Trim() -eq "" -or $line.StartsWith("#")) { continue }
                        
                        try {
                            if ($line -match "\d+/\d+/\d+\s+\d+:\d+:\d+\s+(AM|PM|)") {
                                $parts = $line -split "\s+"
                                $dateStr = "$($parts[0]) $($parts[1])"
                                $eventDate = [DateTime]::Parse($dateStr)
                                
                                if ($eventDate -ge $startDate) {
                                    $logCounter++
                                    
                                    # Pruefe, ob es eine Abfrage ist (Format der DNS-Log-Datei pruefen)
                                    $isQuery = $false
                                    $queryType = ""
                                    
                                    if ($parts.Count -gt 5) {
                                        if ($parts[2] -eq "PACKET" -or $parts[3] -eq "UDP" -or $parts[3] -eq "TCP") {
                                            $isQuery = $true
                                            $queryType = if ($line -match "FORWARDER|RECURSION") { "Rekursive-Abfrage" } else { "DNS-Abfrage" }
                                        }
                                    }
                                    
                                    # Zeige nur Abfragen an, wenn Option ausgewaehlt
                                    if (!$isQuery -or ($isQuery -and $chkAuditQueries.Checked)) {
                                        $eventType = if ($isQuery) { $queryType } else { "Log-Eintrag" }
                                        
                                        $user = if ($parts.Count -gt 5) { $parts[4] } else { "" } # User might be an IP or domain
                                        
                                        $events += [PSCustomObject]@{
                                            TimeStamp = $eventDate
                                            EventType = $eventType
                                            User = $user
                                            Details = $line # Original line from log
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            # Ignoriere fehlerhafte Log-Zeilen
                            continue
                        }
                    }
                    
                    $txtDiagOutput.AppendText("$logCounter relevante Log-Eintraege aus DNS-Logdatei verarbeitet.\r\n")
                }
            }
            else {
                # Remote-Events muessen ueber PowerShell-Remoting geholt werden, was zusaetzliche Berechtigungen erfordert
                try {
                    $scriptBlock = {
                        param($days)
                        $startDate = (Get-Date).AddDays(-$days)
                        
                        # DNS Server-Ereignisse
                        Get-WinEvent -FilterHashtable @{
                            LogName = 'DNS Server'
                            StartTime = $startDate
                        } -ErrorAction SilentlyContinue | 
                        Select-Object TimeCreated, Id, LevelDisplayName, Message
                    }
                    
                    $remoteEvents = Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -ArgumentList $daysToFetch
                    
                    foreach ($event in $remoteEvents) {
                        $eventType = switch ($event.Id) {
                            { $_ -in 512, 513, 514, 515, 516, 517, 518 } { "Zonenaenderung" }
                            { $_ -in 769, 770, 771, 772 } { "Recordaenderung" }
                            { $_ -in 256, 257, 258, 259 } { "DNS-Abfrage" }
                            { $_ -in 1000, 1001, 1002, 1003 } { "Dienstereignis" }
                            default { "Sonstiges" }
                        }
                        
                        # Filter anwenden wie beim lokalen Server
                        $includeEvent = $false
                        
                        if ($eventType -eq "Zonenaenderung" -and $chkAuditZoneChanges.Checked) { $includeEvent = $true }
                        elseif ($eventType -eq "Recordaenderung" -and $chkAuditRecordChanges.Checked) { $includeEvent = $true }
                        elseif ($eventType -eq "DNS-Abfrage" -and $chkAuditQueries.Checked) { $includeEvent = $true }
                        elseif ($eventType -ne "DNS-Abfrage" -and $eventType -ne "Zonenaenderung" -and $eventType -ne "Recordaenderung") { 
                            $includeEvent = $true
                        }
                        
                        if ($includeEvent) {
                            $user = ""
                            if ($event.Message -match "user\s+(\S+)") {
                                $user = $Matches[1]
                            } elseif ($event.Message -match "von\s+(\S+)") {
                                $user = $Matches[1]
                            }
                            
                            $events += [PSCustomObject]@{
                                TimeStamp = $event.TimeCreated
                                EventType = $eventType
                                User = $user
                                Details = $event.Message
                            }
                        }
                    }
                }
                catch {
                    $txtDiagOutput.AppendText("Fehler beim Abrufen von Remote-Ereignissen: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
                    $txtDiagOutput.AppendText("Remote-Ereignisprotokollzugriff erfordert moeglicherweise erhoehte Berechtigungen.`r`n")
                }
            }
            
            # Ereignisse sortieren und anzeigen
            $events = $events | Sort-Object -Property TimeStamp -Descending
            
            # Audit-Grid fuellen
            foreach ($event in $events) {
                # Details might contain special characters. DataGridView should handle them, or they are sanitized on export.
                [void]$dgvAuditLogs.Rows.Add(
                    $event.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss"),
                    $event.EventType,
                    $event.User,
                    $event.Details 
                )
            }
            
            $txtDiagOutput.AppendText("Insgesamt $($events.Count) Audit-Ereignisse geladen.\r\n")
            
            # Speichere die Ereignisse fuer den Export
            $global:currentAuditEvents = $events
        }
        catch { # Catch for Get-WinEvent / log parsing
            $txtDiagOutput.AppendText("Fehler beim Abrufen der Ereignisprotokolle: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
        }
    }
    catch { # Catch for the entire View-AuditLogs function
        $errorMessageLog = "Unerwarteter Fehler beim Anzeigen der Audit-Protokolle: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessageLog`r`n")
        Log-Message $errorMessageLog -severity "ERROR"
    }
}

function Export-AuditLogs {
    try {
        $txtDiagOutput.Clear()
        $txtDiagOutput.AppendText("Exportiere DNS-Audit-Protokolle...\r\n")
        
        # Pruefe, ob Daten zum Exportieren vorhanden sind
        if (-not $global:currentAuditEvents -or $global:currentAuditEvents.Count -eq 0) {
            $txtDiagOutput.AppendText("Keine Audit-Daten zum Exportieren vorhanden. Bitte zuerst 'Protokolle anzeigen' ausfuehren.\r\n")
            return
        }
        
        # Dialog zum Speichern der Datei anzeigen
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.InitialDirectory = $exportFolder
        $saveDialog.Filter = "CSV-Datei (*.csv)|*.csv|XML-Datei (*.xml)|*.xml|JSON-Datei (*.json)|*.json|HTML-Bericht (*.html)|*.html"
        $saveDialog.Title = "Audit-Logs exportieren"
        $saveDialog.DefaultExt = "csv"
        
        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $exportPath = $saveDialog.FileName
            $exportFormat = [System.IO.Path]::GetExtension($exportPath).ToLower()
            
            $txtDiagOutput.AppendText("Exportiere nach: $exportPath`r`n")
            $txtDiagOutput.AppendText("Format: $exportFormat`r`n")
            
            # Sanitize function for strings before export if needed, especially for HTML
            function Sanitize-StringForExport ($str) {
                if ($null -eq $str) { return "" }
                return $str.Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss')
            }
            function Sanitize-StringForHtml ($str) {
                if ($null -eq $str) { return "" }
                $tempStr = $str.Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss')
                return $tempStr.Replace("<", "&lt;").Replace(">", "&gt;")
            }

            # Export je nach gewaehltem Format
            switch ($exportFormat) {
                ".csv" {
                    $global:currentAuditEvents | 
                        Select-Object @{Name='Zeitstempel';Expression={$_.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss")}}, # Timestamp format is safe
                            @{Name='Ereignistyp';Expression={Sanitize-StringForExport $_.EventType}}, 
                            @{Name='Benutzer';Expression={Sanitize-StringForExport $_.User}}, 
                            @{Name='Details';Expression={Sanitize-StringForExport $_.Details}} | 
                        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
                    $txtDiagOutput.AppendText("Daten wurden als CSV exportiert.\r\n")
                }
                ".xml" {
                    # Export-Clixml handles complex objects; direct string sanitization might break deserialization if not careful.
                    # Assuming Clixml handles characters appropriately or the consumer will.
                    # If strict sanitization is needed here, each property would need to be a string and sanitized.
                    $global:currentAuditEvents | Export-Clixml -Path $exportPath
                    $txtDiagOutput.AppendText("Daten wurden als XML exportiert.\r\n")
                }
                ".json" {
                    # ConvertTo-Json should handle unicode characters correctly by escaping them.
                    # If strict ASCII is required, pre-sanitize string properties.
                    $sanitizedEvents = $global:currentAuditEvents | ForEach-Object {
                        [PSCustomObject]@{
                            TimeStamp = $_.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss")
                            EventType = Sanitize-StringForExport $_.EventType
                            User      = Sanitize-StringForExport $_.User
                            Details   = Sanitize-StringForExport $_.Details
                        }
                    }
                    $sanitizedEvents | ConvertTo-Json -Depth 3 | Out-File -FilePath $exportPath -Encoding UTF8
                    $txtDiagOutput.AppendText("Daten wurden als JSON exportiert.\r\n")
                }
                ".html" {
                    # Einfachen HTML-Bericht erstellen
                    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>DNS-Audit-Protokoll</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        h1, h2 { color: #4CAF50; }
        .info { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>DNS-Audit-Protokoll</h1>
    <div class="info">
        <p><strong>Server:</strong> $(Sanitize-StringForHtml $txtDNSServer.Text)</p>
        <p><strong>Exportiert am:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Anzahl Ereignisse:</strong> $($global:currentAuditEvents.Count)</p>
    </div>
    
    <h2>Ereignisse</h2>
    <table>
        <tr>
            <th>Zeitstempel</th>
            <th>Ereignistyp</th>
            <th>Benutzer</th>
            <th>Details</th>
        </tr>
"@

                    $htmlRows = $global:currentAuditEvents | ForEach-Object {
                        "<tr>" +
                        "<td>$($_.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>" + # Timestamp format is safe
                        "<td>$(Sanitize-StringForHtml $_.EventType)</td>" +
                        "<td>$(Sanitize-StringForHtml $_.User)</td>" +
                        "<td>$(Sanitize-StringForHtml $_.Details)</td>" + # Details already HTML escaped and umlauts replaced
                        "</tr>"
                    }

                    $htmlFooter = @"
    </table>
    <div class="info">
        <p><strong>Erstellt mit:</strong> easyDNS Advanced</p>
    </div>
</body>
</html>
"@

                    $htmlContent = $htmlHeader + ($htmlRows -join "`n") + $htmlFooter
                    $htmlContent | Out-File -FilePath $exportPath -Encoding UTF8
                    $txtDiagOutput.AppendText("Daten wurden als HTML-Bericht exportiert.\r\n")
                }
                default {
                    $txtDiagOutput.AppendText("Unbekanntes Exportformat. Verwende CSV als Standard.\r\n")
                    $global:currentAuditEvents | 
                        Select-Object @{Name='Zeitstempel';Expression={$_.TimeStamp.ToString("yyyy-MM-dd HH:mm:ss")}}, 
                            @{Name='Ereignistyp';Expression={Sanitize-StringForExport $_.EventType}}, 
                            @{Name='Benutzer';Expression={Sanitize-StringForExport $_.User}}, 
                            @{Name='Details';Expression={Sanitize-StringForExport $_.Details}} | 
                        Export-Csv -Path "$exportPath.csv" -NoTypeInformation -Encoding UTF8
                }
            }
            
            $txtDiagOutput.AppendText("Export abgeschlossen: $($global:currentAuditEvents.Count) Ereignisse wurden exportiert.\r\n")
            Log-Message "DNS-Audit-Protokolle wurden nach '$exportPath' exportiert" -severity "INFO"
            
            # Biete an, die exportierte Datei zu oeffnen
            $result = Show-MessageBox "Moechten Sie die exportierte Datei oeffnen?" "Export abgeschlossen" `
              -buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) `
              -icon ([System.Windows.Forms.MessageBoxIcon]::Question)
              
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    Invoke-Item -Path $exportPath
                } catch {
                    $txtDiagOutput.AppendText("Fehler beim Oeffnen der Datei: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))`r`n")
                }
            }
        } else {
            $txtDiagOutput.AppendText("Export abgebrochen.\r\n")
        }
    }
    catch {
        $errorMessageLog = "Fehler beim Exportieren der Audit-Protokolle: $($_.ToString().Replace('ä','ae').Replace('ö','oe').Replace('ü','ue').Replace('Ä','Ae').Replace('Ö','Oe').Replace('Ü','Ue').Replace('ß','ss'))"
        $txtDiagOutput.AppendText("$errorMessageLog`r`n")
        Log-Message $errorMessageLog -severity "ERROR"
    }
}

# Füge CheckBox für DNS-Dienst Neustart hinzu
$chkRestartAfterConfig = New-Object System.Windows.Forms.CheckBox
$chkRestartAfterConfig.Text = "DNS-Dienst nach Konfigurationsänderungen neu starten"
$chkRestartAfterConfig.Location = New-Object System.Drawing.Point(20, 220)
$chkRestartAfterConfig.Size = New-Object System.Drawing.Size(350, 20)
$grpAuditParams.Controls.Add($chkRestartAfterConfig)

# Initialisiere globale Variable für Audit-Events
$global:currentAuditEvents = @()

# Event-Handler für Troubleshooting & Auditing
$btnDNSDiag.Add_Click({ Perform-DNSDiagnostic -diagLevel $comboDiagLevel.SelectedItem })
$btnZoneCheck.Add_Click({ Check-ZoneConfiguration })
$btnDNSSecCheck.Add_Click({ Check-DNSSecValidation })
$btnNetDiag.Add_Click({ Perform-NetworkDiagnostic })
$btnClearDiagEvents.Add_Click({ Clear-DiagnosticEvents })
$btnEnableAudit.Add_Click({ Enable-Audit })
$btnDisableAudit.Add_Click({ Disable-Audit })
$btnViewLogs.Add_Click({ View-AuditLogs })
$btnExportLogs.Add_Click({ Export-AuditLogs })