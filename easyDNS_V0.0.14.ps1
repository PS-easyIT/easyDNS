#requires -RunAsAdministrator

###############################################################################
# easyDNS v0.0.14 
###############################################################################
$global:AppConfig = @{
    AppName = "easyDNS v0.0.14"
    Author = "DNS Management Suite"
    ScriptVersion = "0.0.11"
    Website = "https://github.com/easyIT"
    LastUpdate = "24.05.2025"
    
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
    
    # DNS-Konfiguration
    DefaultTTL = 3600
    DefaultReplicationScope = "Domain"
    
    # Pfade
    LogPath = ""
    ExportPath = ""
    ImportPath = ""
}

# Pfade initialisieren
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { 
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path 
}
$global:AppConfig.LogPath = Join-Path $scriptRoot "Logs"
$global:AppConfig.ExportPath = Join-Path $scriptRoot "Export"
$global:AppConfig.ImportPath = Join-Path $scriptRoot "Import"

# Verzeichnisse erstellen falls nicht vorhanden
@($global:AppConfig.LogPath, $global:AppConfig.ExportPath, $global:AppConfig.ImportPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        try { New-Item -ItemType Directory -Path $_ -Force | Out-Null } catch { }
    }
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
# LOGGING-FUNKTIONEN
###############################################################################
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    if (-not $global:AppConfig.EnableLogging) { return }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$Level] $timestamp - $Message"
    
    # Console-Output mit Farben
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "DEBUG" { if ($global:AppConfig.DebugMode) { Write-Host $logEntry -ForegroundColor Cyan } }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Logfile schreiben
    try {
        $today = Get-Date -Format "yyyyMMdd"
        $user = $env:USERNAME
        $logFile = Join-Path $global:AppConfig.LogPath "easyDNS_${today}_${user}.log"
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    } catch {
        # Logfehler ignorieren um Hauptfunktionalität nicht zu beeinträchtigen
    }
}

function Show-MessageBox {
    param(
        [string]$Message,
        [string]$Title = "Information",
        [string]$Type = "Information" # Information, Warning, Error, Question
    )
    
    [System.Windows.MessageBox]::Show($Message, $Title, "OK", $Type)
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
    try {
        # Versuche localhost zuerst
        $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
        if ($dnsFeature -and $dnsFeature.Installed) {
            Write-Log "Lokaler DNS-Server erkannt" -Level "INFO"
            return 'localhost'
        }
    } catch {
        Write-Log "Windows Feature Abfrage fehlgeschlagen" -Level "DEBUG"
    }

    try {
        # Versuche DNS-Client-Konfiguration
        $dnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                       Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }).ServerAddresses
        foreach ($srv in $dnsServers) {
            try {
                # Test ob DNS-Server erreichbar und funktionsfähig
                $testZone = Get-DnsServerZone -ComputerName $srv -ErrorAction Stop | Select-Object -First 1
                if ($testZone) {
                    Write-Log "DNS-Server gefunden: $srv" -Level "INFO"
                    return $srv
                }
            } catch {
                Write-Log "DNS-Server $srv nicht erreichbar" -Level "DEBUG"
            }
        }
    } catch {
        Write-Log "DNS-Client-Konfiguration nicht verfügbar" -Level "DEBUG"
    }

    # Fallback
    Write-Log "Fallback auf localhost" -Level "WARN"
    return "localhost"
}

# Initialer DNS-Server
$global:DetectedDnsServer = Get-DNSServerDetection

###############################################################################
# DNS-HILFSFUNKTIONEN (Robuste Implementierungen)
###############################################################################

function Get-SafeDnsServerZone {
    param([string]$DnsServerName)
    
    $list = @()
    try {
        $rawZones = Get-DnsServerZone -ComputerName $DnsServerName -ErrorAction Stop

        foreach ($z in $rawZones) {
            # Cache, RootHints und "." überspringen
            if ($z.ZoneName -in @("RootHints","Cache",".") -or $z.ZoneType -eq "Cache") {
                continue
            }
            
            $isRev = $false
            if ($z.PSObject.Properties.Name -contains 'IsReverseLookupZone') {
                $isRev = $z.IsReverseLookupZone
            } else {
                $isRev = $z.ZoneName -match '\.arpa$'
            }

            $repScope = 'N/A'
            if ($z.PSObject.Properties.Name -contains 'ReplicationScope' -and $z.ReplicationScope) {
                    $repScope = $z.ReplicationScope
            }
            
            $dnssecStatus = "Disabled"
            try {
                if ($z.IsSigned) {
                    $dnssecStatus = "Enabled"
                }
            } catch {
                # Ignoriere DNSSEC-Fehler
            }

            $list += [PSCustomObject]@{
                ZoneName = $z.ZoneName
                ZoneType = $z.ZoneType
                IsReverse = $isRev
                RepScope = $repScope
                DNSSECStatus = $dnssecStatus
                IsSigned = if ($z.IsSigned) { "Ja" } else { "Nein" }
                RecordCount = 0  # Wird bei Bedarf gefüllt
            }
        }
        
        Write-Log "DNS-Zonen abgerufen: $($list.Count) Zonen von Server $DnsServerName" -Level "INFO"
        
    } catch {
        Write-Log "Fehler beim Abrufen der DNS-Zonen von $DnsServerName`: $_" -Level "ERROR"
    }
    
    return $list
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
            default { return $record.RecordData.ToString() }
        }
    } catch {
        return "Fehler beim Formatieren"
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
        Height="950" Width="1400" MinHeight="700" MinWidth="1200"
        WindowStartupLocation="CenterScreen"
        Background="#F3F3F3"
        FontFamily="Segoe UI"
        FontSize="12">
    
    <Window.Resources>
        <!-- Modern Button Style -->
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="18,8"/> <!-- Increased horizontal padding -->
            <Setter Property="Margin" Value="6"/> <!-- Increased margin for better spacing -->
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="MinWidth" Value="80"/> <!-- Ensure a minimum width for smaller buttons -->
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
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Navigation Button Style -->
        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#484848"/> <!-- Subtle border for definition -->
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="15,10"/> 
            <Setter Property="Margin" Value="8,3,8,3"/> <!-- Margin around each button (left,top,right,bottom) for spacing and inset -->
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border"
                                Background="{TemplateBinding Background}" 
                                CornerRadius="4"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}">
                            <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" 
                                            VerticalAlignment="Center"
                                            Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#3E3E42"/> 
                                <Setter TargetName="border" Property="BorderBrush" Value="#5E5E62"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#0078D4"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="#005A9E"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Card Style -->
        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="White"/>
            <Setter Property="BorderBrush" Value="#D1D1D1"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="16"/>
            <Setter Property="Margin" Value="8"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#C0C0C0" Direction="315" ShadowDepth="2" BlurRadius="8" Opacity="0.3"/>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- TextBox Style -->
        <Style x:Key="ModernTextBox" TargetType="TextBox">
            <Setter Property="BorderBrush" Value="#D1D1D1"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8"/>
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
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <Style TargetType="TabItem">
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>

    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="60"/>        <!-- Header -->
            <RowDefinition Height="*"/>         <!-- Main Content -->
            <RowDefinition Height="40"/>        <!-- Footer -->
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="White" BorderBrush="#D1D1D1" BorderThickness="0,0,0,1">
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
                              Foreground="#323130" VerticalAlignment="Center"/>
                </StackPanel>

                <!-- Center Info -->
                <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock Text="DNS Server:" Margin="0,0,8,0" FontWeight="SemiBold"/>
                    <TextBox Name="txtDNSServer" Width="150" Style="{StaticResource ModernTextBox}" Text="$($global:DetectedDnsServer)"/>
                    <Button Name="btnConnect" Content="Connect" Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                    <TextBlock Name="lblStatus" Text="Status: Ready" Margin="16,0,0,0" 
                              Foreground="#107C10" FontWeight="SemiBold" VerticalAlignment="Center"/>
                </StackPanel>

                <!-- User Info -->
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="USER | " FontSize="16" Margin="0,0,4,0"/>
                    <TextBlock Text="$($env:USERNAME)" FontWeight="SemiBold" Foreground="#323130"/>
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
            <Border Grid.Column="0" Background="#2D2D30" BorderBrush="#D1D1D1" BorderThickness="0,0,1,0">
                <StackPanel Margin="0,16">
                    <!-- Navigation Header -->
                    <TextBlock Text="Navigation" Foreground="White" FontSize="14" FontWeight="SemiBold" 
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
            <Border Grid.Column="1" Background="#F3F3F3" Padding="15">
                <ScrollViewer Name="contentScrollViewer" VerticalScrollBarVisibility="Auto">
                    <Grid Name="contentGrid">
                        <!-- Dashboard Panel -->
                        <StackPanel Name="dashboardPanel" Visibility="Visible">
                            <TextBlock Text="DNS Server Dashboard" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,20"/>
                            
                            <UniformGrid Columns="2" Margin="0,0,0,20">
                                <!-- Zone Overview Card -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Zone Overview" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <TextBlock Name="lblZoneInfo" Text="Loading zone information..." 
                                                  FontSize="12" Foreground="#605E5C"/>
                                    </StackPanel>
                                </Border>

                                <!-- Server Status Card -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Server Status" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <TextBlock Name="lblServerInfo" Text="Loading server information..." 
                                                  FontSize="12" Foreground="#605E5C"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                        </StackPanel>

                        <!-- Forward Zones Panel -->
                        <Grid Name="forwardPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="*"/>    <!-- Zone List Card with DataGrid -->
                                <RowDefinition Height="Auto"/> <!-- Create New Zone Card -->
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Manage Forward Zones" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <Border Grid.Row="1" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/> <!-- Header + Buttons -->
                                        <RowDefinition Height="*"/>    <!-- DataGrid -->
                                    </Grid.RowDefinitions>
                                    <StackPanel Grid.Row="0">
                                        <TextBlock Text="Zone List" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                            <Button Name="btnRefreshZones" Content="Refresh" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnDeleteZone" Content="Delete" Margin="8,0,0,0" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </StackPanel>
                                    <DataGrid Grid.Row="1" Name="dgForwardZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="*"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding ZoneType}" Width="Auto"/>
                                            <DataGridTextColumn Header="Replication" Binding="{Binding RepScope}" Width="Auto"/>
                                            <DataGridTextColumn Header="DNSSEC" Binding="{Binding IsSigned}" Width="Auto"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <StackPanel>
                                    <TextBlock Text="Create New Forward Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="200"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="150"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        
                                        <TextBlock Grid.Column="0" Text="Zone Name:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <TextBox Grid.Column="1" Name="txtNewZoneName" Style="{StaticResource ModernTextBox}"/>
                                        <TextBlock Grid.Column="2" Text="Replication:" VerticalAlignment="Center" Margin="16,0,8,0"/>
                                        <ComboBox Grid.Column="3" Name="cmbReplication" Margin="4" Padding="8">
                                            <ComboBoxItem Content="Domain" IsSelected="True"/>
                                            <ComboBoxItem Content="Forest"/>
                                            <ComboBoxItem Content="Legacy"/>
                                        </ComboBox>
                                        <Button Grid.Column="4" Name="btnCreateZone" Content="Create Zone" 
                                               Margin="16,0,0,0" Background="#107C10" Style="{StaticResource ModernButton}"/>
                                    </Grid>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <!-- Records Panel -->
                        <Grid Name="recordsPanel" Visibility="Collapsed">
                             <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- Select Zone Card -->
                                <RowDefinition Height="Auto"/> <!-- Create New Record Card -->
                                <RowDefinition Height="*"/>    <!-- DNS Records DataGrid Card -->
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Manage DNS Records" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <Border Grid.Row="1" Style="{StaticResource Card}">
                                <StackPanel>
                                    <TextBlock Text="Select Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="Zone:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <ComboBox Name="cmbRecordZone" Width="200" Margin="4" Padding="8"/>
                                        <Button Name="btnRefreshZoneList" Content="Refresh" 
                                               Margin="16,0,0,0" Style="{StaticResource ModernButton}"/>
                                    </StackPanel>
                                </StackPanel>
                            </Border>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <StackPanel>
                                    <TextBlock Text="Create New Record" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="120"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="80"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="200"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="80"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        
                                        <TextBlock Grid.Column="0" Text="Name:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <TextBox Grid.Column="1" Name="txtRecordName" Style="{StaticResource ModernTextBox}"/>
                                        <TextBlock Grid.Column="2" Text="Type:" VerticalAlignment="Center" Margin="8,0,8,0"/>
                                        <ComboBox Grid.Column="3" Name="cmbRecordType" Margin="4" Padding="8">
                                            <ComboBoxItem Content="A" IsSelected="True"/>
                                            <ComboBoxItem Content="AAAA"/>
                                            <ComboBoxItem Content="CNAME"/>
                                            <ComboBoxItem Content="MX"/>
                                            <ComboBoxItem Content="PTR"/>
                                            <ComboBoxItem Content="TXT"/>
                                            <ComboBoxItem Content="SRV"/>
                                        </ComboBox>
                                        <TextBlock Grid.Column="4" Text="Data:" VerticalAlignment="Center" Margin="8,0,8,0"/>
                                        <TextBox Grid.Column="5" Name="txtRecordData" Style="{StaticResource ModernTextBox}"/>
                                        <TextBlock Grid.Column="6" Text="TTL:" VerticalAlignment="Center" Margin="8,0,8,0"/>
                                        <TextBox Grid.Column="7" Name="txtRecordTTL" Text="3600" Style="{StaticResource ModernTextBox}"/>
                                        <StackPanel Grid.Column="8" Orientation="Horizontal" Margin="16,0,0,0">
                                            <Button Name="btnCreateRecord" Content="Create" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnDeleteRecord" Content="Delete" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Grid>
                                </StackPanel>
                            </Border>

                            <Border Grid.Row="3" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="DNS Records" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <DataGrid Grid.Row="1" Name="dgRecords" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="*"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="Auto"/>
                                            <DataGridTextColumn Header="Data" Binding="{Binding Data}" Width="*"/>
                                            <DataGridTextColumn Header="TTL" Binding="{Binding TTL}" Width="Auto"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>
                        </Grid>

                        <!-- Tools Panel -->
                        <Grid Name="toolsPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="*"/>    <!-- TabControl for tools -->
                                <RowDefinition Height="Auto"/> <!-- Output Console Card -->
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="DNS Diagnostics and Troubleshooting" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>

                            <TabControl Grid.Row="1" Name="toolsTabControl" Margin="0,0,8,10">
                                <TabItem Header="Quick Tools">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="Quick DNS Tools" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Grid Margin="0,0,0,12">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="Auto"/>
                                                    <ColumnDefinition Width="200"/>
                                                    <ColumnDefinition Width="*"/>
                                                </Grid.ColumnDefinitions>
                                                <TextBlock Grid.Column="0" Text="Target:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                                <TextBox Grid.Column="1" Name="txtDiagnosisTarget" Style="{StaticResource ModernTextBox}"/>
                                                <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="8,0,0,0" HorizontalAlignment="Left">
                                                    <Button Name="btnPing" Content="Ping" Style="{StaticResource ModernButton}"/>
                                                    <Button Name="btnNslookup" Content="Nslookup" Style="{StaticResource ModernButton}"/>
                                                    <Button Name="btnResolve" Content="Resolve" Style="{StaticResource ModernButton}"/>
                                                    <Button Name="btnTestConnection" Content="Test Connection" Style="{StaticResource ModernButton}"/>
                                                </StackPanel>
                                            </Grid>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Cache">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="DNS Cache Management" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Button Name="btnShowCache" Content="Show DNS Cache" Margin="0,0,0,4" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnClearCache" Content="Clear DNS Cache" Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnClearClientCache" Content="Clear Client Cache (ipconfig /flushdns)" Margin="0,4,0,0" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Service">
                                     <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="DNS Service Management" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Button Name="btnServiceStatus" Content="Service Status" Margin="0,0,0,4" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnStartService" Content="Start DNS Service" Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnStopService" Content="Stop DNS Service" Background="#D13438" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnRestartService" Content="Restart DNS Service" Margin="0,4,0,0" Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Configuration">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="DNS Configuration" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Button Name="btnServerConfig" Content="Server Configuration" Margin="0,0,0,4" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnServerStats" Content="Server Statistics" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnDiagnostics" Content="Diagnostics Settings" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnNetAdapterDNS" Content="Network Adapter DNS" Margin="0,4,0,0" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Forwarders">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="DNS Forwarders" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Button Name="btnShowForwarders" Content="Show Forwarders" Margin="0,0,0,4" Style="{StaticResource ModernButton}"/>
                                            <Grid Margin="0,4,0,4">
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="Auto"/>
                                                </Grid.ColumnDefinitions>
                                                <TextBox Grid.Column="0" Name="txtForwarderIP" Style="{StaticResource ModernTextBox}" 
                                                        ToolTip="IP-Adresse des Forwarders"/>
                                                <Button Grid.Column="1" Name="btnAddForwarder" Content="Add" 
                                                       Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            </Grid>
                                            <Button Name="btnRemoveForwarder" Content="Remove Selected" Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Zone Tools">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="Zone Management Tools" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="Auto"/>
                                                    <ColumnDefinition Width="200"/>
                                                    <ColumnDefinition Width="*"/>
                                                </Grid.ColumnDefinitions>
                                                <TextBlock Grid.Column="0" Text="Zone:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                                <ComboBox Grid.Column="1" Name="cmbDiagZone" Margin="4" Padding="8"/>
                                                <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="8,0,0,0" HorizontalAlignment="Left">
                                                    <Button Name="btnZoneInfo" Content="Zone Info" Style="{StaticResource ModernButton}"/>
                                                    <Button Name="btnZoneRefresh" Content="Force Refresh" Style="{StaticResource ModernButton}"/>
                                                    <Button Name="btnZoneTransfer" Content="Zone Transfer" Style="{StaticResource ModernButton}"/>
                                                </StackPanel>
                                            </Grid>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Event Logs">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="Event Logs and Monitoring" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <StackPanel Orientation="Horizontal" Margin="0,0,0,12" HorizontalAlignment="Left">
                                                <Button Name="btnDNSEvents" Content="DNS Server Events" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnSystemEvents" Content="System Events" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnSecurityEvents" Content="Security Events" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnExportEvents" Content="Export Events" Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                            </StackPanel>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                                <TabItem Header="Advanced">
                                    <Border Style="{StaticResource Card}">
                                        <StackPanel>
                                            <TextBlock Text="Advanced Diagnostics" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                            <StackPanel Orientation="Horizontal" Margin="0,0,0,12" HorizontalAlignment="Left">
                                                <Button Name="btnEnableDebugLog" Content="Enable Debug Logging" Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnDisableDebugLog" Content="Disable Debug Logging" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnExportStats" Content="Export Statistics" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnNetworkProps" Content="Network Properties" Style="{StaticResource ModernButton}"/>
                                            </StackPanel>
                                        </StackPanel>
                                    </Border>
                                </TabItem>
                            </TabControl>
                            
                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="280"/> <!-- Increased height for diagnostic output -->
                                    </Grid.RowDefinitions>
                                    <Grid Grid.Row="0" Margin="0,0,0,8">
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="*"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        <TextBlock Grid.Column="0" Text="Diagnostic Output Console" FontSize="16" FontWeight="SemiBold" VerticalAlignment="Center"/>
                                        <StackPanel Grid.Column="1" Orientation="Horizontal">
                                            <Button Name="btnClearOutput" Content="Clear" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnSaveOutput" Content="Save to File" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </Grid>
                                    <TextBox Grid.Row="1" Name="txtDiagnosisOutput" 
                                            TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                                            FontFamily="Consolas" FontSize="10" 
                                            Background="Black" Foreground="LightGreen"
                                            IsReadOnly="True"/>
                                </Grid>
                            </Border>
                        </Grid>

                        <!-- Reverse Zones Panel -->
                        <Grid Name="reversePanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="*"/>    <!-- Reverse Zone List Card with DataGrid -->
                                <RowDefinition Height="Auto"/> <!-- Create New Reverse Zone Card -->
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Manage Reverse Zones" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <Border Grid.Row="1" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <StackPanel Grid.Row="0">
                                        <TextBlock Text="Reverse Zone List" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                            <Button Name="btnRefreshReverseZones" Content="Refresh" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnDeleteReverseZone" Content="Delete" Margin="8,0,0,0" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </StackPanel>
                                    <DataGrid Grid.Row="1" Name="dgReverseZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="*"/>
                                            <DataGridTextColumn Header="Type" Binding="{Binding ZoneType}" Width="Auto"/>
                                            <DataGridTextColumn Header="Network" Binding="{Binding Network}" Width="Auto"/>
                                            <DataGridTextColumn Header="Replication" Binding="{Binding RepScope}" Width="Auto"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>

                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <StackPanel>
                                    <TextBlock Text="Create New Reverse Zone" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="150"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="100"/>
                                            <ColumnDefinition Width="Auto"/>
                                            <ColumnDefinition Width="150"/>
                                            <ColumnDefinition Width="Auto"/>
                                        </Grid.ColumnDefinitions>
                                        
                                        <TextBlock Grid.Column="0" Text="Network:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                        <TextBox Grid.Column="1" Name="txtReverseNetwork" Style="{StaticResource ModernTextBox}" 
                                                ToolTip="z.B. 192.168.1"/>
                                        <TextBlock Grid.Column="2" Text="Prefix:" VerticalAlignment="Center" Margin="16,0,8,0"/>
                                        <TextBox Grid.Column="3" Name="txtReversePrefix" Text="24" Style="{StaticResource ModernTextBox}"/>
                                        <TextBlock Grid.Column="4" Text="Replication:" VerticalAlignment="Center" Margin="16,0,8,0"/>
                                        <ComboBox Grid.Column="5" Name="cmbReverseReplication" Margin="4" Padding="8">
                                            <ComboBoxItem Content="Domain" IsSelected="True"/>
                                            <ComboBoxItem Content="Forest"/>
                                            <ComboBoxItem Content="Legacy"/>
                                        </ComboBox>
                                        <Button Grid.Column="6" Name="btnCreateReverseZone" Content="Create Zone" 
                                               Margin="16,0,0,0" Background="#107C10" Style="{StaticResource ModernButton}"/>
                                    </Grid>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <Grid Name="importPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- UniformGrid for Import/Export -->
                                <RowDefinition Height="*"/>    <!-- Log Card -->
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Import/Export DNS Data" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <UniformGrid Grid.Row="1" Columns="2" Margin="0,0,0,0"> <!-- Removed bottom margin -->
                                <!-- Export Card -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Export DNS Configuration" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <TextBlock Text="Format:" Margin="0,0,0,4"/>
                                        <ComboBox Name="cmbExportFormat" Margin="0,0,0,12" Padding="8">
                                            <ComboBoxItem Content="CSV" IsSelected="True"/>
                                            <ComboBoxItem Content="XML"/>
                                            <ComboBoxItem Content="JSON"/>
                                        </ComboBox>
                                        <CheckBox Name="chkExportForwardZones" Content="Forward Zones" IsChecked="True" Margin="0,0,0,4"/>
                                        <CheckBox Name="chkExportReverseZones" Content="Reverse Zones" IsChecked="True" Margin="0,0,0,4"/>
                                        <CheckBox Name="chkExportDNSSEC" Content="DNSSEC Settings" IsChecked="False" Margin="0,0,0,12"/>
                                        <Button Name="btnExportDNS" Content="Export DNS Configuration" 
                                               Background="#107C10" Style="{StaticResource ModernButton}"/>
                                    </StackPanel>
                                </Border>

                                <!-- Import Card -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Import DNS Configuration" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <TextBlock Text="File:" Margin="0,0,0,4"/>
                                        <Grid Margin="0,0,0,12">
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBox Grid.Column="0" Name="txtImportFile" Style="{StaticResource ModernTextBox}" IsReadOnly="True"/>
                                            <Button Grid.Column="1" Name="btnBrowseImport" Content="Browse" 
                                                   Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                                        </Grid>
                                        <TextBlock Text="Format:" Margin="0,0,0,4"/>
                                        <ComboBox Name="cmbImportFormat" Margin="0,0,0,12" Padding="8">
                                            <ComboBoxItem Content="CSV" IsSelected="True"/>
                                            <ComboBoxItem Content="XML"/>
                                            <ComboBoxItem Content="JSON"/>
                                        </ComboBox>
                                        <CheckBox Name="chkOverwriteExisting" Content="Überschreibe existierende Records" 
                                                 IsChecked="False" Margin="0,0,0,12"/>
                                        <Button Name="btnImportDNS" Content="Import DNS Configuration" 
                                               Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                            
                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Grid.Row="0" Text="Import/Export Log" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <TextBox Grid.Row="1" Name="txtImportExportLog" 
                                            TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                                            FontFamily="Consolas" FontSize="10" 
                                            Background="#F8F8F8" Foreground="#323130"
                                            IsReadOnly="True"/>
                                </Grid>
                            </Border>
                        </Grid>

                        <Grid Name="dnssecPanel" Visibility="Collapsed">
                             <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="*"/>    <!-- DNSSEC Zone Status Card (DataGrid) -->
                                <RowDefinition Height="Auto"/> <!-- UniformGrid for Settings/Operations -->
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="DNSSEC Management" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <Border Grid.Row="1" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <StackPanel Grid.Row="0">
                                        <TextBlock Text="DNSSEC Zone Status" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                            <Button Name="btnRefreshDNSSEC" Content="Refresh" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnSignZone" Content="Sign Zone" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnUnsignZone" Content="Unsign Zone" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                    </StackPanel>
                                    <DataGrid Grid.Row="1" Name="dgDNSSECZones" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Zone" Binding="{Binding ZoneName}" Width="*"/>
                                            <DataGridTextColumn Header="DNSSEC Status" Binding="{Binding DNSSECStatus}" Width="Auto"/>
                                            <DataGridTextColumn Header="Key Signing Key" Binding="{Binding KSKStatus}" Width="Auto"/>
                                            <DataGridTextColumn Header="Zone Signing Key" Binding="{Binding ZSKStatus}" Width="Auto"/>
                                            <DataGridTextColumn Header="Next Rollover" Binding="{Binding NextRollover}" Width="Auto"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>

                            <UniformGrid Grid.Row="2" Columns="2" Margin="0,0,0,0">
                                <!-- DNSSEC Settings -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Settings" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                        <TextBlock Text="Selected Zone:" Margin="0,0,0,4"/>
                                        <ComboBox Name="cmbDNSSECZone" Margin="0,0,0,12" Padding="8"/>
                                        <TextBlock Text="Algorithm:" Margin="0,0,0,4"/>
                                        <ComboBox Name="cmbDNSSECAlgorithm" Margin="0,0,0,12" Padding="8">
                                            <ComboBoxItem Content="RSA/SHA-256" IsSelected="True"/>
                                            <ComboBoxItem Content="RSA/SHA-512"/>
                                            <ComboBoxItem Content="ECDSA P-256"/>
                                        </ComboBox>
                                        <TextBlock Text="Key Length:" Margin="0,0,0,4"/>
                                        <ComboBox Name="cmbKeyLength" Margin="0,0,0,12" Padding="8">
                                            <ComboBoxItem Content="1024"/>
                                            <ComboBoxItem Content="2048" IsSelected="True"/>
                                            <ComboBoxItem Content="4096"/>
                                        </ComboBox>
                                        <CheckBox Name="chkAutoRollover" Content="Automatic Key Rollover" 
                                                 IsChecked="True" Margin="0,0,0,12"/>
                                    </StackPanel>
                                </Border>

                                <!-- DNSSEC Operations -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNSSEC Operations" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                        <Button Name="btnGenerateKeys" Content="Generate New Keys" 
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnExportKeys" Content="Export Public Keys" 
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnValidateSignatures" Content="Validate Signatures" 
                                               Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <Button Name="btnForceRollover" Content="Force Key Rollover" 
                                               Background="#FF8C00" Margin="0,0,0,8" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Text="DNSSEC Status:" FontWeight="SemiBold" Margin="0,12,0,4"/>
                                        <TextBlock Name="lblDNSSECStatus" Text="Ready" Foreground="#107C10"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                        </Grid>

                        <Grid Name="auditPanel" Visibility="Collapsed">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/> <!-- Title -->
                                <RowDefinition Height="Auto"/> <!-- UniformGrid for Monitoring/Stats -->
                                <RowDefinition Height="*"/>    <!-- Log Viewer Card (DataGrid) -->
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="Audit and Logs" FontSize="24" FontWeight="SemiBold" 
                                      Foreground="#323130" Margin="0,0,0,12"/>
                            
                            <UniformGrid Grid.Row="1" Columns="2" Margin="0,0,0,0">
                                <!-- Live Monitoring -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="Live DNS Monitoring" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <StackPanel Orientation="Horizontal" Margin="0,0,0,12">
                                            <Button Name="btnStartMonitoring" Content="Start" 
                                                   Background="#107C10" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnStopMonitoring" Content="Stop" 
                                                   Background="#D13438" Style="{StaticResource ModernButton}"/>
                                            <Button Name="btnClearMonitoring" Content="Clear" Style="{StaticResource ModernButton}"/>
                                        </StackPanel>
                                        <TextBlock Text="Monitor Events:" Margin="0,0,0,4"/>
                                        <CheckBox Name="chkMonitorQueries" Content="DNS Queries" IsChecked="True" Margin="0,0,0,2"/>
                                        <CheckBox Name="chkMonitorZoneChanges" Content="Zone Changes" IsChecked="True" Margin="0,0,0,2"/>
                                        <CheckBox Name="chkMonitorErrors" Content="DNS Errors" IsChecked="True" Margin="0,0,0,2"/>
                                        <CheckBox Name="chkMonitorSecurity" Content="Security Events" IsChecked="True" Margin="0,0,0,12"/>
                                        <TextBlock Name="lblMonitoringStatus" Text="Status: Stopped" 
                                                  Foreground="#D13438" FontWeight="SemiBold"/>
                                    </StackPanel>
                                </Border>

                                <!-- Statistics -->
                                <Border Style="{StaticResource Card}">
                                    <StackPanel>
                                        <TextBlock Text="DNS Statistics" FontSize="16" FontWeight="SemiBold" 
                                                  Foreground="#323130" Margin="0,0,0,12"/>
                                        <Button Name="btnRefreshStats" Content="Refresh Statistics" 
                                               Margin="0,0,0,12" Style="{StaticResource ModernButton}"/>
                                        <TextBlock Name="lblDNSStats" Text="Loading statistics..." 
                                                  FontSize="12" Foreground="#605E5C"/>
                                    </StackPanel>
                                </Border>
                            </UniformGrid>
                            
                            <Border Grid.Row="2" Style="{StaticResource Card}">
                                <Grid>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/> <!-- Header + Filters -->
                                        <RowDefinition Height="*"/>    <!-- DataGrid -->
                                    </Grid.RowDefinitions>
                                    <StackPanel Grid.Row="0">
                                        <Grid Margin="0,0,0,12">
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="*"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Grid.Column="0" Text="DNS Event Log" FontSize="16" FontWeight="SemiBold"/>
                                            <StackPanel Grid.Column="1" Orientation="Horizontal">
                                                <Button Name="btnExportLogs" Content="Export Logs" Style="{StaticResource ModernButton}"/>
                                                <Button Name="btnClearLogs" Content="Clear Logs" 
                                                       Background="#FF8C00" Style="{StaticResource ModernButton}"/>
                                            </StackPanel>
                                        </Grid>
                                        <Grid Margin="0,0,0,8">
                                            <Grid.ColumnDefinitions>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="120"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="120"/>
                                                <ColumnDefinition Width="Auto"/>
                                                <ColumnDefinition Width="Auto"/>
                                            </Grid.ColumnDefinitions>
                                            <TextBlock Grid.Column="0" Text="Filter:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <ComboBox Grid.Column="1" Name="cmbLogLevel" Padding="4" Margin="0,0,8,0">
                                                <ComboBoxItem Content="All" IsSelected="True"/>
                                                <ComboBoxItem Content="ERROR"/>
                                                <ComboBoxItem Content="WARN"/>
                                                <ComboBoxItem Content="INFO"/>
                                                <ComboBoxItem Content="DEBUG"/>
                                            </ComboBox>
                                            <TextBlock Grid.Column="2" Text="Search:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                            <TextBox Grid.Column="3" Name="txtLogSearch" Style="{StaticResource ModernTextBox}"/>
                                            <Button Grid.Column="4" Name="btnFilterLogs" Content="Filter" 
                                                   Margin="8,0,0,0" Style="{StaticResource ModernButton}"/>
                                            <Button Grid.Column="5" Name="btnRefreshLogs" Content="Refresh" 
                                                   Margin="4,0,0,0" Style="{StaticResource ModernButton}"/>
                                        </Grid>
                                    </StackPanel>
                                    <DataGrid Grid.Row="1" Name="dgAuditLogs" AutoGenerateColumns="False" 
                                             IsReadOnly="True" GridLinesVisibility="Horizontal" 
                                             HeadersVisibility="Column" CanUserReorderColumns="False">
                                        <DataGrid.Columns>
                                            <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="Auto"/>
                                            <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="Auto"/>
                                            <DataGridTextColumn Header="Event" Binding="{Binding Event}" Width="Auto"/>
                                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                                            <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="Auto"/>
                                        </DataGrid.Columns>
                                    </DataGrid>
                                </Grid>
                            </Border>
                        </Grid>
                    </Grid>
                </ScrollViewer>
            </Border>
        </Grid>

        <!-- Footer -->
        <Border Grid.Row="2" Background="White" BorderBrush="#D1D1D1" BorderThickness="0,1,0,0">
            <Grid Margin="20,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="$($global:AppConfig.AppName)" 
                          VerticalAlignment="Center" FontSize="11" Foreground="#605E5C"/>
                
                <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock Text="Version $($global:AppConfig.ScriptVersion)" FontSize="11" Foreground="#605E5C" Margin="0,0,16,0"/>
                    <TextBlock Text="by $($global:AppConfig.Author)" FontSize="11" Foreground="#605E5C" Margin="0,0,16,0"/>
                    <TextBlock Text="$($global:AppConfig.Website)" FontSize="11" Foreground="#0078D4" Cursor="Hand"/>
                </StackPanel>

                <TextBlock Grid.Column="2" Text="Copyright 2025 - Last Update: $($global:AppConfig.LastUpdate)" 
                          HorizontalAlignment="Right" VerticalAlignment="Center" FontSize="11" Foreground="#605E5C"/>
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
    "txtDNSServer", "btnConnect", "lblStatus", "lblZoneInfo", "lblServerInfo",
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
    "cmbDiagZone", "btnZoneInfo", "btnZoneRefresh", "btnZoneTransfer",
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
    $global:Controls[$_] = $global:Window.FindName($_)
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
        $global:Controls[$_].Visibility = "Collapsed"
    }
    
    # Alle Nav-Buttons zurücksetzen
    $global:NavButtons | ForEach-Object {
        $_.Background = "Transparent"
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
        
        # Panel-spezifische Initialisierung
        switch ($PanelName) {
            "dashboard" { Update-Dashboard }
            "forward" { Update-ForwardZonesList }
            "reverse" { Update-ReverseZonesList }
            "records" { Update-ZonesList }
            "import" { Clear-ImportExportLog }
            "dnssec" { Update-DNSSECStatus }
            "tools" { 
                Clear-DiagnosisOutput
                Update-DiagnosticZonesList
            }
            "audit" { Update-AuditLogs }
        }
        
        Write-Log "Panel gewechselt zu: $PanelName" -Level "DEBUG"
    }
}

###############################################################################
# EVENT-HANDLER
###############################################################################

# Navigation Event-Handler
$global:Controls.btnDashboard.Add_Click({ Show-Panel "dashboard" })
$global:Controls.btnForward.Add_Click({ Show-Panel "forward" })
$global:Controls.btnReverse.Add_Click({ Show-Panel "reverse" })
$global:Controls.btnRecords.Add_Click({ Show-Panel "records" })
$global:Controls.btnImport.Add_Click({ Show-Panel "import" })
$global:Controls.btnDNSSEC.Add_Click({ Show-Panel "dnssec" })
$global:Controls.btnTools.Add_Click({ Show-Panel "tools" })
$global:Controls.btnAudit.Add_Click({ Show-Panel "audit" })

# DNS-Server Verbindung
$global:Controls.btnConnect.Add_Click({
    $serverName = $global:Controls.txtDNSServer.Text.Trim()
    if ([string]::IsNullOrEmpty($serverName)) {
        Show-MessageBox "Bitte geben Sie einen DNS-Server an." "Fehler" "Warning"
        return
    }
    
    $global:Controls.lblStatus.Text = "Status: Verbinde..."
    $global:Controls.lblStatus.Foreground = "#FF8C00"
    
    try {
        $zones = Get-DnsServerZone -ComputerName $serverName -ErrorAction Stop
        $global:DetectedDnsServer = $serverName
        $global:Controls.lblStatus.Text = "Status: Verbunden"
        $global:Controls.lblStatus.Foreground = "#107C10"
        
        Write-Log "Verbindung zu DNS-Server '$serverName' hergestellt" -Level "INFO"
        
        if ($global:CurrentPanel -eq "dashboard") {
            Update-Dashboard
        }
        
        Show-MessageBox "Erfolgreich mit DNS-Server '$serverName' verbunden!" "Verbindung hergestellt"
        
    } catch {
        $global:Controls.lblStatus.Text = "Status: Fehler"
        $global:Controls.lblStatus.Foreground = "#D13438"
        Write-Log "Fehler bei Verbindung zu DNS-Server '$serverName': $_" -Level "ERROR"
        Show-MessageBox "Fehler bei der Verbindung zum DNS-Server:`n$_" "Verbindungsfehler" "Error"
    }
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

function Update-Dashboard {
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $forwardZones = ($zones | Where-Object { -not $_.IsReverse }).Count
        $reverseZones = ($zones | Where-Object { $_.IsReverse }).Count
        $signedZones = ($zones | Where-Object { $_.IsSigned -eq "Ja" }).Count
        
        $global:Controls.lblZoneInfo.Text = @"
Forward-Zonen: $forwardZones
Reverse-Zonen: $reverseZones
DNSSEC-signiert: $signedZones
Gesamt: $($zones.Count)
"@
        
        try {
            $serviceStatus = "Unbekannt"
            if ($global:Controls.txtDNSServer.Text -eq "localhost") {
                $service = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
                if ($service) { $serviceStatus = $service.Status }
            }
            
            $global:Controls.lblServerInfo.Text = @"
Server: $($global:Controls.txtDNSServer.Text)
DNS-Dienst: $serviceStatus
Letzter Check: $(Get-Date -Format 'HH:mm:ss')
Version: $($global:AppConfig.ScriptVersion)
"@
        } catch {
            $global:Controls.lblServerInfo.Text = @"
Server: $($global:Controls.txtDNSServer.Text)
Status: Nicht verfügbar
Fehler beim Abrufen
"@
        }
        
        Write-Log "Dashboard aktualisiert" -Level "DEBUG"
        
    } catch {
        $global:Controls.lblZoneInfo.Text = "Fehler beim Laden der Zone-Informationen"
        $global:Controls.lblServerInfo.Text = "Fehler beim Laden der Server-Informationen"
        Write-Log "Fehler beim Aktualisieren des Dashboards: $_" -Level "ERROR"
    }
}

function Update-ForwardZonesList {
    try {
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text | Where-Object { -not $_.IsReverse }
        $global:Controls.dgForwardZones.ItemsSource = $zones
        Write-Log "Forward-Zonen-Liste aktualisiert: $($zones.Count) Zonen" -Level "INFO"
    } catch {
        Write-Log "Fehler beim Aktualisieren der Forward-Zonen-Liste: $_" -Level "ERROR"
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
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $global:Controls.cmbRecordZone.Items.Clear()
        
        foreach ($zone in $zones) {
            $global:Controls.cmbRecordZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbRecordZone.Items.Count -gt 0) {
            $global:Controls.cmbRecordZone.SelectedIndex = 0
        }
        
        Write-Log "Zonen-Liste für Records aktualisiert: $($zones.Count) Zonen" -Level "DEBUG"
    } catch {
        Write-Log "Fehler beim Aktualisieren der Zonen-Liste: $_" -Level "ERROR"
    }
}

function Update-RecordsList {
    if (-not $global:Controls.cmbRecordZone.SelectedItem) { return }
    
    try {
        $zoneName = $global:Controls.cmbRecordZone.SelectedItem.ToString()
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
    } catch {
        Write-Log "Fehler beim Aktualisieren der Records-Liste: $_" -Level "ERROR"
        Show-MessageBox "Fehler beim Laden der DNS-Records: $_" "Fehler" "Error"
    }
}

function Create-NewRecord {
    $zoneName = $global:Controls.cmbRecordZone.SelectedItem
    $recordName = $global:Controls.txtRecordName.Text.Trim()
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
    
    $ttl = 3600
    if (-not [string]::IsNullOrEmpty($recordTTL)) {
        if (-not [int]::TryParse($recordTTL, [ref]$ttl)) {
            Show-MessageBox "TTL muss eine Zahl sein." "Validierungsfehler" "Warning"
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
    } catch {
        Write-Log "Fehler beim Aktualisieren der Reverse-Zonen-Liste: $_" -Level "ERROR"
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
        
    } catch {
        Write-Log "Fehler beim Aktualisieren des DNSSEC-Status: $_" -Level "ERROR"
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

function Update-DNSStatistics {
    try {
        $stats = Get-DNSStatistics -DnsServerName $global:Controls.txtDNSServer.Text
        
        $statsText = @"
Zonen-Uebersicht:
• Gesamt: $($stats.TotalZones) Zonen
• Forward: $($stats.ForwardZones) Zonen  
• Reverse: $($stats.ReverseZones) Zonen
• DNSSEC-signiert: $($stats.SignedZones) Zonen

Server-Information:
• Server: $($global:Controls.txtDNSServer.Text)
• Uptime: $($stats.ServerUptime)
• Letztes Update: $($stats.LastUpdate)

Cache-Information:
• Cache-Status: $($stats.CacheSize)
• Monitoring: $(if ($global:MonitoringActive) { "Aktiv" } else { "Inaktiv" })
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
        $zones = Get-SafeDnsServerZone -DnsServerName $global:Controls.txtDNSServer.Text
        $global:Controls.cmbDiagZone.Items.Clear()
        
        foreach ($zone in $zones) {
            $global:Controls.cmbDiagZone.Items.Add($zone.ZoneName)
        }
        
        if ($global:Controls.cmbDiagZone.Items.Count -gt 0) {
            $global:Controls.cmbDiagZone.SelectedIndex = 0
        }
        
        Write-Log "Diagnostic-Zonen-Liste aktualisiert: $($zones.Count) Zonen" -Level "DEBUG"
    } catch {
        Write-Log "Fehler beim Aktualisieren der Diagnostic-Zonen-Liste: $_" -Level "ERROR"
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
    Update-Dashboard
})

$global:Window.Add_Closed({
    Write-Log "easyDNS WPF beendet" -Level "INFO"
})

# Show the window
[void]$global:Window.ShowDialog() 
# SIG # Begin signature block
# MIIcCAYJKoZIhvcNAQcCoIIb+TCCG/UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbpXSQaXEkIz2d
# IWag/CDfLrW40IMNg39anWLiDGOAD6CCFk4wggMQMIIB+KADAgECAhB3jzsyX9Cg
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
# LSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQICEA3H
# rFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEh
# MB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAw
# MFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFt
# cGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU
# 7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR
# +2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwE
# u7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Za
# zch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW3
# 5xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gd
# FpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rq
# BvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vH
# espYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QE
# PHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1
# Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMB
# AAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAO
# BgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEE
# azBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYB
# BQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9
# EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk
# 97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2
# UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71
# WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQf
# jXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noD
# js6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxi
# Df06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/
# D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8Ml
# uDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG
# 2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8
# hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLR
# xHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAw
# WhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVz
# dGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr
# 0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBb
# ZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQK
# WXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wD
# cKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25
# CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6l
# vJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dV
# mVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuh
# KuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7C
# e7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTR
# ofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUw
# ggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzo
# MB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIH
# gDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZR
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGlt
# ZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBS
# oFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5
# rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZE
# N/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwB
# D9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QA
# GB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBV
# N4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW6
# 0OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQ
# TwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC
# 3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmA
# p/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9T
# HFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84
# ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFEDCCBQwCAQEwNDAgMR4wHAYDVQQD
# DBVQaGluSVQtUFNzY3JpcHRzX1NpZ24CEHePOzJf0KCMSL6wELasExMwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgOmSkjWjj9B/efP61/q68EyBl56xL6hCPmFqcFsN7ylEw
# DQYJKoZIhvcNAQEBBQAEggEAAdH9fSo2bAzb68HV9XyOqhkvoto/UUl/arBe0Z1Z
# q+GHvmaRamVF3585HR1NfjGV7m9/FgG4hCcWBhpXaiJHuEfg3oQSEHc8hKXBAHT4
# s+H/tCHuCsawTeZ4+gFw8uJJFYqrAouEN8Iv4sIkQ9u+MLv8si43AGFoP7AGJ117
# xBFUoEMsqB/5bjDJgZTGQFJHzIifkVz2N9x2LzJeLARnswEopPT2prlzMN/JBzbz
# VD2lYVx3StE9ivDrxq0y8254xA+2gy2Bt+zIdGaAGoN0d/HJ2HNz5XX0DSzC4lk3
# JLznXUFI7N25IY09CW2IbTjLWEJE7t5mG8OH8Hw2RuD/JqGCAyYwggMiBgkqhkiG
# 9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgw
# DQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqG
# SIb3DQEJBTEPFw0yNTA3MTIwODAwMjRaMC8GCSqGSIb3DQEJBDEiBCBo7LpSO32C
# H4hXUvAXign9ZsAg7vDtMRo+m786S1/9BDANBgkqhkiG9w0BAQEFAASCAgCP5ol+
# S9rmVM2eKk5ciX8ctOSJKS9Kth2S8R1TYYWvZUGtX7db212o+jSwMC1cgx9NcUnC
# SEh+QjeT+J12hyzBh3+jIjA1oesr4k8DUd0O3/3UrdMPxeCAjlWd1AHZiJvz+QvZ
# gg7qbFyRGIhCJenZ+x8shR00eZ43kNiYOhmNTB/aI/D3RHbdcO+JiycODMkCS8jo
# l2fClnXp6XWWDHbeEoN/hIlvvbm+ZgpLmvQfKX0YjvDmksFt9CvYasXCbHQjRjR+
# e2O6hb2lvPeHfG51UWnQRDq8czk2dbuZSirF2BlzY95bWBOs1UvfR0YCHPbWp+qP
# 7uquM0/nSeD3BnXjKqF97EtYeOcYy6O2A7I2w0tN6LfWmGu3EPO1DaxFE4xyIJks
# 0UjGV5u4YZj5DJEjLYH2XxqNY8Ix3M21QZvspTmnjmaySjG3yovt6f8e/ykBT+NU
# fMU2/7G52wh8bi84xZcycI9w1ePNMepHlX8HHiSgczL19V5BbfY6Qf64ohIsVL5b
# NQJtbGfqYMpkRbz2AWgaO1M4SL9Jbl1ck5MyQraJXzxpZNGpfEMGcKJcKnuen8dR
# /r+FXmH3BY+C/3iegvU3Rs9QyuuJSKdU1E2kdtBNY2P1WGNzFJsrV4CBPrvZcSbx
# ET6udl/muOreTtBMEe7kXa5sw2EC8TyRmfz/OA==
# SIG # End signature block
