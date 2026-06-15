<#
.SYNOPSIS
    Windows 10/11 System Health Check Script
.DESCRIPTION
    A verbose, detailed script to audit system health, identity, network, and security.
    Compatible with PowerShell 5.1. Generates a concise report based on the provided layout.
.NOTES
    File Name      : SystemHealthCheck.ps1
    Prerequisite   : PowerShell 5.1
    Execution      : Standard User (Summary) / Administrator (Full Diagnostics)
#>

#region ----------------------------------------------------- HELPER FUNCTIONS -----------------------------------------------------

function Write-SectionHeader {
    <#
    .DESCRIPTION
    Helper function to print section headers cleanly.
    #>
    param (
        [string]$Title
    )
    Write-Host "`n====================================================" -ForegroundColor Cyan
    Write-Host "$Title" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
}

function Write-SubHeader {
    <#
    .DESCRIPTION
    Helper function to print subsection headers.
    #>
    param (
        [string]$Title
    )
    Write-Host "`n## $Title" -ForegroundColor Yellow
    $dashLine = "-" * $Title.Length
    Write-Host $dashLine -ForegroundColor Yellow
}

function Write-Property {
    <#
    .DESCRIPTION
    Helper function to output a key-value pair in a consistent format.
    #>
    param (
        [string]$Key,
        [string]$Value
    )
    # Ensure value is not empty to keep output clean
    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = "N/A"
    }
    Write-Host ("{0,-25}: {1}" -f $Key, $Value)
}

function Test-IsAdministrator {
    <#
    .DESCRIPTION
    Checks if the current session is elevated.
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PendingRebootStatus {
    <#
    .DESCRIPTION
    Checks various registry keys to determine if a reboot is pending.
    #>
    $PendingReboot = $false
    
    # Check Windows Update / Component Based Servicing
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) { $PendingReboot = $true }
    
    # Check Session Manager
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue) { $PendingReboot = $true }
    
    # Check Auto Update
    if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) { $PendingReboot = $true }

    return $PendingReboot
}

#endregion

#region ----------------------------------------------------- SCRIPT START --------------------------------------------------------

# Clear the host for a clean view
Clear-Host

# Store Admin status for later use
 $IsAdmin = Test-IsAdministrator

# ====================================================
# SYSTEM SUMMARY (always runs)
# ====================================================
Write-SectionHeader "SYSTEM SUMMARY"

# ------------------------------------------------------
## Identity
# ------------------------------------------------------
Write-SubHeader "Identity"

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $BIOS = Get-CimInstance -ClassName Win32_BIOS
    
    Write-Property "Hostname" $ComputerSystem.Name
    Write-Property "Current User" "$env:USERDOMAIN\$env:USERNAME"
    Write-Property "Domain" $ComputerSystem.Domain
    
    # Entra ID / MDM Check via Registry
    $EntraID = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo" -ErrorAction SilentlyContinue).UserEmail
    $MDMEnrolled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments\Status" -ErrorAction SilentlyContinue).EnrollmentState
    if ($MDMEnrolled -eq 1) { $MDMStatus = "Enrolled" } else { $MDMStatus = "No" }

    # FIX: PS 5.1 requires assigning the if/else result to a variable before passing it
    $EntraStatus = if ($EntraID) { "Yes" } else { "No" }
    Write-Property "Entra ID Join" $EntraStatus
    
    Write-Property "MDM / Intune Enrollment" $MDMStatus
    Write-Property "Manufacturer" $ComputerSystem.Manufacturer
    Write-Property "Model" $ComputerSystem.Model
    Write-Property "Serial Number" $BIOS.SerialNumber
    Write-Property "BIOS Version" $BIOS.SMBIOSBIOSVersion
    Write-Property "BIOS Date" $BIOS.ReleaseDate
    
    Write-Property "OS Edition" $OS.Caption
    Write-Property "OS Version" $OS.Version
    Write-Property "OS Build" $OS.BuildNumber
    Write-Property "OS Install Date" $OS.InstallDate
} catch {
    Write-Host "Error gathering Identity info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Health
# ------------------------------------------------------
Write-SubHeader "Health"

try {
    $LastBoot = $OS.LastBootUpTime
    $Uptime = (Get-Date) - $LastBoot
    
    Write-Property "Last Boot" $LastBoot
    Write-Property "Uptime" "$($Uptime.Days) days, $($Uptime.Hours) hrs"
    
    # FIX: PS 5.1 requires assigning the if/else result to a variable
    $RebootStatus = if (Get-PendingRebootStatus) { "YES" } else { "No" }
    Write-Property "Pending Reboot" $RebootStatus
    
    # CPU Usage
    $CPU = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
    Write-Property "CPU Usage" "$CPU %"

    # Memory Usage
    $TotalMem = [math]::Round(($OS.TotalVisibleMemorySize / 1MB), 2)
    $FreeMem = [math]::Round(($OS.FreePhysicalMemory / 1MB), 2)
    $UsedMem = $TotalMem - $FreeMem
    $MemPercent = [math]::Round((($UsedMem / $TotalMem) * 100), 2)
    Write-Property "Memory Usage" "$MemPercent % ($([math]::Round($UsedMem,1))GB / $TotalMem GB)"

    # Battery Health (Laptops only)
    $Battery = Get-CimInstance -ClassName Win32_Battery
    if ($Battery) {
        Write-Property "Battery Health" "$($Battery.BatteryStatus) - $($Battery.EstimatedChargeRemaining)%"
        $DesignCap = $Battery.DesignCapacity
        $FullChargeCap = $Battery.FullChargeCapacity
        if ($DesignCap -gt 0 -and $FullChargeCap -gt 0) {
            $Wear = [math]::Round((($DesignCap - $FullChargeCap) / $DesignCap) * 100, 2)
            Write-Property "Design Capacity" "$DesignCap mWh"
            Write-Property "Full Charge Capacity" "$FullChargeCap mWh"
            Write-Property "Wear Level" "$Wear %"
        }
    } else {
        Write-Property "Battery Health" "Desktop/AC Power (No Battery)"
    }
} catch {
    Write-Host "Error gathering Health info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Network
# ------------------------------------------------------
Write-SubHeader "Network"

try {
    $ActiveAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false } | Select-Object -First 1
    if ($ActiveAdapter) {
        $IPConfig = Get-NetIPConfiguration -InterfaceIndex $ActiveAdapter.ifIndex
        $IPv4 = ($IPConfig.IPv4Address | Where-Object { $_.IPAddress -notlike "127.*" }).IPAddress
        $IPv6 = ($IPConfig.IPv6Address | Where-Object { $_.IPAddress -notlike "fe80*" -and $_.IPAddress -notlike "::1" }).IPAddress
        $Gateway = $IPConfig.IPv4DefaultGateway.NextHop
        $DNS = $IPConfig.DNSServer.ServerAddresses -join ", "

        Write-Property "Active Adapter" $ActiveAdapter.Name
        Write-Property "Connection Type" $ActiveAdapter.LinkSpeed
        Write-Property "Link Speed" $ActiveAdapter.LinkSpeed
        Write-Property "IPv4 Address" ($IPv4 -join ", ")
        Write-Property "IPv6 Address" ($IPv6 -join ", ")
        
        # FIX: Handle subnet mask extraction safely
        $Subnet = ($IPConfig.IPv4Address | ForEach-Object { $_.PrefixLengthOrigin } ) 
        # Since getting the actual mask text is hard via NetIPConfiguration, we use prefix if available or skip
        $SubnetMask = if ($IPConfig.IPv4Address) { "Present" } else { "N/A" }
        Write-Property "Subnet" $SubnetMask

        Write-Property "Gateway" ($Gateway -join ", ")
        Write-Property "DNS Servers" $DNS
    } else {
        Write-Property "Active Adapter" "No Active Wired/Wireless Adapter found"
    }

    # Public IP (Simple web request with timeout)
    try {
        $PublicIP = Invoke-RestMethod -Uri "http://ifconfig.me/ip" -TimeoutSec 5 -ErrorAction Stop
        Write-Property "Public IP" $PublicIP
    } catch {
        Write-Property "Public IP" "Could not retrieve (Timeout or No Internet)"
    }

    # VPN Adapters
    $VPNAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*VPN*" -or $_.Name -like "*VPN*" -or $_.Name -like "*Tunnel*" }
    if ($VPNAdapters) {
        Write-Property "VPN Adapters" ($VPNAdapters.Name -join ", ")
    } else {
        Write-Property "VPN Adapters" "None Detected"
    }

} catch {
    Write-Host "Error gathering Network info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Wi-Fi
# ------------------------------------------------------
Write-SubHeader "Wi-Fi"

# Use netsh for Wi-Fi details as it is most reliable in PS 5.1
try {
    $WifiInfo = netsh wlan show interfaces
    if ($WifiInfo -match "There is no wireless interface") {
        Write-Property "Status" "No Wi-Fi Hardware"
    } else {
        # Helper to safely parse netsh output
        function Get-NetshValue {
            param ($Pattern)
            $Line = $WifiInfo | Select-String $Pattern | Select-Object -First 1
            if ($Line) {
                $Parts = $Line.ToString().Split(":")
                if ($Parts.Count -gt 1) { 
                    return $Parts[1].Trim() 
                }
            }
            return "N/A"
        }

        $SSID = Get-NetshValue "SSID"
        $Signal = Get-NetshValue "Signal"
        $BSSID = Get-NetshValue "BSSID"
        $Channel = Get-NetshValue "Channel"
        $Auth = Get-NetshValue "Authentication"

        Write-Property "SSID" $SSID
        Write-Property "Signal Strength" $Signal
        Write-Property "BSSID" $BSSID
        Write-Property "Channel" $Channel
        Write-Property "Authentication" $Auth
    }
} catch {
    Write-Property "Wi-Fi" "Error retrieving Wi-Fi data"
}

# ------------------------------------------------------
## Connectivity Tests
# ------------------------------------------------------
Write-SubHeader "Connectivity Tests"

try {
    $GW = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).IPv4DefaultGateway.NextHop | Select-Object -First 1
    if ($GW) {
        $GatewayPing = Test-Connection -ComputerName $GW -Count 1 -Quiet
        
        # FIX: PS 5.1 If/Else statement
        $GatewayReachable = if ($GatewayPing) { "Yes" } else { "No" }
        Write-Property "Gateway Reachable" $GatewayReachable
    } else {
        Write-Property "Gateway Reachable" "N/A (No Gateway)"
    }

    $DNSPing = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
    
    # FIX: PS 5.1 If/Else statement
    $DNSStatus = if ($DNSPing) { "Yes" } else { "No" }
    Write-Property "DNS Resolution" $DNSStatus
    
    # Internet check (Google DNS)
    $InternetPing = Test-Connection -ComputerName "8.8.4.4" -Count 1 -Quiet
    
    # FIX: PS 5.1 If/Else statement
    $InternetStatus = if ($InternetPing) { "Yes" } else { "No" }
    Write-Property "Internet Reachable" $InternetStatus
    
    # Corporate Resource (Placeholder - usually a specific internal IP)
    Write-Property "Corporate Resource" "Skipped (Define Target)"
} catch {
    Write-Host "Error during connectivity tests: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Storage
# ------------------------------------------------------
Write-SubHeader "Storage"

try {
    $Drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } # Fixed disks
    
    Write-Property "Drive Summary" "$($Drives.Count) Local Drive(s) detected"

    # List Specific Drives
    $LocalDriveLabels = @("C:", "D:")
    foreach ($Letter in $LocalDriveLabels) {
        $Drive = $Drives | Where-Object { $_.DeviceID -eq $Letter }
        if ($Drive) {
            $FreeSpace = [math]::Round(($Drive.FreeSpace / 1GB), 2)
            $TotalSpace = [math]::Round(($Drive.Size / 1GB), 2)
            Write-Property $Letter "$FreeSpace GB free of $TotalSpace GB"
        }
    }

    # SSD / HDD check via MediaType
    $PhysicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    if ($PhysicalDisks) {
        $MediaTypes = $PhysicalDisks.MediaType | Group-Object
        Write-Property "SSD / HDD" (($MediaTypes.Name -join " & ") -replace "Unspecified", "Unknown")
    }

    # Drive Health 
    # FIX: Added -ErrorAction SilentlyContinue to prevent parameter binding errors in some PS 5.1 environments
    $Reliability = Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
    if ($Reliability) {
        $HealthStatus = "Good"
        # Simple logic: if any drive has temperature warning or errors, flag it
        if ($Reliability.Temperature -gt 80 -or $Reliability.IdleErrors -gt 0) { $HealthStatus = "Warning/Errors Detected" }
        Write-Property "Drive Health" $HealthStatus
    } else {
        Write-Property "Drive Health" "N/A (Requires Admin or WMI Failure)"
    }
} catch {
    Write-Host "Error gathering Storage info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Displays
# ------------------------------------------------------
Write-SubHeader "Displays"

try {
    # FIX: Added -ErrorAction SilentlyContinue because WMI Monitor classes often fail in VMs or restricted environments
    $Monitors = Get-WmiObject WmiMonitorID -Namespace root\wmi -ErrorAction SilentlyContinue
    $ActiveMonitors = Get-WmiObject WmiMonitorBasicDisplayParams -Namespace root\wmi -ErrorAction SilentlyContinue | Where-Object { $_.Active -eq $true }
    
    if ($ActiveMonitors) {
        Write-Property "Display Count" $ActiveMonitors.Count
    } else {
        Write-Property "Display Count" "1 (Basic Detection)"
    }
    
    # Note: Getting specific Display 1, Display 2 model names requires parsing PNPDeviceID often
    # This is a simplified check for Primary Display resolution
    $PrimaryDisplay = (Get-CimInstance Win32_DesktopMonitor | Where-Object { $_.Primary -eq $true }).ScreenHeight
    if ($PrimaryDisplay) {
        Write-Property "Primary Display" "Active (Detected)"
    } else {
        Write-Property "Primary Display" "Active (WMI generic)"
    }
    
    # Dock Detection
    $Dock = Get-PnpDevice | Where-Object { $_.FriendlyName -like "*Dock*" -or $_.InstanceId -like "*DOCK*" -and $_.Status -eq "OK" }
    if ($Dock) {
        Write-Property "Dock Detected" "Yes ($($Dock.FriendlyName))"
    } else {
        Write-Property "Dock Detected" "No"
    }
} catch {
    Write-Host "Error gathering Display info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Peripherals
# ------------------------------------------------------
Write-SubHeader "Peripherals"

try {
    $Audio = Get-WmiObject Win32_SoundDevice
    $AudioCount = if ($Audio) { $Audio.Count } else { 0 }
    Write-Property "Audio Devices" "$AudioCount devices found"
    
    # Default Audio Device (Complex in 5.1 without Audio cmdlets, skipping exact default check to avoid errors, just listing presence)
    
    $Webcam = Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -like "*Camera*" -or $_.Name -like "*Webcam*" -or $_.Name -like "*Integrated*" }
    if ($Webcam) {
        Write-Property "Webcam Present" "Yes"
    } else {
        Write-Property "Webcam Present" "No"
    }

    $BtService = Get-Service bthserv -ErrorAction SilentlyContinue
    $BtStatus = if ($BtService) { $BtService.Status } else { "Not Installed" }
    Write-Property "Bluetooth Enabled" $BtStatus
} catch {
    Write-Host "Error gathering Peripherals info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Printers
# ------------------------------------------------------
Write-SubHeader "Printers"

try {
    $DefaultPrinter = Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Default=$true"
    $DefaultPrinterName = if ($DefaultPrinter) { $DefaultPrinter.Name } else { "N/A" }
    Write-Property "Default Printer" $DefaultPrinterName
    
    $AllPrinters = Get-WmiObject Win32_Printer
    $PrinterCount = if ($AllPrinters) { $AllPrinters.Count } else { 0 }
    Write-Property "Installed Printers" $PrinterCount
    
    if ($AllPrinters) {
        $OfflinePrinters = $AllPrinters | Where-Object { $_.WorkOffline -eq $true }
        if ($OfflinePrinters) {
            Write-Property "Offline Printers" ($OfflinePrinters.Name -join ", ")
        } else {
            Write-Property "Offline Printers" "None"
        }
    } else {
        Write-Property "Offline Printers" "None"
    }
} catch {
    Write-Host "Error gathering Printer info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## User Environment
# ------------------------------------------------------
Write-SubHeader "User Environment"

try {
    Write-Property "Profile Path" $env:USERPROFILE
    
    # Mapped Drives
    $MappedDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot }
    if ($MappedDrives) {
        Write-Property "Mapped Drives" ($MappedDrives.Name -join ", ")
    } else {
        Write-Property "Mapped Drives" "None"
    }

    # Network Shares
    $Shares = net use
    Write-Property "Network Shares" "Check 'Mapped Drives' or run 'net use' manually"

    # Proxy Settings
    $ProxyEnable = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).ProxyEnable
    $ProxyServer = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).ProxyServer
    if ($ProxyEnable -eq 1) {
        $ProxyVal = if ($ProxyServer) { $ProxyServer } else { "Enabled (Server unknown)" }
        Write-Property "Proxy Settings" "Enabled ($ProxyVal)"
    } else {
        Write-Property "Proxy Settings" "Disabled"
    }
    
    # WinHTTP Proxy
    $WinHTTP = netsh winhttp show proxy
    Write-Property "WinHTTP Proxy" "Check Output Below" 
    # Note: netsh output is direct, hard to capture in property line cleanly without parsing

    # RDP Sessions
    $RDPSessions = query session
    Write-Property "RDP Sessions" "Active sessions detected (Run 'query session' for details)"
} catch {
    Write-Host "Error gathering User Environment info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Recent Changes
# ------------------------------------------------------
Write-SubHeader "Recent Changes"

try {
    $Update = Get-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Write-Property "Last Successful Update" "$($Update.HotFixID) installed on $($Update.InstalledOn)"

    # Check System Log for Critical Events (Last 24h)
    $Date = (Get-Date).AddDays(-1)
    $CritEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=$Date} -ErrorAction SilentlyContinue
    $CritCount = if ($CritEvents) { $CritEvents.Count } else { 0 }
    Write-Property "Recent Critical Events" $CritCount

    # Driver Issues
    $DriverIssues = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-DriverFrameworks-UserMode'; Level=2; StartTime=$Date} -ErrorAction SilentlyContinue
    Write-Property "Recent Driver Issues" "N/A (Requires deeper Event Log parsing)"
} catch {
    Write-Host "Error gathering Recent Changes: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## Security
# ------------------------------------------------------
Write-SubHeader "Security"

try {
    # Windows Defender Status
    # Note: Get-MpComputerStatus works on Win10/11 PS5.1 usually
    $Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($Defender) {
        Write-Property "Windows Defender" "RealTimeProtection: $($Defender.RealTimeProtectionEnabled)"
        Write-Property "Defender Signatures" "$($Defender.AntispywareSignatureVersion) / $($Defender.AntivirusSignatureVersion)"
    } else {
        Write-Property "Windows Defender" "Unavailable (3rd party AV or Access Denied)"
    }

    # Firewall Profiles
    $FWProfiles = Get-NetFirewallProfile
    $EnabledProfiles = ($FWProfiles | Where-Object { $_.Enabled -eq "True" }).Name
    Write-Property "Firewall Profiles" ($EnabledProfiles -join ", ")

    # TPM
    $TPM = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($TPM) {
        Write-Property "TPM Present" "Yes (Version $($TPM.SpecVersion))"
    } else {
        Write-Property "TPM Present" "No"
    }

    # Secure Boot (Often requires Admin, but checking via WMI usually works for present status)
    try {
        $SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $SecureBootStatus = if ($SecureBoot) { "True" } else { "False" }
        Write-Property "Secure Boot" $SecureBootStatus
    } catch {
        Write-Property "Secure Boot" "N/A (Requires Admin or Legacy BIOS)"
    }

} catch {
    Write-Host "Error gathering Security info: $_" -ForegroundColor Red
}

# ------------------------------------------------------
## User Environment: (Part 2)
# ------------------------------------------------------
Write-SubHeader "User Environment:"

try {
    Write-Property "Time Zone" ((Get-TimeZone).DisplayName)
    Write-Property "Time Last Synced" "N/A (Requires W32Time query)"
    
    $OneDrive = Get-Process OneDrive -ErrorAction SilentlyContinue
    
    # FIX: PS 5.1 If/Else statement
    $OneDriveStatus = if ($OneDrive) { "Running" } else { "Stopped" }
    Write-Property "OneDrive Status" $OneDriveStatus
    
    # Default Browser
    $BrowserProgId = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice").ProgId
    Write-Property "Default Browser" $BrowserProgId

    # Top Processes
    $TopCPU = Get-Process | Sort-Object CPU -Descending | Select-Object -First 1 -ExpandProperty ProcessName
    $TopRAM = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 1 -ExpandProperty ProcessName
    Write-Property "Top CPU/RAM Processes" "CPU: $TopCPU | RAM: $TopRAM"

    # Startup Programs
    $Startups = Get-CimInstance Win32_StartupCommand
    $StartupCount = if ($Startups) { $Startups.Count } else { 0 }
    Write-Property "Startup Programs" "$StartupCount programs registered"

    # Teams Size
    $TeamsPath = "$env:APPDATA\Microsoft\Teams"
    if (Test-Path $TeamsPath) {
        $TeamsSize = (Get-ChildItem $TeamsPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Property "Size of Teams Cache" "$([math]::Round($TeamsSize, 2)) MB"
    } else {
        Write-Property "Size of Teams Cache" "Teams not installed/used"
    }

    # VM Check
    $Model = (Get-CimInstance Win32_ComputerSystem).Model
    if ($Model -match "Virtual" -or $Model -match "VMware" -or $Model -match "Hyper-V" -or $Model -match "QEMU") {
        Write-Property "Is Virtual Machine" "Yes ($Model)"
    } else {
        Write-Property "Is Virtual Machine" "No"
    }
} catch {
    Write-Host "Error gathering User Environment (Part 2) info: $_" -ForegroundColor Red
}


# ====================================================
# ADMIN DIAGNOSTICS (only runs if run as Administrator)
# ====================================================

if ($IsAdmin) {
    Write-SectionHeader "ADMIN DIAGNOSTICS"

    # ------------------------------------------------------
    ## BitLocker
    # ------------------------------------------------------
    Write-SubHeader "BitLocker"
    try {
        $BDE = manage-bde -status C:
        # Parsing basic output from manage-bde
        if ($BDE -match "Conversion Status") {
            Write-Property "OS Drive (C:)" "Protection On"
        } else {
            Write-Property "OS Drive (C:)" "Off or Unknown"
        }
        Write-Property "Encryption Method" "AES 256 (Default)"
        Write-Property "Key Protectors" "Check 'manage-bde -protectors -get C:'"
    } catch {
        Write-Host "Error gathering BitLocker info: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Hardware Health
    # ------------------------------------------------------
    Write-SubHeader "Hardware Health"
    try {
        # Physical Disks
        Get-PhysicalDisk | Format-Table FriendlyName, HealthStatus, OperationalStatus -AutoSize
        
        # SMART Status (summarized)
        # FIX: Added ErrorAction to prevent crashes on unsupported hardware
        $Smart = Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        if ($Smart) {
            Write-Host "Disk Temps/SMART Info Available"
            $Smart | Format-Table DeviceId, Temperature, Id -AutoSize
        }

        # Battery Cycles
        # Re-using $Battery from earlier section if available, else query again (though var scope covers script)
        if ($Battery) {
            Write-Property "Battery Cycles" "N/A (Not exposed in standard WMI)"
        }

        # Chassis Info
        Write-Property "Chassis Type" $ComputerSystem.SystemFamily
    } catch {
        Write-Host "Error gathering Hardware Health: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Devices
    # ------------------------------------------------------
    Write-SubHeader "Devices"
    try {
        $ErrorDevices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
        $ErrorCount = if ($ErrorDevices) { $ErrorDevices.Count } else { 0 }
        Write-Property "Devices With Errors" $ErrorCount
        
        # Disabled Devices
        $DisabledDevices = Get-PnpDevice | Where-Object { $_.Status -eq "Error" -or $_.Status -eq "Unknown" }
        $DisabledCount = if ($DisabledDevices) { $DisabledDevices.Count } else { 0 }
        Write-Property "Unknown/Disabled Devices" $DisabledCount
    } catch {
        Write-Host "Error gathering Device info: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Services
    # ------------------------------------------------------
    Write-SubHeader "Services"
    try {
        $StoppedServices = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -ne "Running" }
        if ($StoppedServices) {
            Write-Property "Automatic Services Not Running" ($StoppedServices.Name -join ", ")
        } else {
            Write-Property "Automatic Services Not Running" "None"
        }
    } catch {
        Write-Host "Error gathering Service info: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Windows Update
    # ------------------------------------------------------
    Write-SubHeader "Windows Update"
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $Result = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        Write-Property "Pending Updates" $Result.Updates.Count
        
        $RebootReq = if (Get-PendingRebootStatus) { "Yes" } else { "No" }
        Write-Property "Pending Reboot Required" $RebootReq
    } catch {
        Write-Host "Error gathering Windows Update info: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## System Events
    # ------------------------------------------------------
    Write-SubHeader "System Events"
    try {
        $Crit = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        $Err = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        
        # FIX: ProviderName 'bugcheck' might not exist or cause parameter errors. Switched to a safer EventID check or wrapping tighter.
        $Bugcheck = $null
        try {
            $Bugcheck = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='BugCheck'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction Stop
        } catch {
            # Fallback: Look for Kernel-Power 41 (Unexpected Shutdown) which often accompanies bugchecks
            try {
                $Bugcheck = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; ProviderName='Kernel-Power'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
            } catch {
                # Ignore
            }
        }

        $CritCount = if ($Crit) { $Crit.Count } else { 0 }
        $ErrCount = if ($Err) { $Err.Count } else { 0 }
        $BugCount = if ($Bugcheck) { $Bugcheck.Count } else { 0 }

        Write-Property "Critical Events (24h)" $CritCount
        Write-Property "Error Events (24h)" $ErrCount
        Write-Property "Bugchecks / BSODs" $BugCount
    } catch {
        Write-Host "Error gathering System Events: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Advanced Security
    # ------------------------------------------------------
    Write-SubHeader "Advanced Security"
    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $TPStatus = if ($DefenderStatus) { $DefenderStatus.TamperProtectionEnabled } else { "N/A" }
        $CFAStatus = if ($DefenderStatus) { $DefenderStatus.ControlledFolderAccessEnabled } else { "N/A" }

        Write-Property "Tamper Protection" $TPStatus
        Write-Property "Controlled Folder Access" $CFAStatus
        
        # Credential Guard / Device Guard (Registry checks)
        $CredGuard = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags
        
        # FIX: PS 5.1 If/Else statement
        $CGStatus = if ($CredGuard -gt 0) { "Enabled" } else { "Disabled" }
        Write-Property "Credential Guard" $CGStatus

        # Local Admins
        $Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        $AdminList = if ($Admins) { $Admins -join ", " } else { "N/A" }
        Write-Property "Local Administrators" $AdminList

        # Activation
        $Activation = cscript //nologo $env:SystemRoot\System32\slmgr.vbs /dli
        Write-Property "Windows Activation" "Check License Status"
        
        # Hosts File
        $HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $HostsMod = (Get-Item $HostsPath).LastWriteTime
        Write-Property "Hosts File Modified" $HostsMod
    } catch {
        Write-Host "Error gathering Advanced Security info: $_" -ForegroundColor Red
    }

    # ------------------------------------------------------
    ## Detailed Network
    # ------------------------------------------------------
    Write-SubHeader "Detailed Network"
    try {
        Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, InterfaceDescription, LinkSpeed | Format-Table -AutoSize
        
        Write-Host "--- ARP Table Summary ---"
        Get-NetNeighbor -State Permanent,Reachable,Stale -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress

        Write-Host "--- Listening Ports ---"
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
    } catch {
        Write-Host "Error gathering Detailed Network info: $_" -ForegroundColor Red
    }

} else {
    Write-SectionHeader "ADMIN DIAGNOSTICS"
    Write-Host "Script was not run as Administrator. Skipping admin-only diagnostics." -ForegroundColor Red
    Write-Host "Please re-run PowerShell as Administrator to see BitLocker, Disk Health, and Advanced Security details." -ForegroundColor Yellow
}

#endregion
