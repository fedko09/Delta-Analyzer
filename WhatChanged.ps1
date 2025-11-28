<#
    WhatChanged - System History Correlator (v0.6)
    Windows 10 / 11
#>

# Relaunch as STA for WPF (required for XAML/WPF)
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File $PSCommandPath @args
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
Add-Type -AssemblyName System.Windows.Forms

# ---------------------------
# Data functions
# ---------------------------

function Get-SysDeltaRestorePoints {
    try {
        Get-ComputerRestorePoint | ForEach-Object {
            [pscustomobject]@{
                Created          = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)
                SequenceNumber   = $_.SequenceNumber
                Description      = $_.Description
                EventType        = $_.EventType
                RestorePointType = $_.RestorePointType
            }
        }
    } catch { @() }
}

function Get-SysDeltaShadowCopies {
    try {
        Get-CimInstance Win32_ShadowCopy | ForEach-Object {
            [pscustomobject]@{
                Created            = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.InstallDate)
                ID                 = $_.ID
                VolumeName         = $_.VolumeName
                ClientAccessible   = $_.ClientAccessible
                OriginatingMachine = $_.OriginatingMachine
                ServiceMachine     = $_.ServiceMachine
            }
        }
    } catch { @() }
}

function Get-SysDeltaReliability {
    param([datetime]$Since)

    try {
        Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeGenerated -ge $Since } |
            Select-Object TimeGenerated, SourceName, ProductName, EventIdentifier,
                          @{Name = 'Level'; Expression = { $_.Severity }},
                          Message
    } catch { @() }
}

function Get-SysDeltaUpdateEvents {
    param([datetime]$Since)

    try {
        $logs      = @('System','Application')
        $providers = @(
            'Microsoft-Windows-WindowsUpdateClient',
            'Microsoft-Windows-Servicing',
            'MsiInstaller'
        )

        $filter = @{
            LogName      = $logs
            ProviderName = $providers
            StartTime    = $Since
        }

        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
    } catch { @() }
}

function Get-SysDeltaFirewallRules {
    try {
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, Enabled, Direction, Action, Profile, Group, PolicyStoreSource |
            Sort-Object Name
    } catch { @() }
}

function Get-SysDeltaFirewallEvents {
    param([datetime]$Since)

    try {
        Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -ge $Since } |
            Select-Object TimeCreated, Id, LevelDisplayName, TaskDisplayName, Message
    } catch { @() }
}

function Convert-DmtfSafe {
    param([object]$Value)

    if ($Value -is [datetime]) { return $Value }

    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }

    try {
        return [System.Management.ManagementDateTimeConverter]::ToDateTime($s)
    } catch {
        return $null
    }
}

function Get-SystemSummary {
    $items = New-Object System.Collections.Generic.List[object]

    function AddItem {
        param($Category,$Name,$Value)
        $items.Add([pscustomobject]@{
            Category = $Category
            Name     = $Name
            Value    = $Value
        }) | Out-Null
    }

    try {
        $os   = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $cpu  = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

        # OS
        AddItem 'OS' 'Caption' $os.Caption
        AddItem 'OS' 'Version' $os.Version
        AddItem 'OS' 'Build'   $os.BuildNumber

        $installDate = Convert-DmtfSafe $os.InstallDate
        if ($installDate) {
            AddItem 'OS' 'InstallDate' $installDate
        }

        # Computer
        AddItem 'Computer' 'Name'         $cs.Name
        AddItem 'Computer' 'Manufacturer' $cs.Manufacturer
        AddItem 'Computer' 'Model'        $cs.Model
        AddItem 'Computer' 'Total RAM (GB)' ([math]::Round($cs.TotalPhysicalMemory / 1GB, 2))

        # BIOS
        if ($bios) {
            $biosVer = $bios.SMBIOSBIOSVersion -join ', '
            AddItem 'BIOS' 'Version' $biosVer

            $biosDate = Convert-DmtfSafe $bios.ReleaseDate
            if ($biosDate) {
                AddItem 'BIOS' 'ReleaseDate' $biosDate
            }
        }

        # CPU
        if ($cpu) {
            AddItem 'CPU' 'Name'              $cpu.Name
            AddItem 'CPU' 'Cores'             $cpu.NumberOfCores
            AddItem 'CPU' 'LogicalProcessors' $cpu.NumberOfLogicalProcessors
        }

        # Uptime
        $bootTime = Convert-DmtfSafe $os.LastBootUpTime
        if ($bootTime) {
            $uptime = (Get-Date) - $bootTime
            AddItem 'Uptime' 'Since'    $bootTime
            AddItem 'Uptime' 'Duration' ("{0:%d}d {0:hh}h {0:mm}m" -f $uptime)
        }

        # Disks
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
            ForEach-Object {
                if ($_.Size -gt 0) {
                    $totalGB = [math]::Round($_.Size/1GB,1)
                    $freeGB  = [math]::Round($_.FreeSpace/1GB,1)
                    $ratio   = [double]$_.FreeSpace / [double]$_.Size

                    AddItem 'Disk' ("Drive {0}" -f $_.DeviceID) (
                        "{0} GB total, {1} GB free ({2:P0} free)" -f $totalGB, $freeGB, $ratio
                    )
                }
            }

        # Network IPv4
        Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $ipv4 = @($_.IPAddress | Where-Object { $_ -match '^\d+\.' })
                if ($ipv4.Count -gt 0) {
                    AddItem 'Network' $_.Description ($ipv4 -join ', ')
                }
            }
    } catch {
        AddItem 'Error' 'System info' $_.Exception.Message
    }

    $items
}

# ---------------------------
# XAML UI + busy overlay
# ---------------------------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="What Changed? - System History Correlator"
        Height="650" Width="1150"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="12">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Top bar -->
    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
      <TextBlock Text="Time range:" VerticalAlignment="Center" Margin="0,0,6,0"/>
      <ComboBox x:Name="cmbRange" Width="150" Margin="0,0,8,0" SelectedIndex="2">
        <ComboBoxItem Content="Last 24 hours" Tag="1"/>
        <ComboBoxItem Content="Last 3 days" Tag="3"/>
        <ComboBoxItem Content="Last 7 days" Tag="7"/>
        <ComboBoxItem Content="Last 30 days" Tag="30"/>
        <ComboBoxItem Content="Last 90 days" Tag="90"/>
      </ComboBox>
      <Button x:Name="btnRefresh" Content="Refresh" Width="90" Margin="0,0,8,0"/>
      <Button x:Name="btnExport" Content="Export tab to CSV" Width="130" Margin="0,0,12,0"/>
      <TextBlock Text="Search current tab:" VerticalAlignment="Center" Margin="0,0,6,0"/>
      <TextBox x:Name="txtSearch" Width="220" Margin="0,0,12,0"/>
      <TextBlock x:Name="lblTopStatus" VerticalAlignment="Center"
                 Text="Browse built-in system history: system info, restore points, reliability, updates, firewall."/>
    </StackPanel>

    <!-- Tabs -->
    <TabControl x:Name="tabMain" Grid.Row="1">
      <!-- Restore & Shadow -->
      <TabItem Header="Restore &amp; Shadow">
        <Grid Margin="0">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <GroupBox Header="Restore points" Grid.Row="0" Margin="0,0,0,4">
            <DataGrid x:Name="dgRestore" AutoGenerateColumns="True" IsReadOnly="True"
                      Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
          </GroupBox>
          <GroupBox Header="Shadow copies (VSS)" Grid.Row="1" Margin="0,4,0,0">
            <DataGrid x:Name="dgShadows" AutoGenerateColumns="True" IsReadOnly="True"
                      Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <!-- System Info -->
      <TabItem Header="System Info">
        <DataGrid x:Name="dgSysInfo" AutoGenerateColumns="True" IsReadOnly="True"
                  Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
      </TabItem>

      <!-- Reliability Monitor -->
      <TabItem Header="Reliability">
        <Grid Margin="0">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="4,0,4,4">
            <TextBlock Text="Severity filter:" VerticalAlignment="Center" Margin="0,0,6,0"/>
            <ComboBox x:Name="cmbRelSeverity" Width="170" SelectedIndex="0">
              <ComboBoxItem Content="All" Tag="All"/>
              <ComboBoxItem Content="Critical only" Tag="Critical"/>
              <ComboBoxItem Content="Error and above" Tag="ErrorPlus"/>
              <ComboBoxItem Content="Warning and above" Tag="WarningPlus"/>
              <ComboBoxItem Content="Info and above" Tag="InfoPlus"/>
            </ComboBox>
            <Button x:Name="btnRelWindow" Content="Focus updates/firewall around selected" Margin="8,0,0,0"/>
          </StackPanel>
          <DataGrid x:Name="dgReliability" Grid.Row="1"
                    AutoGenerateColumns="True" IsReadOnly="True"
                    Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"
                    IsTextSearchEnabled="True" />
        </Grid>
      </TabItem>

      <!-- Updates / Installs -->
      <TabItem Header="Updates &amp; Installs">
        <DataGrid x:Name="dgUpdates" AutoGenerateColumns="True" IsReadOnly="True"
                  Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
      </TabItem>

      <!-- Firewall rules -->
      <TabItem Header="Firewall Rules">
        <DataGrid x:Name="dgFwRules" AutoGenerateColumns="True" IsReadOnly="True"
                  Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
      </TabItem>

      <!-- Firewall events -->
      <TabItem Header="Firewall Events">
        <DataGrid x:Name="dgFwEvents" AutoGenerateColumns="True" IsReadOnly="True"
                  Margin="4" CanUserAddRows="False" CanUserDeleteRows="False"/>
      </TabItem>
    </TabControl>

    <!-- Bottom status -->
    <StatusBar Grid.Row="2" Margin="0,8,0,0">
      <StatusBarItem>
        <TextBlock x:Name="lblStatus" Text="Ready."/>
      </StatusBarItem>
    </StatusBar>

    <!-- Busy overlay -->
    <Grid x:Name="busyOverlay" Background="#80000000" Visibility="Collapsed">
      <Border Background="#FF2D2D30" CornerRadius="6" Padding="20"
              HorizontalAlignment="Center" VerticalAlignment="Center">
        <StackPanel HorizontalAlignment="Center">
          <TextBlock x:Name="lblBusyText" Text="Loading..."
                     Foreground="White" FontSize="16" FontWeight="Bold"
                     HorizontalAlignment="Center" Margin="0,0,0,8"/>
          <ProgressBar IsIndeterminate="True" Width="220" Height="16"/>
        </StackPanel>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

# ---------------------------
# Load XAML
# ---------------------------
[xml]$xamlXml = $xaml
$reader = New-Object System.Xml.XmlNodeReader $xamlXml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$cmbRange       = $window.FindName('cmbRange')
$btnRefresh     = $window.FindName('btnRefresh')
$btnExport      = $window.FindName('btnExport')
$txtSearch      = $window.FindName('txtSearch')
$tabMain        = $window.FindName('tabMain')
$lblTopStatus   = $window.FindName('lblTopStatus')
$lblStatus      = $window.FindName('lblStatus')
$cmbRelSeverity = $window.FindName('cmbRelSeverity')
$btnRelWindow   = $window.FindName('btnRelWindow')
$busyOverlay    = $window.FindName('busyOverlay')
$lblBusyText    = $window.FindName('lblBusyText')

$dgRestore     = $window.FindName('dgRestore')
$dgShadows     = $window.FindName('dgShadows')
$dgSysInfo     = $window.FindName('dgSysInfo')
$dgReliability = $window.FindName('dgReliability')
$dgUpdates     = $window.FindName('dgUpdates')
$dgFwRules     = $window.FindName('dgFwRules')
$dgFwEvents    = $window.FindName('dgFwEvents')

# ---------------------------
# Data stores for filtering
# ---------------------------
$script:DataRestore     = @()
$script:DataShadows     = @()
$script:DataSysInfo     = @()
$script:DataReliability = @()
$script:DataUpdates     = @()
$script:DataFwRules     = @()
$script:DataFwEvents    = @()

# ---------------------------
# Helpers
# ---------------------------
function Show-BusyOverlay {
    param(
        [string]$Message = "Loading..."
    )

    if ($lblBusyText) { $lblBusyText.Text = $Message }
    if ($busyOverlay) { $busyOverlay.Visibility = 'Visible' }
    $window.Cursor = 'Wait'

    # Let WPF process the layout change before we block with heavy work
    [System.Windows.Forms.Application]::DoEvents() | Out-Null
}

function Hide-BusyOverlay {
    if ($busyOverlay) { $busyOverlay.Visibility = 'Collapsed' }
    $window.Cursor = 'Arrow'
}

function Apply-SearchFilter {
    param(
        [object[]]$Data,
        [string]$Search
    )

    if (-not $Data) { return @() }
    if ([string]::IsNullOrWhiteSpace($Search)) { return $Data }

    $pattern = "*$Search*"

    $Data | Where-Object {
        $values = $_.PSObject.Properties.Value | ForEach-Object { [string]$_ }
        ($values -join ' ') -like $pattern
    }
}

function Apply-ReliabilitySeverityFilter {
    param([object[]]$Data)

    if (-not $Data) { return @() }

    $item = [System.Windows.Controls.ComboBoxItem]$cmbRelSeverity.SelectedItem
    $tag  = if ($item -and $item.Tag) { [string]$item.Tag } else { 'All' }

    switch ($tag) {
        'Critical'    { $Data | Where-Object { $_.Level -eq 1 } }
        'ErrorPlus'   { $Data | Where-Object { $_.Level -le 2 } }
        'WarningPlus' { $Data | Where-Object { $_.Level -le 3 } }
        'InfoPlus'    { $Data | Where-Object { $_.Level -le 4 } }
        default       { $Data }
    }
}

function Get-SelectedDays {
    param($ComboBox)

    $item = [System.Windows.Controls.ComboBoxItem]$ComboBox.SelectedItem
    if ($item -and $item.Tag) { [int]$item.Tag } else { 7 }
}

function Update-CurrentTabView {
    $search = $txtSearch.Text
    $tab    = $tabMain.SelectedItem
    if (-not $tab) { return }

    $header = [string]$tab.Header

    switch ($header) {
        'Restore & Shadow' {
            $dgRestore.ItemsSource = Apply-SearchFilter -Data $script:DataRestore -Search $search
            $dgShadows.ItemsSource = Apply-SearchFilter -Data $script:DataShadows -Search $search
        }
        'System Info' {
            $dgSysInfo.ItemsSource = Apply-SearchFilter -Data $script:DataSysInfo -Search $search
        }
        'Reliability' {
            $data = Apply-ReliabilitySeverityFilter -Data $script:DataReliability
            $dgReliability.ItemsSource = Apply-SearchFilter -Data $data -Search $search
        }
        'Updates & Installs' {
            $dgUpdates.ItemsSource = Apply-SearchFilter -Data $script:DataUpdates -Search $search
        }
        'Firewall Rules' {
            $dgFwRules.ItemsSource = Apply-SearchFilter -Data $script:DataFwRules -Search $search
        }
        'Firewall Events' {
            $dgFwEvents.ItemsSource = Apply-SearchFilter -Data $script:DataFwEvents -Search $search
        }
    }
}

function Load-SysHistoryData {
    param([datetime]$Since)

    $lblStatus.Text    = "Loading system history since $Since..."
    $lblTopStatus.Text = $lblStatus.Text
    Show-BusyOverlay "Loading system history since $Since..."

    try {
        # System info
        $script:DataSysInfo = Get-SystemSummary

        # Restore & Shadow
        $script:DataRestore = Get-SysDeltaRestorePoints | Sort-Object Created -Descending
        $script:DataShadows = Get-SysDeltaShadowCopies | Sort-Object Created -Descending

        # Reliability
        $script:DataReliability = Get-SysDeltaReliability -Since $Since | Sort-Object TimeGenerated -Descending

        # Updates / Installs
        $script:DataUpdates = Get-SysDeltaUpdateEvents -Since $Since | Sort-Object TimeCreated -Descending

        # Firewall current rules (not time-filtered, state at present)
        $script:DataFwRules = Get-SysDeltaFirewallRules

        # Firewall events
        $script:DataFwEvents = Get-SysDeltaFirewallEvents -Since $Since | Sort-Object TimeCreated -Descending

        Update-CurrentTabView

        $lblStatus.Text    = "Loaded system history since $Since."
        $lblTopStatus.Text = "History loaded - use tabs, severity, and search to explore."
    }
    catch {
        $lblStatus.Text    = "Error loading data: $($_.Exception.Message)"
        $lblTopStatus.Text = "Error loading data."
    }
    finally {
        Hide-BusyOverlay
    }
}

function Export-CurrentTabToCsv {
    $tab = $tabMain.SelectedItem
    if (-not $tab) { return }

    $header = [string]$tab.Header
    $data   = @()

    switch ($header) {
        'Restore & Shadow' {
            $r = @($dgRestore.ItemsSource)
            $s = @($dgShadows.ItemsSource)
            $data = @()
            foreach ($x in $r) { $data += $x }
            foreach ($x in $s) { $data += $x }
        }
        'System Info' {
            $data = @($dgSysInfo.ItemsSource)
        }
        'Reliability' {
            $data = @($dgReliability.ItemsSource)
        }
        'Updates & Installs' {
            $data = @($dgUpdates.ItemsSource)
        }
        'Firewall Rules' {
            $data = @($dgFwRules.ItemsSource)
        }
        'Firewall Events' {
            $data = @($dgFwEvents.ItemsSource)
        }
    }

    if (-not $data -or $data.Count -eq 0) {
        $lblStatus.Text = "No data in current tab to export."
        return
    }

    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $ts  = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $safeHeader = ($header -replace '[^\w]+','_')
    $dlg.FileName = "{0}-{1}.csv" -f $safeHeader, $ts
    $dlg.Filter   = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"

    $result = $dlg.ShowDialog()
    if (-not $result) { return }

    try {
        $data | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        $lblStatus.Text = "Exported current tab to: $($dlg.FileName)"
    }
    catch {
        $lblStatus.Text = "Error exporting CSV: $($_.Exception.Message)"
    }
}

function Focus-UpdatesAndFirewall-AroundSelectedReliability {
    $sel = $dgReliability.SelectedItem
    if (-not $sel) {
        $lblStatus.Text = "Select a reliability event first."
        return
    }

    $center = $sel.TimeGenerated
    if (-not $center) {
        $lblStatus.Text = "Selected reliability event has no TimeGenerated."
        return
    }

    $from = $center.AddHours(-2)
    $to   = $center.AddHours(2)

    $dgUpdates.ItemsSource = $script:DataUpdates | Where-Object {
        $_.TimeCreated -ge $from -and $_.TimeCreated -le $to
    }

    $dgFwEvents.ItemsSource = $script:DataFwEvents | Where-Object {
        $_.TimeCreated -ge $from -and $_.TimeCreated -le $to
    }

    $lblStatus.Text = "Focused Updates & Firewall to events between $from and $to. Refresh to reset."
}

# ---------------------------
# Events
# ---------------------------
$btnRefresh.Add_Click({
    $days  = Get-SelectedDays -ComboBox $cmbRange
    $since = (Get-Date).AddDays(-$days)
    Load-SysHistoryData -Since $since
})

$cmbRange.Add_SelectionChanged({
    if ($window.IsInitialized) {
        $days  = Get-SelectedDays -ComboBox $cmbRange
        $since = (Get-Date).AddDays(-$days)
        Load-SysHistoryData -Since $since
    }
})

$txtSearch.Add_TextChanged({
    if ($window.IsInitialized) {
        Update-CurrentTabView
    }
})

$tabMain.Add_SelectionChanged({
    if ($window.IsInitialized) {
        Update-CurrentTabView
    }
})

if ($cmbRelSeverity) {
    $cmbRelSeverity.Add_SelectionChanged({
        if ($window.IsInitialized) {
            Update-CurrentTabView
        }
    })
}

$btnExport.Add_Click({
    Export-CurrentTabToCsv
})

$btnRelWindow.Add_Click({
    Focus-UpdatesAndFirewall-AroundSelectedReliability
})

# Initial load: last 7 days
$initialDays  = Get-SelectedDays -ComboBox $cmbRange
$initialSince = (Get-Date).AddDays(-$initialDays)
Load-SysHistoryData -Since $initialSince

# Show window
$window.ShowDialog() | Out-Null
