WhatChanged – System History Correlator
---------------------------------------

WhatChanged is a Windows 10/11 diagnostic tool built in PowerShell + WPF.
Its purpose is simple: answer the classic question every technician asks—
“What changed around the time this system broke?”

Instead of taking custom snapshots, the tool correlates all the native
Windows history sources already built into the OS. This allows instant
analysis of problems even if the user never ran the tool beforehand.

---------------------------------------
Features
---------------------------------------

• Visual overview across multiple tabs:
    - System Info (OS, BIOS, CPU, uptime, disks, network)
    - Restore Points
    - Shadow Copies (VSS)
    - Reliability Monitor events (Win32_ReliabilityRecords)
    - Updates & Installs (Windows Update, Servicing, MSI)
    - Firewall Rules (current state)
    - Firewall Events (time-filtered)

• Search and filter:
    - Live search box filters the current tab
    - Reliability tab includes severity filters (Critical/Error/Warning/etc.)
    - Timeline focus button: select a reliability event to automatically
      narrow Updates + Firewall activity ±2 hours around it

• Export to CSV:
    - Any tab can be exported with one click

• Busy overlay:
    - Shows “Loading…” with an indeterminate progress bar to prevent the UI
      from freezing during heavy WinEvent/CIM queries

---------------------------------------
Technical Notes
---------------------------------------

• Requires PowerShell 5+ on Windows 10 or 11  
• WPF/UI requires STA mode (script auto-relaunches as STA if needed)  
• CIM classes used:
    Win32_ReliabilityRecords  
    Win32_OperatingSystem  
    Win32_ComputerSystem  
    Win32_BIOS  
    Win32_LogicalDisk  
    Win32_NetworkAdapterConfiguration  

• Relies entirely on built-in Windows telemetry—no agents, snapshots, or
  background services required.

---------------------------------------
Author
---------------------------------------

Developed by Bogdan Fedko
