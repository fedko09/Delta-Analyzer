# Delta-Analyzer
WhatChanged is a Windows 10/11 diagnostic tool that correlates system history to answer ‘what changed?’ across restore points, shadow copies, reliability events, updates, firewall rules, and more. Includes search, filtering, CSV export, and a modern WPF UI for fast troubleshooting.

PS1 and EXE are the same app, just different execution. Use as see fit. 

> With PS1 file, drop the file in a location, open terminal/powershell, navigate to the directory, use **Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass** to remove script prompt, and then type in the .\WhatChanged.ps1 and enter. Execution policy will reset with close/reopen of terminal window.
