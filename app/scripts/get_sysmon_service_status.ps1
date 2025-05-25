Get-Service -Name "Sysmon" | Select-Object Name, Status, StartType | ConvertTo-Json
