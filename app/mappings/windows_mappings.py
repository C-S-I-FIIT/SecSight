from enum import Enum


# https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogtype?view=windowsdesktop-9.0
LOG_TYPES = {
    1: "Administrative",
    2: "Operation", 
    3: "Analytical",
    4: "Debug"
}

# https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogmode?view=windowsdesktop-9.0
LOG_MODES = {
    0: "Circular",
    1: "AutoBackup",
    2: "Retain"
}

SERVICE_STATUS = {
    0: "NotInstalled",
    1: "Stopped",
    2: "StartPending", 
    3: "StopPending",
    4: "Running",
    5: "ContinuePending",
    6: "PausePending",
    7: "Paused"
}


windows_event_log_mapping = {  # Unified mapping for Windows event log channels
    "security": "Security",
    "application": "Application",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": [
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "wmi_event": "Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "DNS Server",
    "dns-server-audit": "Microsoft-Windows-DNS-Server/Audit",
    "dns-server-analytic": "Microsoft-Windows-DNS-Server/Analytical",
    "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "dhcp": "Microsoft-Windows-DHCP-Server/Operational",
    "msexchange-management": "MSExchange Management",
    "applocker": [
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    "printservice-admin": "Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "Microsoft-Windows-PrintService/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "smbclient-security": "Microsoft-Windows-SmbClient/Security",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "microsoft-servicebus-client": "Microsoft-ServiceBus-Client",
    "ldap_debug": "Microsoft-Windows-LDAP-Client/Debug",
    "security-mitigations": [
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ],
    "diagnosis-scripted": "Microsoft-Windows-Diagnosis-Scripted/Operational",
    "shell-core": "Microsoft-Windows-Shell-Core/Operational",
    "openssh": "OpenSSH/Operational",
    "bitlocker": "Microsoft-Windows-BitLocker/BitLocker Management",
    "vhdmp": "Microsoft-Windows-VHDMP/Operational",
    "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer/Operational",
    "lsa-server": "Microsoft-Windows-LSA/Operational",
    "appxpackaging-om": "Microsoft-Windows-AppxPackaging/Operational",
    "dns-client": "Microsoft-Windows-DNS-Client/Operational",
    "appmodel-runtime": "Microsoft-Windows-AppModel-Runtime/Admin",
    "capi2": "Microsoft-Windows-CAPI2/Operational",
    "certificateservicesclient-lifecycle-system": "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
    # Category-based mappings
    "process_creation": "Microsoft-Windows-Sysmon/Operational",
    "registry_add": "Microsoft-Windows-Sysmon/Operational",
    "registry_set": "Microsoft-Windows-Sysmon/Operational",
    "registry_delete": "Microsoft-Windows-Sysmon/Operational",
    "registry_event": "Microsoft-Windows-Sysmon/Operational",
    "file_change": "Microsoft-Windows-Sysmon/Operational",
    "file_event": "Microsoft-Windows-Sysmon/Operational",
    "file_delete": "Microsoft-Windows-Sysmon/Operational",
    "file_access": "Microsoft-Windows-Sysmon/Operational",
    "file_rename": "Microsoft-Windows-Sysmon/Operational",
    "image_load": "Microsoft-Windows-Sysmon/Operational",
    "pipe_created": "Microsoft-Windows-Sysmon/Operational",
    "ps_classic_start": "Windows PowerShell",
    "ps_module": "Microsoft-Windows-PowerShell/Operational",
    "ps_script": "Microsoft-Windows-PowerShell/Operational",
    "process_access": "Microsoft-Windows-Sysmon/Operational",
    "process_creation": "Microsoft-Windows-Sysmon/Operational",
    "raw_access_thread": "Microsoft-Windows-Sysmon/Operational",
    "driver_load": "Microsoft-Windows-Sysmon/Operational",
    "create_stream_hash": "Microsoft-Windows-Sysmon/Operational",
    "create_remote_thread": "Microsoft-Windows-Sysmon/Operational",
    "network_connection": "Microsoft-Windows-Sysmon/Operational",
    "dns_query": "Microsoft-Windows-Sysmon/Operational"
}

mitre_tactics = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Resource Development",
    "Initial Access": "Initial Access",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion": "Defense Evasion",
    "Credential Access": "Credential Access",
    "Discovery": "Discovery",
    "Lateral Movement": "Lateral Movement",
    "Collection": "Collection",
    "Command and Control": "Command and Control",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
    "Pre-Attack": "Pre-Attack",
    "Supply Chain": "Supply Chain",
    "Impact": "Impact",
    "Impact": "Impact",
}

