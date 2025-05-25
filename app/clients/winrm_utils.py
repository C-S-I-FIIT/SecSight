import winrm
from typing import Dict, Any

def execute_powershell(connection_info: Dict[str, str], script: str) -> str:
    """
    Execute a PowerShell script on a remote Windows machine using WinRM.
    
    Args:
        connection_info: Dictionary containing connection details
        script: PowerShell script to execute
        
    Returns:
        Output from the PowerShell script
    """
    session = winrm.Session(
        connection_info['hostname'],
        auth=(connection_info['username'], connection_info['password']),
        transport=connection_info.get('transport', 'ntlm'),
        server_cert_validation=connection_info.get('server_cert_validation', 'ignore')
    )
    
    result = session.run_ps(script)
    if result.status_code != 0:
        raise Exception(f"PowerShell execution failed: {result.std_err.decode()}")
    
    return result.std_out.decode()

def check_host(connection_info: Dict[str, str]) -> Dict[str, Any]:
    """
    Check if Winlogbeat is running and get its configuration.
    
    Args:
        connection_info: Dictionary containing connection details
        
    Returns:
        Dictionary containing service status and configuration
    """
    # Check if Winlogbeat service is running
    service_check_script = """
    $service = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
    if ($service) {
        $service.Status
    } else {
        "Not Found"
    }
    """
    
    service_status = execute_powershell(connection_info, service_check_script).strip()
    service_running = service_status == "Running"
    
    # Get Winlogbeat configuration
    config_script = """
    $winlogbeatPath = "C:\\Program Files\\winlogbeat\\winlogbeat.exe"
    if (Test-Path $winlogbeatPath) {
        & $winlogbeatPath export config
    } else {
        "Winlogbeat not found at $winlogbeatPath"
    }
    """
    
    config = execute_powershell(connection_info, config_script)
    
    return {
        'service_running': service_running,
        'config': config
    } 