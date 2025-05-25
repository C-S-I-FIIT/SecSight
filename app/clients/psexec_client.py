from pypsexec.client import Client
from typing import Dict, Any, Optional
import socket
from urllib3.exceptions import MaxRetryError, NameResolutionError
from .remote_client import RemoteClient
import logging
import base64

# Suppress pypsexec logs
logging.getLogger('pypsexec').setLevel(logging.WARNING)
logging.getLogger('smbprotocol').setLevel(logging.WARNING)
logging.getLogger('spnego').setLevel(logging.WARNING)

class PSEXECClient(RemoteClient):
    def __init__(self, hostname: str, username: str, password: str):
        """
        Initialize PSEXEC client for remote Windows machine communication.
        
        Args:
            hostname: IP address or hostname of the remote machine
            username: Username for authentication
            password: Password for authentication
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = None
        self._service_created = False
    
    def connect(self) -> None:
        """Establish connection to the remote machine."""
        try:
            self.client = Client(
                self.hostname,
                username=self.username,
                password=self.password,
                encrypt=True
            )
            self.client.connect()
            self.client.create_service()
        except (MaxRetryError, NameResolutionError, socket.error) as e:
            raise Exception(f"Connection to {self.hostname} failed: {str(e)}")
    
    
    def disconnect(self) -> None:
        """Close connection to the remote machine."""
        if self.client:
            try:
                self.client.cleanup()
                self.client.remove_service()
                self.client.disconnect()
            except Exception as e:
                raise Exception(f"Error disconnecting from {self.hostname}: {str(e)}")
    
    # def execute_command(self, executable: str, arguments: Optional[str] = None) -> Dict[str, Any]:
    #     """
    #     Execute a command on the remote machine using PowerShell.
        
    #     Args:
    #         executable: Path to the executable or command name
    #         arguments: Optional arguments for the executable
            
    #     Returns:
    #         Dictionary containing command output and status
    #     """
    #     if not self.client:
    #         raise Exception("Not connected to remote machine")
        
        # try:
    
        #     # Construct PowerShell command
        #     if arguments:
        #         powershell_cmd = f'& "{executable}" {arguments}'
        #     else:
        #         powershell_cmd = f'& "{executable}"'
            
        #     # Execute through PowerShell
        #     result = self.client.run_executable(
        #         "powershell.exe",
        #         f"-ExecutionPolicy Bypass -NoProfile -NonInteractive -Command {powershell_cmd}"
        #     )
            
        #     return {
        #         'stdout': result[0].decode('utf-8') if result[0] else "",
        #         'stderr': result[1].decode('utf-8') if result[1] else "",
        #         'return_code': result[2]
        #     }
        # except Exception as e:
        #     raise Exception(f"Error executing command on {self.hostname}: {str(e)}")
    
    def execute_powershell(self, script: str) -> Dict[str, Any]:
        """
        Execute a PowerShell script on the remote machine.
        
        Args:
            script: PowerShell script to execute
            
        Returns:
            Dictionary containing script output and status
        """
        if not self.client:
            raise Exception("Not connected to remote machine")
        
        try:            
            # Execute the script directly through PowerShell
            # script = script.replace('"', '`"').replace("'", "`'")
            script_base64 = base64.b64encode(script.encode('utf-8')).decode('utf-8')
            result = self.client.run_executable(
                "powershell.exe",
                fr"""-ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{script_base64}'))" | iex""",
                timeout_seconds=10)
            
            return {
                'stdout': result[0].decode('utf-8') if result[0] else "",
                'stderr': result[1].decode('utf-8') if result[1] else "",
                'return_code': result[2]
            }
        except Exception as e:
            raise Exception(f"Error executing PowerShell script on {self.hostname}: {str(e)}")
    
    def check_winlogbeat(self) -> Dict[str, Any]:
        """
        Check if Winlogbeat is running and get its configuration.
        
        Returns:
            Dictionary containing service status and configuration
        """
        try:
            # Check if Winlogbeat service is running using PowerShell
            service_result = self.execute_powershell(
                'Get-Service winlogbeat | Select-Object -Property Status,Name | ConvertTo-Json'
            )
            service_running = '"Status":"Running"' in service_result['stdout']
            
            if not service_running:
                return {
                    'running': False,
                    'config': None
                }
            
            # Get Winlogbeat configuration using PowerShell
            config_result = self.execute_powershell(
                '& "C:\\Program Files\\winlogbeat\\winlogbeat.exe" export config'
            )
            
            return {
                'running': service_running,
                'config': config_result['stdout']
            }
        except Exception as e:
            raise Exception(f"Error checking Winlogbeat: {str(e)}")
    
    def get_sysmon_config(self) -> Dict[str, Any]:
        """
        Get Sysmon configuration from the registry.
        
        Returns:
            Dictionary containing Sysmon configuration
        """
        raise NotImplementedError("Not yet implemented") 