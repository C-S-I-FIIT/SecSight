from pypsrp.client import Client
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import yaml
from typing import Dict, Any, List, Optional
import socket
from urllib3.exceptions import MaxRetryError, NameResolutionError
from .remote_client import RemoteClient

class WinRMClient(RemoteClient):
    def __init__(self, hostname: str, username: str, password: str):
        """
        Initialize WinRM client for remote Windows machine communication.
        
        Args:
            hostname: IP address or hostname of the remote machine
            username: Username for authentication
            password: Password for authentication
        """
        
        self.hostname = hostname
        self.username = username
        self.password = password
        self.wsman = None
        self.runspace = None
    
    def connect(self) -> None:
        """Establish connection to the remote machine."""
        try:
            self.wsman = WSMan(
                server=self.hostname,
                auth="negotiate",
                username=self.username,
                password=self.password,
                ssl=False,
                connection_timeout=5
            )
            self.runspace = RunspacePool(connection=self.wsman)
            self.runspace.open()
        except (MaxRetryError, NameResolutionError, socket.error) as e:
            raise Exception(f"Connection to {self.hostname} failed: {str(e)}")
    
    def disconnect(self) -> None:
        """Close connection to the remote machine."""
        if self.runspace:
            self.runspace.close()
        if self.wsman:
            self.wsman.close()
    
    def execute_command(self, executable: str, arguments: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute a command on the remote machine.
        
        Args:
            executable: Path to the executable or command name
            arguments: Optional arguments for the executable
            
        Returns:
            Dictionary containing command output and status
        """
        if not self.runspace:
            raise Exception("Not connected to remote machine")
        
        try:
            ps = PowerShell(self.runspace)
            if arguments:
                ps.add_script(f"& '{executable}' {arguments}")
            else:
                ps.add_script(f"& '{executable}'")
            
            output = ps.invoke()
            return {
                'stdout': "\n".join(str(line) for line in output),
                'stderr': "",
                'return_code': 0 if output else 1
            }
        except Exception as e:
            raise Exception(f"Error executing command on {self.hostname}: {str(e)}")
    
    def execute_powershell(self, script: str) -> Dict[str, Any]:
        """
        Execute a PowerShell script on the remote machine.
        
        Args:
            script: PowerShell script to execute
            
        Returns:
            Dictionary containing script output and status
        """
        if not self.runspace:
            raise Exception("Not connected to remote machine")
        
        try:
            ps = PowerShell(self.runspace)
            ps.add_script(script)
            
            output = ps.invoke()
            return {
                'stdout': "\n".join(str(line) for line in output),
                'stderr': "",
                'return_code': 0 if output else 1
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
            # Check if Winlogbeat service is running
            ps = PowerShell(self.runspace)
            ps.add_script("""
            $service = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
            if ($service) {
                $service.Status
            } else {
                "Not Found"
            }
            """)
            output = ps.invoke()
            service_status = str(output[0]).strip() if output else "Not Found"
            service_running = service_status == "Running"
            
            if not service_running:
                return {
                    'running': False,
                    'config': None
                }
            
            # Get Winlogbeat configuration
                       # Get Winlogbeat configuration using export config command
            ps = PowerShell(self.runspace)
            ps.add_script("""
            C:
            cd '\\Program Files\\winlogbeat'
            .\winlogbeat.exe export config
            """)
            output = ps.invoke()
            config_content = "\n".join(str(line) for line in output)
            
            try:
                config = yaml.safe_load(config_content)
                return {
                    'running': False if not config else True,  # Set running to False if config is empty
                    'config': config or {}  # Ensure we return at least an empty dict
                }
            except yaml.YAMLError as e:
                return {
                    'running': False,
                    'config': {}
                }
                
        except (MaxRetryError, NameResolutionError, socket.error) as e:
            raise Exception(f"Connection to {self.hostname} failed: {str(e)}")
        except Exception as e:
            raise Exception(f"Error checking Winlogbeat: {str(e)}")
        finally:
            if hasattr(self, 'runspace'):
                self.runspace.close()
            if hasattr(self, 'wsman'):
                self.wsman.close()
    
    def parse_winlogbeat_config(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Winlogbeat configuration to extract entries.
        
        Args:
            config: Winlogbeat configuration dictionary
            
        Returns:
            List of configuration entries
        """
        # Initialize entries list
        entries = []
        
        # Extract event logs configuration
        if config and 'winlogbeat' in config and 'event_logs' in config['winlogbeat']:
            for event_log in config['winlogbeat']['event_logs']:
                event_ids = event_log.get('event_id', None)
                # Handle both single event_id and list of event_ids
                if event_ids is None:
                    entry = {
                        'name': event_log.get('name', ''),
                        'event_id': None
                    }
                    entries.append(entry)
                else:
                    for event_id in event_ids.split(','):
                        entry = {
                            'name': event_log.get('name', ''),
                            'event_id': event_id.strip()
                        }
                        entries.append(entry)
        return entries 
    
    def get_sysmon_config(self) -> Dict[str, Any]:
        """
        Get Sysmon configuration from the registry.
        
        Returns:
            Dictionary containing Sysmon configuration
        """
        raise NotImplementedError("Not yet implemented")
    
    def parse_sysmon_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Sysmon configuration to extract entries.
        
        Args:
            config: Sysmon configuration dictionary
        """
        raise NotImplementedError("Not yet implemented")