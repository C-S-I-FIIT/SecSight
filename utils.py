import os
from typing import List, Dict
from loguru import logger
from app.clients.win_client import WinClient
from app.collectors.netbox_client import NetboxClient

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def restart_computers_on_170_subnet() -> Dict[str, str]:
    """
    Restart all computers in the 10.0.170.X subnet using PSEXEC.
    
    Returns:
        Dictionary containing results for each host
    """
    results = {}
    
    # Get all hosts from Netbox
    netbox = NetboxClient()
    hosts = netbox.get_all_hosts()
    
    # Filter hosts in 10.0.170.X subnet
    target_hosts = [
        host for host in hosts 
        if host.get('ip') and host['ip'].startswith('10.0.170.254')
    ]
    
    logger.info(f"Found {len(target_hosts)} hosts in 10.0.170.X subnet")
    
    # Connect to each host and restart
    for host in target_hosts:
        hostname = host['name']
        ip = host['ip'].split('/')[0]  # Remove CIDR notation if present
        
        try:
            logger.info(f"Connecting to {hostname} ({ip})")
            client = WinClient(ip)
            
            if not client.client:
                results[hostname] = "Failed to connect"
                continue
                
            # Execute restart command
            restart_command = """
            Write-Output "Initiating system restart..."
            Restart-Computer -Force
            """
            
            result = client.client.execute_powershell(restart_command)
            
            if result['return_code'] == 0:
                results[hostname] = "Successfully initiated system restart"
                logger.success(f"Successfully initiated system restart on {hostname}")
            else:
                results[hostname] = f"Failed to restart system: {result['stderr']}"
                logger.error(f"Failed to restart system on {hostname}: {result['stderr']}")
                
        except Exception as e:
            results[hostname] = f"Error: {str(e)}"
            logger.error(f"Error processing {hostname}: {str(e)}")
            
    return results

def force_gpo_update_on_170_subnet() -> Dict[str, str]:
    """
    Force GPO policy update on all computers in the 10.0.170.X subnet using PSEXEC.
    
    Returns:
        Dictionary containing results for each host
    """
    results = {}
    
    # Get all hosts from Netbox
    netbox = NetboxClient()
    hosts = netbox.get_all_hosts()
    
    # Filter hosts in 10.0.170.X subnet
    target_hosts = [
        host for host in hosts 
        if host.get('ip') and host['ip'].startswith('10.0.170.')
    ]
    
    logger.info(f"Found {len(target_hosts)} hosts in 10.0.170.X subnet")
    
    # Connect to each host and force GPO update
    for host in target_hosts:
        hostname = host['name']
        ip = host['ip'].split('/')[0]  # Remove CIDR notation if present
        
        try:
            logger.info(f"Connecting to {hostname} ({ip})")
            client = WinClient(ip)
            
            if not client.client:
                results[hostname] = "Failed to connect"
                continue
                
            # Execute GPO update command
            gpo_command = """
            Write-Output "Forcing GPO policy update..."
            $result = gpupdate /force
            Write-Output $result
            """
            
            result = client.client.execute_powershell(gpo_command)
            
            if result['return_code'] == 0:
                results[hostname] = "Successfully forced GPO update"
                logger.success(f"Successfully forced GPO update on {hostname}")
                logger.debug(f"GPO update output: {result['stdout']}")
            else:
                results[hostname] = f"Failed to force GPO update: {result['stderr']}"
                logger.error(f"Failed to force GPO update on {hostname}: {result['stderr']}")
                
        except Exception as e:
            results[hostname] = f"Error: {str(e)}"
            logger.error(f"Error processing {hostname}: {str(e)}")
            
    return results

def get_winlogbeat_configs_from_subnet() -> Dict[str, Dict]:
    """
    Connect to all computers in the 10.0.170.X subnet and parse their winlogbeat.yml files
    to get the event_logs configurations.
    
    Returns:
        Dictionary mapping host info (ip, name) to its winlogbeat log configurations,
        showing what logs are enabled and which ones might be missing
    """
    results = {}
    # Standard important Windows logs to check for
    
    # Get all hosts from Netbox
    netbox = NetboxClient()
    hosts = netbox.get_all_hosts()
    
    # Filter hosts in 10.0.170.X subnet
    target_hosts = [
        host for host in hosts 
        if host.get('platform_os') and host['platform_os'].lower().startswith('windows')
    ]
    
    logger.info(f"Found {len(target_hosts)} Windows hosts")
    
    # Connect to each host and get winlogbeat config
    for host in target_hosts:
        hostname = host['name']
        ip = host['ip'].split('/')[0]  # Remove CIDR notation if present
        
        try:
            logger.info(f"Connecting to {hostname} ({ip})")
            client = WinClient(ip)
            
            if not client.client:
                results[f"{hostname} ({ip})"] = {"error": "Failed to connect"}
                continue
                
            # Get winlogbeat config
            config = client.get_winlogbeat_config()
            
            if not config:
                results[f"{hostname} ({ip})"] = {"error": "Failed to get winlogbeat config"}
                continue
            
            # Extract event logs configuration
            event_logs = config.get('winlogbeat.event_logs', [])
            
            if not event_logs:
                results[f"{hostname} ({ip})"] = {"error": "No event_logs configuration found"}
                continue
            
            # Extract just the log names from the configuration
            configured_logs = []
            for log_entry in event_logs:
                if isinstance(log_entry, dict) and 'name' in log_entry:
                    configured_logs.append(log_entry['name'])
                elif isinstance(log_entry, str):
                    configured_logs.append(log_entry)
            
            # Check which standard logs are missing            
            # Store the event logs in the results
            results[f"{hostname} ({ip})"] = {
                "configured_logs": configured_logs,
                "raw_config": event_logs  # Include raw config for reference
            }
            
            logger.success(f"Successfully retrieved winlogbeat config from {hostname}")
                
        except Exception as e:
            results[f"{hostname} ({ip})"] = {"error": f"Error: {str(e)}"}
            logger.error(f"Error processing {hostname}: {str(e)}")
            
    print("\n=== WINLOGBEAT CONFIGURATION SUMMARY ===\n")
    
    for host, config in results.items():
        print(f"Host: {host}")
        
        if "error" in config:
            print(f"  Error: {config['erkror']}")
            continue
            
        print(f"  Configured logs ({len(config['configured_logs'])}):")
        for log in sorted(config['configured_logs']):
            print(f"    - {log}")
            
        print("")  # Empty line between hosts

if __name__ == "__main__":
    # Uncomment the function you want to run
    restart_computers_on_170_subnet()
    # force_gpo_update_on_170_subnet()
    
    # Run winlogbeat config analysis
    #get_winlogbeat_configs_from_subnet()
    
    # Print summary of results
   