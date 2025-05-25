from app.clients.vault_client import VaultClient
from app.clients.winrm_client import WinRMClient
from app.clients.psexec_client import PSEXECClient
from app.clients.remote_client import RemoteClient
from functools import wraps
from typing import Optional, Dict, Any, Union

from app.mappings.windows_mappings import SERVICE_STATUS

import re
import os
import json
import yaml
from loguru import logger

def require_client(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.client:
            logger.error(f"[WinClient] [ERROR] Not connected to remote machine")
            raise Exception("Not connected to remote machine")
        return func(self, *args, **kwargs)
    return wrapper

class WinClient:
    
    SCRIPTS_PATH = os.path.join(os.getcwd(), 'app', 'scripts')
    
    def __init_winrm__(self):
        self.winrm = WinRMClient(self.ip, self.credentials['user'], self.credentials['pass'])
        try:
            self.winrm.connect()
            logger.debug(f"[WinClient] [WINRM] Connected to {self.ip}")
            _tmp = self.winrm.execute_command('echo "Hello, World!"')
            
            if _tmp['return_code'] == 0 and _tmp['stdout'].startswith('Hello'):
                logger.success(f"[WinClient] [WINRM] Connected to {self.ip}")
                return True
            else:
                raise Exception(f"Return code: {_tmp['return_code']}, Stdout: {_tmp['stdout']}")
        except Exception as e:
            logger.error(f"[WinClient] [WINRM] Failed to connect to {self.ip}: {e}")
            return False
        
    def __init_psexec__(self):
        self.psexec = PSEXECClient(self.ip, self.credentials['user'], self.credentials['pass'])
        try:
            logger.info(f"[WinClient] [INIT] Checking PSEXEC connection")
            self.psexec.connect()
            
            _tmp = self.psexec.execute_powershell('echo "Hello, World!"')
            
            if _tmp['return_code'] == 0 and _tmp['stdout'].startswith('Hello'):
                logger.success(f"[WinClient] [PSEXEC] Connected to {self.ip}")
                return True
            else:
                raise Exception(f"Return code: {_tmp['return_code']}, Stdout: {_tmp['stdout']}")

        except Exception as e:
            logger.error(f"[WinClient] [PSEXEC] Failed to connect to {self.ip}: {e}")
            return False

    def __init_credentials__(self, ip: str):
        vault = VaultClient()
        
        path = f'windows/logins'
        secrets_list = vault.list_secrets(path)
        secret = None
        
        for _secret in secrets_list:
            metadata = vault.get_metadata(path + '/' + _secret)
            
            ip_regex = metadata.get('custom_metadata', {}).get('ip_regex', None)
            if ip_regex:
                if re.match(ip_regex, self.ip):
                    logger.debug(f"[WinClient] [CRED_CHECK] Secret \"{_secret}\" matches IP {self.ip}")
                    secret = _secret
                    break
                else:
                    logger.debug(f"[WinClient] [CRED_CHECK] Secret \"{_secret}\" does not match IP {self.ip}")
            else:
                logger.debug(f"[WinClient] [CRED_CHECK] Secret \"{_secret}\" does not have an IP regex")
        
        if secret:
            self.credentials = vault.get_secret(path + '/' + secret)
            logger.debug(f"[WinClient] [CRED_CHECK] Credentials for {self.ip}: {self.credentials}")
            return True
        else:
            logger.error(f"[WinClient] [CRED_CHECK] No credentials found for {self.ip}, cannot connect, skipping...")
            return False
        
    def __init__(self, ip: str, number_of_attempts: int = 3):
        self.ip = ip
        self.client: Optional[RemoteClient|None] = None
        self.number_of_attempts = number_of_attempts
        self.initialized = False
        
        try:
            if self.__init_credentials__(ip):
                logger.info(f"[WinClient] [INIT] Initializing WinClient for {self.ip}")

                for _ in range(self.number_of_attempts):
                    logger.info(f"[WinClient] [INIT] Attempt {_ + 1} of {self.number_of_attempts}")
                    if self.__init_psexec__():
                        self.client = self.psexec
                        self.initialized = True
                        break
                    elif self.__init_winrm__():
                        self.client = self.winrm
                        self.initialized = True
                        break
                    else:
                        logger.error(f"[WinClient] Failed to connect to {self.ip}, WinRM nor PSEXEC are available, skipping...")
            else:
                logger.error(f"[WinClient] Failed to initialize WinClient for {self.ip}, credentials not found, skipping...")
                self.initialized = False
        except Exception as e:
            logger.error(f"[WinClient] [INIT] Failed to initialize WinClient for {self.ip}: {e}")
            raise e
    
    @require_client
    def _execute_script(self, script_path: str):
        with open(script_path, 'r') as f:
            script = f.read()
            
        max_attempts = 3
        last_exception = None
        
        # Try primary client (current self.client) first
        for attempt in range(1, max_attempts + 1):
            try:
                logger.debug(f"[WinClient] [EXEC] Primary client attempt {attempt}/{max_attempts}")
                return self.client.execute_powershell(script)
            except Exception as e:
                last_exception = e
                logger.warning(f"[WinClient] [EXEC] Primary client attempt {attempt} failed: {e}")
                
        # Try alternate client as fallback
        alternate_client = None
        alternate_name = "WinRM" if isinstance(self.client, PSEXECClient) else "PSExec"
        
        try:
            # Setup alternate client if needed
            if isinstance(self.client, PSEXECClient) and (not hasattr(self, 'winrm') or self.winrm is None):
                self.winrm = WinRMClient(self.ip, self.credentials['user'], self.credentials['pass'])
                self.winrm.connect()
                alternate_client = self.winrm
            elif isinstance(self.client, WinRMClient) and (not hasattr(self, 'psexec') or self.psexec is None):
                self.psexec = PSEXECClient(self.ip, self.credentials['user'], self.credentials['pass'])
                self.psexec.connect()
                alternate_client = self.psexec
            else:
                alternate_client = self.winrm if isinstance(self.client, PSEXECClient) else self.psexec
                
            # Try with alternate client
            for attempt in range(1, max_attempts + 1):
                try:
                    logger.debug(f"[WinClient] [EXEC] {alternate_name} fallback attempt {attempt}/{max_attempts}")
                    return alternate_client.execute_powershell(script)
                except Exception as e:
                    last_exception = e
                    logger.warning(f"[WinClient] [EXEC] {alternate_name} fallback attempt {attempt} failed: {e}")
        except Exception as e:
            logger.error(f"[WinClient] [EXEC] Failed to initialize {alternate_name} fallback: {e}")
        
        # All attempts failed with both clients
        raise Exception(f"Failed to execute script {script_path} after all retry attempts: {last_exception}")

    def _get_winlogbeat_service_status(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_winlogbeat_service_status.ps1')
        return self._execute_script(script_path)
    
    def _get_winlogbeat_service_path(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_winlogbeat_service_path.ps1')
        return self._execute_script(script_path)
    
    def _get_winlogbeat_config(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_winlogbeat_config.ps1')
        return self._execute_script(script_path)
    
    def _get_sysmon_service_status(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_sysmon_service_status.ps1')
        return self._execute_script(script_path)
    
    def _get_sysmon_service_path(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_sysmon_service_path.ps1')
        return self._execute_script(script_path)
    
    def _get_sysmon_config(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_sysmon_config.ps1')    
        return self._execute_script(script_path)
    
    def _get_windows_log_sources(self):
        script_path = os.path.join(WinClient.SCRIPTS_PATH, 'get_windows_log_sources.ps1')
        return self._execute_script(script_path)
    

    
    def process_sysmon(self):
        status = self._get_sysmon_service_status()
        path = self._get_sysmon_service_path()
        config = self._get_sysmon_config()
        
        return status, path, config
    
    def process_windows_log_sources(self):
        return self._get_windows_log_sources()
    
    def get_winlogbeat_status(self) -> str:
        logger.info(f"[WinClient] [WINLOGBEAT] Getting winlogbeat status")
        status = self._get_winlogbeat_service_status()
        
        if status['return_code'] == 0:
            _stat_json: Dict[str, Any] = json.loads(status['stdout'])
            _stat: int = _stat_json.get('Status', 0)
            
            if _stat in SERVICE_STATUS:
                return SERVICE_STATUS[_stat]
            else:
                logger.error(f"[WinClient] [WINLOGBEAT] Unknown service status: {_stat}")
                return SERVICE_STATUS[0]
            
            # 0 = NotInstalled

        else:
            logger.error(f"[WinClient] [WINLOGBEAT] Failed to get winlogbeat status: {status['stderr']}")
            return SERVICE_STATUS[0]
    
    def get_winlogbeat_config(self) -> Dict[str, Any]:
        logger.info(f"[WinClient] [WINLOGBEAT] Getting winlogbeat config")
        config = self._get_winlogbeat_config()
        
        if config['return_code'] == 0 and config['stdout'].strip() != '':
            _config = yaml.safe_load(config['stdout'])
            return _config
        else:
            logger.error(f"[WinClient] [WINLOGBEAT] Failed to get winlogbeat config:\n\
                         {10*'='}\n\
                         {config['stderr']}\n\
                         {10*'='}")
            return {}
    
    