import os
import hvac
from typing import Union
from hvac.exceptions import InvalidPath
from dotenv import load_dotenv

class VaultClient:
    
    def __init__(self, ssl_verify=False, mount_point='kv'):
        load_dotenv()
        self.vault_addr = os.getenv('VAULT_ADDR', 'https://127.0.0.1:8200/')
        self.vault_token = os.getenv('VAULT_TOKEN')
        self.client = hvac.Client(url=self.vault_addr, token=self.vault_token, verify=ssl_verify)
        self.mount_point = mount_point
        # Verify connection
        if not self.client.is_authenticated():
            raise Exception("Failed to authenticate with Vault")
        
    def test_connection(self) -> bool:
        """Test the connection to Vault server.
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            return self.client.is_authenticated()
        except Exception:
            return False
            
    def get_secret(self, path) -> dict:
        """Retrieve a secret from Vault."""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point
            )
            return response['data']['data']
        
        except InvalidPath:
            return {}

            
    def list_secrets(self, path) -> list:
        """List secrets at a given path."""
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self.mount_point
            )
            return response['data']['keys']
        except InvalidPath:
            return []

    def get_metadata(self, path) -> dict:
        """Get metadata for a secret at the given path.
        
        Returns:
            dict: A dictionary containing metadata about the secret, including:
                - created_time: When the secret was created
                - current_version: The current version number
                - max_versions: Maximum number of versions to keep
                - oldest_version: The oldest version number
                - versions: Dictionary of version numbers and their metadata
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self.mount_point
            )
            return response['data']
        except InvalidPath:
            return {} 