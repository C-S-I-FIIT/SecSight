from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class RemoteClient(ABC):
    """Abstract base class for remote Windows machine communication."""
    
    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the remote machine."""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the remote machine."""
        pass
    
    @abstractmethod
    def execute_powershell(self, script: str) -> Dict[str, Any]:
        """
        Execute a PowerShell script on the remote machine.
        
        Args:
            script: PowerShell script to execute
            
        Returns:
            Dictionary containing script output and status
        """
        pass