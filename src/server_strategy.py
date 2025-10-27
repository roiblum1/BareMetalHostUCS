import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Dict, Type
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from config import operator_logger

disable_warnings(InsecureRequestWarning)
logger = operator_logger

# Import strategies after config to avoid circular imports
from hp_server_stategy import HPServerStrategy
from dell_server_strategy import DellServerStrategy
from ucs_server_strategy import CiscoServerStrategy

class ServerType(Enum):
    HP = "hp"
    DELL = "dell"
    CISCO = "cisco"
    UNKNOWN = "unknown"

class ServerStrategy(ABC):
    
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials
        self._cache = None
        self._session = None 
        self._auth_token = None
        
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the server type is properly configured."""
        pass
    
    @abstractmethod
    def ensure_connected(self) -> None:
        """Ensure that a connection to management system."""
        pass
    
    @abstractmethod
    def get_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Retrieve server information such as MAC and BMC address."""
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the management system."""
        pass
    
    def clear_cache(self):
        """Clear any cached data."""
        self._cache = None
    
class ServerTypeDetector:
    @staticmethod
    def detect(server_name: str, server_vendor: Optional[str] = None) -> ServerType:
        if server_vendor:
            server_vendor = server_vendor.strip()
            logger.debug(f"Server vendor provided: {server_vendor}")
            vendor_upper = server_vendor.upper()
            logger.debug(f"Server vendor upper case: {vendor_upper}")
            
            if vendor_upper == "HP":
                logger.debug("Detected server type: HP")
                return ServerType.HP
            elif vendor_upper == "DELL":
                logger.debug("Detected server type: DELL")
                return ServerType.DELL
            elif vendor_upper == "CISCO":
                logger.debug("Detected server type: CISCO")
                return ServerType.CISCO
            else:
                logger.info("Server vendor not recognized, falling back to auto-detection.")
        
        server_name_lower = server_name.lower()
        if "rf" in server_name_lower:
            logger.debug("Detected server type: HP based on server name.")
            return ServerType.HP
        elif "ome" in server_name_lower:
            logger.debug("Detected server type: DELL based on server name.")
            return ServerType.DELL
        else:
            logger.debug("Defaulting to CISCO server type.")
            return ServerType.CISCO

class ServerStrategyFactory:
    _strategies: Dict[ServerType, Type[ServerStrategy]] = {
        ServerType.HP: HPServerStrategy,
        ServerType.DELL: DellServerStrategy,
        ServerType.CISCO: CiscoServerStrategy,
    }

    @classmethod
    def create_strategy(cls, server_type: ServerType, credentials: Dict[str, str]) -> ServerStrategy:
        strategy_class = cls._strategies.get(server_type)
        if not strategy_class:
            raise ValueError(f"No strategy found for server type: {server_type}")
        return strategy_class(credentials)
    
    @classmethod
    def register_strategy(cls, server_type: ServerType, strategy_class: Type[ServerStrategy]) -> None:
        cls._strategies[server_type] = strategy_class
        