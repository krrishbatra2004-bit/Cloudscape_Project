from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

class BaseCloudDriver(ABC):
    """
    Interface for all cloud discovery drivers.
    Ensures a standardized data structure across different providers.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def initialize_session(self) -> Any:
        """Handles authentication and session creation."""
        pass

    @abstractmethod
    def scan_compute(self) -> List[Dict[str, Any]]:
        """Discovers EC2, Virtual Machines, or Compute Instances."""
        pass

    @abstractmethod
    def scan_storage(self) -> List[Dict[str, Any]]:
        """Discovers S3, Blob Storage, or Buckets."""
        pass

    @abstractmethod
    def scan_network(self) -> Dict[str, Any]:
        """Discovers VPCs, Subnets, and Load Balancers."""
        pass

    @abstractmethod
    def get_full_inventory(self) -> Dict[str, Any]:
        """Orchestrates a full scan and returns a consolidated manifest."""
        pass