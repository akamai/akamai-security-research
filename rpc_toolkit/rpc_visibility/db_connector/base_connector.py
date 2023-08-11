from etw_tracker.rpc_stats import RpcStats

from socket import gethostname, getaddrinfo, AF_INET
from abc import ABC, abstractmethod
from typing import Optional, List

class RpcAbstractDB(ABC):
    def __del__(self):
        self.disconnect()

    @abstractmethod
    def connect_to_db(self, db_addr: str, db_port: Optional[int], username: Optional[str], password: Optional[str]) -> None:
        pass

    @abstractmethod
    def save_connection_stats(self, connection_stats: RpcStats) -> None:
        pass

    @abstractmethod
    def update_connection_stats(self, connection_stats: RpcStats) -> None:
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    def _create_node_for_host(self, hostname: str) -> None:
        ips = [ip[4][0] for ip in getaddrinfo(host=gethostname(), port=None, family=AF_INET)]
        self._save_node_data(hostname, ips)

    @abstractmethod
    def _save_node_data(self, hostname: str, ips: List[str]) -> None:
        pass