from contextlib import nullcontext
from typing import Dict, Optional
from threading import Lock


_SOURCE_KEY = "_SOURCE_KEY_"


class ConnectionMap:
    def __init__(self, should_lock: bool = False) -> None:
        self._port_track: Dict = {}
        self._smb_track: Dict = {}
        if should_lock:
            self._tcp_lock = Lock()
            self._smb_lock = Lock()
        else:
            self._tcp_lock = nullcontext()
            self._smb_lock = nullcontext()


    def file_to_host(self, filename: str) -> Optional[str]:
        with self._smb_lock:
            for _,trees in self._smb_track.items():
                if filename in trees.values():
                    return trees.get(_SOURCE_KEY, None)
                
    def port_to_host(self, port: int) -> Optional[str]:
        with self._tcp_lock:
            return self._port_track.get(port, None)
        
    def add_file_mapping(self, connection_uuid: str, tree_uuid: str, filename: str) -> None:
        with self._smb_lock:
            if connection_uuid in self._smb_track:
                self._smb_track[connection_uuid][tree_uuid] = filename

    def del_file_mapping(self, connection_uuid:str, tree_uuid: str) -> None:
        with self._smb_lock:
            if connection_uuid in self._smb_track:
                self._smb_track[connection_uuid].pop(tree_uuid, None)
                # filename = self._smb_track[connection_uuid].pop(tree_uuid, "unknown")
                # print(f"{filename} closed on {connection_guid}")

    def add_smb_connection(self, connection_uuid: str, host: str) -> None:
        with self._smb_lock:
            self._smb_track[connection_uuid] = {_SOURCE_KEY: host}
        # print(f"{host} connected to {connection_uuid}")

    def del_smb_connection(self, connection_uuid: str) -> None:
        with self._smb_lock:
            self._smb_track.pop(connection_uuid, None)
            # trees = self._smb_track.pop(connection_uuid, None)
        # addr = trees[_SOURCE_KEY] if trees else "unknown"
        # print(f"{addr} disconnected from {connection_uuid}")

    def add_port_mapping(self, port: int, host: str) -> None:
        with self._tcp_lock:
            self._port_track[port] = host

    def del_port_mapping(self, port: int) -> None:
        with self._tcp_lock:
            self._port_track.pop(port, None)
