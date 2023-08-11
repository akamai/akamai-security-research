from etw_tracker.connection_mapper import ConnectionMap
from etw_tracker.known_rpc_interfaces import known_interfaces

from typing import Optional, Dict
from datetime import datetime, timedelta
from socket import gethostbyname
import psutil

NULL_ACTIVITY_GUID = "{00000000-0000-0000-0000-000000000000}"
_PIPE_MAPS = {
    "ntsvcs": "svcctl",
    "lsass": "lsarpc"
}

class RpcStats:
    CALL_SIDE_CLIENT = "client"
    CALL_SIDE_SERVER = "server"

    @classmethod
    def _filetime_to_str(cls, ft):
        us = cls._filetime_to_epoch(ft) // 10
        return (datetime(1970, 1, 1) + timedelta(microseconds = us)).strftime("%Y-%m-%dT%H:%M:%S")
    
    @classmethod
    def _filetime_to_epoch(cls, ft):
        EPOCH_AS_FILETIME = 11644473600000
        return ft // 10**4 - EPOCH_AS_FILETIME

    def __init__(self, connection_map: ConnectionMap, process_map: Dict, event_id: int, event_data: Dict):
        self.activity_id = None
        self.call_side = None
        self.interface_uuid = None
        self.interface_name = None
        self.opnum = None
        self.function = None
        self.network_addr = None
        self.endpoint = None
        self.auth_level = None
        self.auth_service = None
        self.impersonation_level = None
        self.protocol = None
        self.pid = None
        self.process_name = None
        self.event_id = None
        self.computer_name = None
        self.image_name = None
        self.return_code = None
        self.timestamp = None
        self._connection_map = connection_map
        self._proc_map = process_map
        self.parse_event(event_id, event_data)

    def parse_call_start_event(self, event_data: Dict) -> None:
        self.interface_uuid = event_data["InterfaceUuid"].lower()[1:-1]
        self.opnum = event_data["ProcNum"]
        self.opnum = self.opnum if isinstance(self.opnum, int) else int(self.opnum, 16)
        if self.interface_uuid in known_interfaces:
            self.interface_name = known_interfaces[self.interface_uuid]["interface_name"]
            functions = known_interfaces[self.interface_uuid].get("functions", [])
            if self.opnum < len(functions):
                self.function = functions[self.opnum]
        self.protocol = event_data["Protocol"].strip()
        self.endpoint = event_data["Endpoint"]
        if self.call_side == self.CALL_SIDE_SERVER:
            if self.protocol == "TCP":
                self.network_addr = self._connection_map.port_to_host(self.endpoint)
                # print(f"found remote {self.network_addr} for port {self.endpoint}")
            elif self.protocol == "Named Pipes":
                pipe_name = self.endpoint.lower().replace("\\pipe\\", "")
                pipe_name = _PIPE_MAPS.get(pipe_name, pipe_name)
                self.network_addr = self._connection_map.file_to_host(pipe_name)
                # print(f"pipe {pipe_name} openend, found addr {self.network_addr}")
            else:
                self.network_addr = event_data["NetworkAddress"]
        else:
            self.network_addr = event_data["NetworkAddress"]
            if self.network_addr.startswith("\\\\"):
                self.network_addr = self.network_addr[2:]
            if self.network_addr != "NULL"  and any([x.isalpha() for x in self.network_addr]):
                try:
                    self.network_addr = gethostbyname(self.network_addr)
                except:
                    # print(f"failed gethostbyname for {self.network_addr}")
                    pass
        self.auth_level = event_data["AuthenticationLevel"]
        self.auth_service = event_data["AuthenticationService"]
        self.impersonation_level = event_data["ImpersonationLevel"]

    def parse_event_header(self, event_data: Dict) -> None:
        self.activity_id = event_data["EventHeader"]["ActivityId"]
        self.timestamp = self._filetime_to_epoch(event_data["EventHeader"]["TimeStamp"])
        # self.timestamp = event_data["EventHeader"]["TimeStamp"]
        self.pid = event_data["EventHeader"]["ProcessId"]
        self.process_name = self._proc_map.get(self.pid, None)

    def parse_call_end_event(self, event_data: Dict) -> None:
        self.return_code = event_data["Status"]
        self.pid = event_data["EventHeader"]["ProcessId"]

    def parse_error_event(self, event_data: Dict) -> None:
        self.pid = event_data["ProcessID"]
        self.computer_name = event_data["ComputerName"]
        self.image_name = event_data["ImageName"]
        self.return_code = event_data["Status"]

    def parse_event(self, event_id: int, event_data: Dict) -> None:
        self.event_id = event_id
        if event_id in [5, 7]:
            self.call_side = self.CALL_SIDE_CLIENT
        elif event_id in [6,8]:
            self.call_side = self.CALL_SIDE_SERVER
        if event_id in [5,6]:
            self.parse_call_start_event(event_data)
        elif event_id in [7,8]:
            self.parse_call_end_event(event_data)
        elif event_id == 1:
            self.parse_error_event(event_data)

        if event_id in [5,6] or self.activity_id == NULL_ACTIVITY_GUID:
            self.parse_event_header(event_data)

    def __str__(self):
        return f"Activity Id: {self.activity_id}, {self.interface_uuid} opnum {self.opnum}, event {self.event_id} event id"

    def to_dict(self) -> Dict:
        return {
            "activity_id"           : self.activity_id,
            "call_side"             : self.call_side,
            "interface_uuid"        : self.interface_uuid,
            "interface_name"        : self.interface_name,
            "opnum"                 : self.opnum,
            "function_name"         : self.function,
            "network_addr"          : self.network_addr,
            "endpoint"              : self.endpoint,
            "auth_level"            : self.auth_level,
            "auth_service"          : self.auth_service,
            "impersonation_level"   : self.impersonation_level,
            "protocol"              : self.protocol,
            "pid"                   : self.pid,
            "process_name"          : self.process_name,
            "computer_name"         : self.computer_name,
            "image_name"            : self.image_name,
            "return_code"           : self.return_code,
            "event_id"             : self.event_id,
            "timestamp"             : self.timestamp
        }

