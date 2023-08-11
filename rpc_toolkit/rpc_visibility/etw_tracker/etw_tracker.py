from db_connector.base_connector import RpcAbstractDB
from etw_tracker.connection_mapper import ConnectionMap
from etw_tracker.rpc_stats import RpcStats, NULL_ACTIVITY_GUID

from typing import Dict, Tuple, List
from threading import Lock, Thread, Event
from etw.evntrace import TRACE_LEVEL_INFORMATION
from etw.etw import ETW, ProviderInfo
from etw.GUID import GUID
import signal

class EtwTracker:
    # Ideally I would do the event id check with a filter in the ETW provider, but it's a headache with all the necessary pointers in ctypes.
    # So this is good enough for now. A C/C++ solution should use ENABLE_TRACE_PARAMETERS in the ETW provider.
    RPC_ETW_NAME = "Microsoft-Windows-RPC"
    RPC_ETW_GUID = "{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}"
    RPC_ETW_EVENTS = [1, 5, 6, 7, 8]
    TCP_ETW_NAME = "Microsoft-Windows-TCPIP"
    TCP_ETW_GUID = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}"
    TCP_ETW_EVENTS = [1017, 1184, 1185]
    SMB_ETW_GUID = "{D48CE617-33A2-4BC3-A5C7-11AA4F29619E}"
    SMB_ETW_NAME = "Microsoft-Windows-SMBServer"
    SMB_ETW_EVENTS = [8, 9, 500, 501, 502]
    PROCESS_ETW_NAME = "Microsoft-Windows-Kernel-Process",
    PROCESS_ETW_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
    LOST_EVENT_GUID = "{6A399AE0-4BC6-4DE9-870B-3657F8947E7E}"


    def __init__(self, db_saver: RpcAbstractDB):
        self._event_chains = {}
        self._chain_lock = Lock()
        self._connection_map = ConnectionMap()
        self._process_map = {}
        self._db_saver = db_saver
        # The three providers have to be on the same consumer otherwise the connect-disconnect parsing occurs BEFORE the RPC parsing (or it's technically a race, and we know who's faster)
        # Being on the same consumer make it more streamlined/sequentional
        self._rpc_track = ETW(
            providers = [
                ProviderInfo(
                    self.RPC_ETW_NAME,
                    GUID(self.RPC_ETW_GUID),
                    TRACE_LEVEL_INFORMATION
                ),
                ProviderInfo(
                    self.TCP_ETW_NAME,
                    GUID(self.TCP_ETW_GUID),
                    TRACE_LEVEL_INFORMATION,
                    any_keywords=0x400000000
                ),
                ProviderInfo(
                    self.SMB_ETW_NAME,
                    GUID(self.SMB_ETW_GUID),
                    TRACE_LEVEL_INFORMATION,
                    any_keywords= 0x8000000000000001 | 0x4000000000000010
                ),
                ProviderInfo(
                    self.PROCESS_ETW_NAME,
                    GUID(self.PROCESS_ETW_GUID),
                    TRACE_LEVEL_INFORMATION,
                    0x40 | 0x10
                )
            ],
            event_callback = self._track_etw,
            event_id_filters = self.RPC_ETW_EVENTS + self.SMB_ETW_EVENTS + self.TCP_ETW_EVENTS
        )

    def _track_etw(self, event_tup: Tuple[int, Dict]) -> None:
        event_id, event_data = event_tup
        provider_id = event_tup[1]["EventHeader"]["ProviderId"]
        if provider_id == self.RPC_ETW_GUID:
            self._track_rpc(event_id, event_data)
        elif provider_id == self.TCP_ETW_GUID:
            self._track_tcp_connections(event_id, event_data)
        elif provider_id == self.SMB_ETW_GUID:
            self._track_smb_files(event_id, event_data)
        elif provider_id == self.PROCESS_ETW_GUID:
            self._track_process_creation(event_id, event_data)
        elif provider_id == self.LOST_EVENT_GUID:
            return
        else:
            raise ValueError(f"Unknown ETW provider {provider_id}")
      
    def _track_rpc(self, event_id: int, event_data: Dict) -> None:
        if event_id not in self.RPC_ETW_EVENTS:
            return
        
        event = RpcStats(self._connection_map, self._process_map, event_id, event_data)

        if (event.interface_uuid is None) or (event.opnum is None):
            # nothing we can do about it really
            return
        
        with self._chain_lock:
            if event.activity_id == NULL_ACTIVITY_GUID:
                self._db_saver.save_connection_stats(event)
                # Thread(target=self._db_saver.save_connection_stats, args=(event,)).start()
            else:
                self._db_saver.update_connection_stats(event)
                # Thread(target=self._db_saver.update_connection_stats, args=(event,)).start()

    @staticmethod
    def _parse_event_connection(ip_addr: str) -> List[str]:
        # pywintrace already parses the address and gives a string from format <ip>:<port>. That is not the case in the raw event data.
        # In raw event data the network address is a binary field
        #   1st byte - Address Family (2 for AF_INET)
        #   3rd-4th bytes - port
        #   5th-8th bytes - ip address, each byte is an octet

        if ip_addr.count(":") == 1: # crude solution to filter ipv6 out
            return ip_addr.split(":")
        elif "." in ip_addr:
            ip, port = ip_addr.rsplit(":", 1)
            ip = "".join([c for c in ip if c.isdigit() or c == '.'])
            return ip, port
        else:
            return None, None
    
    def _track_tcp_connections(self, event_id: int, event_data: Dict) -> None:
        if event_id not in self.TCP_ETW_EVENTS:
            return
        _, local_port = self._parse_event_connection(event_data["LocalAddress"])
        remote_addr, _ = self._parse_event_connection(event_data["RemoteAddress"])

        if not local_port or not remote_addr:
            return
        
        if event_id == 1017:
            self._connection_map.add_port_mapping(local_port, remote_addr)
            # print(f"{remote_addr} connected to {local_port}")
        else:
            self._connection_map.del_port_mapping(local_port)
            # print(f"{remote_addr} disconnected from {local_port}")

    def _track_smb_files(self, event_id: int, event_data: Dict) -> None:
        if event_id not in self.SMB_ETW_EVENTS:
            return
        connection_guid = event_data["ConnectionGUID"]
        if event_id == 500:
            addr = self._parse_event_connection(event_data["Address"])[0]
            self._connection_map.add_smb_connection(connection_guid, addr)
        elif event_id == 501 or event_id == 502:
            self._connection_map.del_smb_connection(connection_guid)
        elif event_id == 8:
            filename = event_data["FileName"]
            if filename:
                filename = filename.lower()
            tree_connect_guid = event_data["TreeConnectGUID"]
            self._connection_map.add_file_mapping(connection_guid, tree_connect_guid, filename)
            # print(f"{filename} opened on {connection_guid}")
        elif event_id == 9:
            tree_connect_guid = event_data["TreeConnectGUID"]
            self._connection_map.del_file_mapping(connection_guid, tree_connect_guid)

    def _track_process_creation(self, event_id: int, event_data: Dict) -> None:
        if event_id == 1:
            self._process_map[int(event_data["ProcessID"])] = event_data["ImageName"]
        elif event_id == 2:
            self._process_map.pop(event_data["ProcessID"], None)
        else:
            return
        
    def start_tracking(self) -> None:
        self._rpc_track.start()

    def stop_tracking(self) -> None:
        self._rpc_track.stop()

    def wait(self) -> None:
        def stop_signal(signum, frame):
            self.stop_tracking()
            stop_event.set()

        stop_event = Event()
        signal.signal(signal.SIGTERM, stop_signal)
        signal.signal(signal.SIGINT, stop_signal)
        while not stop_event.wait(1):
            pass

