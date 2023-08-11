from etw_tracker.rpc_stats import RpcStats, NULL_ACTIVITY_GUID
from db_connector.base_connector import RpcAbstractDB

from typing import Optional, List, Dict
from neo4j import GraphDatabase
from socket import gethostname, gethostbyname


class RpcNeo4j(RpcAbstractDB):
    def __init__(self) -> None:
        self._driver = None
        self._hostname = gethostname()
        self._connected = False
    
    def disconnect(self) -> None:
        if self._connected:
            self._driver.close()

    def connect_to_db(self, db_addr: str, username: Optional[str], password: Optional[str]) -> None:
        self._driver = GraphDatabase.driver(db_addr, auth=(username, password))
        self._connected = True
        self._create_node_for_host(self._hostname)

    def _save_node_data(self, hostname: Optional[str], ips: List[str]) -> None:
        assert self._connected
        with self._driver.session() as session:
            if hostname:
                if not session.run(f"MATCH (c:Computer) WHERE c.hostname = '{self._hostname}' RETURN c").single():  
                    session.run("CREATE (c:Computer {hostname: '" + hostname + "', ips: "+ str(ips) + "})")
                else:
                    session.run("MATCH (c:Computer) WHERE c.hostname = '" + hostname + "' SET c.ips = "+ str(ips))
            else:
                session.run("CREATE (c:Computer {hostname: 'unknown', ips: "+ str(ips) + "})")

    def save_connection_stats(self, rpc_stats: RpcStats) -> None:
        assert self._connected
        if rpc_stats.activity_id == NULL_ACTIVITY_GUID and rpc_stats.interface_uuid is None:
            return
        
        if rpc_stats.protocol == "LRPC":
            return

        stat_dict = rpc_stats.to_dict()
        network_addr = stat_dict.pop("network_addr", None)
        if network_addr == "NULL":
            network_addr = None
        
        side = stat_dict.pop("call_side", None)
        if side == RpcStats.CALL_SIDE_CLIENT:
            source = self._hostname
            destination = network_addr if network_addr else self._hostname
        elif side == RpcStats.CALL_SIDE_SERVER:
            destination = self._hostname
            source = network_addr if network_addr else self._hostname
        else:
            return
                
        with self._driver.session() as session:
            if not session.run(f"MATCH (c:Computer) WHERE (c.hostname='{source}' OR '{source}' IN c.ips) RETURN c").single():
                print(f"new source {source}")
                self._save_external_node(source)
            if not session.run(f"MATCH (c:Computer) WHERE (c.hostname='{destination}' OR '{destination}' IN c.ips) RETURN c").single():
                print(f"new dest {destination}")
                self._save_external_node(destination)

            session.run(f"""
                            MATCH
                                (s:Computer),(d:Computer)
                            WHERE (s.hostname='{source}' OR '{source}' IN s.ips) AND (d.hostname='{destination}' OR '{destination}' IN d.ips)
                            CREATE (s)-[:Connects {{{self.dict_to_query_format(stat_dict, "{}: {}")}}}]->(d)
                        """
            )

    def _save_external_node(self, node: str) -> None:
        if any([c.isalpha() for c in node]):
            ip = gethostbyname(node)
            hostname = node
        else:
            ip = node
            hostname = None

        self._save_node_data(hostname, [ip])
    
    def update_connection_stats(self, rpc_stats: RpcStats) -> None:
        if rpc_stats.protocol == "LRPC":
            return

        stat_dict = rpc_stats.to_dict()
        stat_dict.pop("network_addr", None)
        stat_dict.pop("call_side", None)

        # We correlate by activity ID and opnums as well, because DCOM events all share the same activity id and can reach event chains of hundred events even though they span different interfaces and opnums
        query = f"""
            MATCH (:Computer)<-[r:Connects]->(:Computer)
            WHERE r.activity_id = '{rpc_stats.activity_id}'
            AND r.opnum = {rpc_stats.opnum} AND r.interface_uuid = '{rpc_stats.interface_uuid}'
            SET {self.dict_to_query_format(stat_dict, "r.{}={}")}
            RETURN 1
        """

        with self._driver.session() as session:
            if not session.run(query).data(): # it means we were requested to update a relation that doesn't exist, so we need to create it
                self.save_connection_stats(rpc_stats)

    @classmethod
    def dict_to_query_format(cls, data_dict: Dict, format_str: str) -> str:
        query_str = ""
        for key, value in data_dict.items():
            if key == "timestamp" and value is not None:
                value = "datetime({epochmillis:" + str(value) + "})"
            elif not (isinstance(value, int) or isinstance(value,list)):
                value = f"'{str(value).strip()}'"
            elif value is None:
                value = "NULL"
            query_str += format_str.format(key, value)
            query_str += ", "
        return query_str[:-2]

