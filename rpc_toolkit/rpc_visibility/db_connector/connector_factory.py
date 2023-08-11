from db_connector.base_connector import RpcAbstractDB
from db_connector.neo4j_connector import RpcNeo4j

from typing import Type, Optional

NEO4J_DB = "neo4j"

_db_mapping = {
    NEO4J_DB: RpcNeo4j
}

SUPPORTED_DBS = list(_db_mapping.keys())

def db_factory(db_type: str) -> Type[RpcAbstractDB]:
    db_cls = _db_mapping.get(db_type)
    
    if db_cls is None:
        raise ValueError(f"DB type {db_type} is not supported")
    
    return db_cls()
