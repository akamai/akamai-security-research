from rpc_registration_lookup.base_rpc_registration_scraper import BaseRpcRegistrationExtractor
from rpc_registration_lookup.ida_rpc_registration_scraper import IdaProRpcRegistrationExtractor
from rpc_registration_lookup.radare_rpc_registration_scraper import Radare2RpcRegistrationExtractor

IDA = "idapro"
RADARE = "radare"

_factory = {
    IDA: IdaProRpcRegistrationExtractor,
    RADARE: Radare2RpcRegistrationExtractor
}
disassemblers = list(_factory.keys())


class UnsupportedDisassemblerTypeException(Exception):
    def __init__(self, dism_name: str) -> None:
        super().__init__(f"Disassembler {dism_name} is not currently supported")


def rpc_registration_scraper_factory(disassembler: str) -> BaseRpcRegistrationExtractor:
    if disassembler not in _factory:
        raise UnsupportedDisassemblerTypeException(disassembler)
    return _factory[disassembler]
