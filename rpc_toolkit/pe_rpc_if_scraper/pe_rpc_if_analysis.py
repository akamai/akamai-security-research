from rpc_registration_lookup.base_rpc_registration_scraper import\
    BaseRpcRegistrationExtractor,\
<<<<<<< HEAD
=======
    INTERFACE_SECURITY_CALLBACK,\
>>>>>>> a47327a9a16c08db23aa58c8177ca9ea4f4f3c20
    INTERFACE_FLAGS,\
    PARSING_ERROR
from pe_utils import get_rdata_offset_size_rva, assert_dotnet_pe, ptr_to_rva
from symbol_helper import PESymbolMatcher

<<<<<<< HEAD

=======
>>>>>>> a47327a9a16c08db23aa58c8177ca9ea4f4f3c20
from typing import List, Dict, Any, Union, Optional
from contextlib import contextmanager
from pefile import PE
from uuid import UUID
import platform
import re

RPC_IF_SEC_NO_CACHE = 64
RPC_IF_SEC_CACHE_PER_PROC = 128


@contextmanager
def sym_help_dummy(pe_path: str) -> None:
    yield


class PeRpcInterfaceScraper:
    RPC_SIDE_CLIENT = "client"
    RPC_SIDE_SERVER = "server"
    
    DCE_SYNTAX_UUID = UUID("8A885D04-1CEB-11C9-9FE8-08002B104860")
    MIDL_LOOKUP_RE = re.compile(b'\x60\x00\x00\x00.{20}' + re.escape(DCE_SYNTAX_UUID.bytes_le), re.DOTALL)

    def __init__(self, disassembler: Optional[BaseRpcRegistrationExtractor] = None) -> None:
        self._can_parse_symbols = platform.system() == "Windows"
        self._sym_helper = PESymbolMatcher() if self._can_parse_symbols else sym_help_dummy
        if disassembler:
            assert isinstance(disassembler, BaseRpcRegistrationExtractor)
            self.disassembler = disassembler
        else:
            self.disassembler = None

    def __del__(self) -> None:
        if self._can_parse_symbols:
            del self._sym_helper

    def scrape_executable(self, pe_path: str) -> Dict[str, Any]:
        with open(pe_path, 'rb') as f:
            pe_data = f.read()
        pe = PE(data=pe_data)

        # We're signaling out .NET executables since they're built differently, and this parsing method would not work.
        assert_dotnet_pe(pe)

        rdata_off, rdata_size, rdata_rva = get_rdata_offset_size_rva(pe)
        rdata = pe_data[rdata_off: rdata_off + rdata_size]
        if_offs = self._get_rpc_if_offsets(rdata)

        with self._sym_helper(pe_path):
            ret_dict = {}
            for if_rdata_offset in if_offs:
                interface_data = self._get_interface_data(pe, if_rdata_offset+rdata_off)
                interface_data['interface_address'] = hex(if_rdata_offset + rdata_rva + pe.OPTIONAL_HEADER.ImageBase)
                ret_dict[str(UUID(bytes_le=rdata[if_rdata_offset+4:if_rdata_offset+20]))] = interface_data

<<<<<<< HEAD
        if self.disassembler and any(interface['role'] == self.RPC_SIDE_SERVER for interface in ret_dict.values()):
            registration_info = self.disassembler.get_rpc_registration_info(pe_path)
            for info in registration_info.values():
                info['global_caching_enabled'] = self._check_flags_for_global_cache(info[INTERFACE_FLAGS])
            ret_dict['interface_registration_info'] = registration_info
=======
            if self.disassembler and any(interface['role'] == self.RPC_SIDE_SERVER for interface in ret_dict.values()):
                registration_info = self.disassembler.get_rpc_registration_info(pe_path)
                for info in registration_info.values():
                    info['global_caching_enabled'] = self._check_flags_for_global_cache(info[INTERFACE_FLAGS])
                    if info[INTERFACE_SECURITY_CALLBACK] == PARSING_ERROR:
                        info['security_callback_name'] = ""
                    else:
                        info['security_callback_name'] = self._sym_helper.sym_from_addr(
                            int(info[INTERFACE_SECURITY_CALLBACK], 16),
                        )
                ret_dict['interface_registration_info'] = registration_info
>>>>>>> a47327a9a16c08db23aa58c8177ca9ea4f4f3c20

        return ret_dict

    def _get_rpc_if_offsets(self, data: bytes) -> List[int]:
        return [match.start() for match in self.MIDL_LOOKUP_RE.finditer(data)]

    def _get_interface_data(
        self,
        pe: PE,
        interface_off: int
    ) -> Dict[str, Union[int, str]]:
        """
        The RPC interface struct looks like this:
        DWORD       size;                       // 0x0
        GUID        interface_id;               // 0x4
        WORD        interface_version_major;    // 0x14
        WORD        interface_version_minor;    // 0x16
        GUID        transfer_syntax;            // 0x18
        WORD        transfer_version_major;     // 0x28
        WORD        transfer_version_minor;     // 0x2A
        DWORD       alignment_filler;           // 0x2C
        VOID *      dispatch_table;             // 0x30
        DWORD       endpoint count;             // 0x38
        DWORD       alignment_filler;           // 0x3C
        VOID *      endpoint_table;             // 0x40
        VOID *      manager_ep_vector;          // 0x48
        VOID *      func_table;                 // 0x50
        LONGLONG    flags;                      // 0x58
        :param pe: the PE object for the pe file that we analyze.
        :param interface_off: the offset of the MIDL struct that we parse.
        :return: a dict with all function information for the struct.
        """
        # The pointers inside the MIDL struct are absolute values so we need to calculate the RVA manually.
        res_dict = {}
        rpc_stub_ptr = pe.get_qword_from_offset(interface_off + 0x30)
        if rpc_stub_ptr:
            res_dict["number_of_functions"] = pe.get_qword_at_rva(ptr_to_rva(rpc_stub_ptr, pe))
            role = self.RPC_SIDE_SERVER
            rpc_func_list_ptr = pe.get_qword_at_rva(ptr_to_rva(pe.get_qword_from_offset(interface_off + 0x50) + 0x8, pe))
            func_ptrs = [
                pe.get_qword_at_rva(ptr_to_rva(rpc_func_list_ptr + i * 8, pe))
                for i in range(res_dict["number_of_functions"])
            ]
            res_dict["functions_pointers"] = [hex(addr) for addr in func_ptrs if addr]
            if self._can_parse_symbols:
                res_dict["function_names"] = [self._sym_helper.sym_from_addr(addr) for addr in func_ptrs if addr]
        else:
            # Only RPC Servers have function stubs.
            # For clients, the marshalling is done inline, so it's not in the struct.
            role = self.RPC_SIDE_CLIENT

        res_dict['role'] = role
        res_dict['flags'] = hex(pe.get_qword_from_offset(interface_off + 0x58))
        return res_dict

    @staticmethod
    def _check_flags_for_global_cache(flags: Union[int, str]) -> Union[bool, str]:
        if type(flags) == str:
            if flags.startswith('0x'):
                flags = int(flags, 16)
            elif flags.isdecimal():
                flags = int(flags, 10)
            else:
                return PARSING_ERROR
        return (flags & RPC_IF_SEC_CACHE_PER_PROC) == 0 and (flags & RPC_IF_SEC_NO_CACHE) == 0
