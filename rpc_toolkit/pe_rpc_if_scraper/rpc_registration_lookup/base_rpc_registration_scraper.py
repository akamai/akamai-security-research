# Akamai RPC Toolkit
# Copyright 2022 Akamai Technologies, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in
# compliance with the License.  You may obtain a copy
# of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing
# permissions and limitations under the License.

from typing import Dict, List, Callable, Union, Optional, Tuple
from abc import abstractmethod, ABCMeta


UNKNOWN_ADDRESS = "unknown_address"
PARSING_ERROR = "argument_parsing_error"

INTERFACE_FLAGS = "flags"
INTERFACE_SECURITY_CALLBACK = "security_callback_addr"
INTERFACE_HAS_DESCRIPTOR = "has_security_descriptor"
INTERFACE_ADDRESS = "interface_address"
INTERFACE_SECURITY_CALLBACK_INFO = "security_callback_info"


class UnknownRpcServerRegistrationFunctionException(Exception):
    def __init__(self, func_name: str) -> None:
        super().__init__(f"Unknown RpcServerRegister function {func_name}")


class DismExtractorFailue(Exception):
    def __init__(self, return_code: int) -> None:
        super().__init__(f"Running the dism failed, return code {return_code}")


class BaseRpcRegistrationExtractor(metaclass=ABCMeta):
    _default_dism_path: str = None

    def __init__(self, dism_path: Optional[str] = None) -> None:
        self._pe_path: Optional[str] = None
        self._dism_path = dism_path if dism_path else self._default_dism_path

    def get_rpc_registration_info(self, pe_path: str) -> Dict[str, Dict]:
        reg_info = {}
        for func_name, func_info in self._get_rpc_registration_info(pe_path).items():
            func_calls = func_info.get("args", {})
            security_callbacks = func_info.get("security_callback_info", None)
            for xref, xref_params in func_calls.items():
                parsed_params = self._get_parser_for_func_name(func_name)(xref_params)
                security_callback = security_callbacks.get(xref, None) if security_callbacks else None
                reg_info[xref] = {
                    INTERFACE_ADDRESS: parsed_params[0],
                    INTERFACE_FLAGS: parsed_params[1],
                    INTERFACE_SECURITY_CALLBACK: parsed_params[2],
                    INTERFACE_HAS_DESCRIPTOR: parsed_params[3],
                    INTERFACE_SECURITY_CALLBACK_INFO: security_callback
                }         
        return reg_info

    @abstractmethod
    def _get_rpc_registration_info(self, pe_path: str) -> Dict[str, Dict[str, List]]:
        # This function should use the disassembler and return all rpc registration function calls and their arguments.
        # The output should look like this:
        # {
        #     function_name: {
        #                        function_xref_addr: [[arg1, arg2, arg3...], use_call_attributes, security_callback_info],
        #                        function_other_xref_addr: [[arg1, arg2, arg3...], use_call_attributes, security_callback_info],
        #                        ...
        #                    }
        # }
        raise NotImplemented()

    def _get_parser_for_func_name(self, func_name: str) -> Callable:
        if func_name == "RpcServerRegisterIf2" or func_name == "RpcServerRegisterIfEx":
            return self._parse_server_register_ex
        elif func_name == "RpcServerRegisterIf":
            return self._parse_server_register
        elif func_name == "RpcServerRegisterIf3":
            return self._parse_server_register3
        else:
            raise UnknownRpcServerRegistrationFunctionException(func_name)

    def _parse_server_register_ex(self, args: List) -> Tuple[str, Union[int, str], Optional[str], bool]:
        return self._formalize_params(rpc_if_addr=args[0], flags=args[3], security_callback=args[-1])

    def _parse_server_register(self, args: List) -> Tuple[str, Union[int, str], Optional[str], bool]:
        return self._formalize_params(rpc_if_addr=args[0])

    def _parse_server_register3(self, args: List) -> Tuple[str, Union[int, str], Optional[str], bool]:
        explicit_security_descriptor = args[7] is not None and args[7] != PARSING_ERROR
        return self._formalize_params(args[0], args[3], args[6], explicit_security_descriptor)

    @staticmethod
    def _formalize_params(
            rpc_if_addr: str = UNKNOWN_ADDRESS,
            flags: Union[int, str] = 0,
            security_callback: Optional[str] = None,
            explicit_security_descriptor: bool = False
    ) -> Tuple[str, Union[int, str], Optional[str], bool]:
        return rpc_if_addr, flags, security_callback, explicit_security_descriptor
