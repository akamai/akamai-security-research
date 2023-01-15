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

import idaapi
import idc
import idautils
import ida_ua

from typing import List, Tuple, Dict, Optional  # Using `Union` typing causes IDA to raise an exception, so we don't use it
import json
import string

from security_callback_analyzer.security_callback_analyzer import analyze_security_callback
from security_callback_analyzer.rpc_call_attributes_struct import RpcCallAttrStructType

TEMP_OUTPUT_FILE = "ida_pro_rpc_reg_info.tmp"
PARSING_ERROR = "argument_parsing_error"


def find_rpc_server_registration_funcs() -> List[Tuple[str, int]]:
    rpc_reg_imports = []

    def imp_cb(ea: int, name: str, ord: int) -> bool:
        if name and name.startswith("RpcServerRegisterIf"):
            rpc_reg_imports.append((name, ea))
        return True

    for i in range(idaapi.get_import_module_qty()):
        import_name = idaapi.get_import_module_name(i)
        # print(import_name)
        if import_name.lower() != "rpcrt4":
            continue
        idaapi.enum_import_names(i, imp_cb)
    return rpc_reg_imports


def find_all_func_xrefs(func_ea: int) -> List[int]:
    xref_eas = []
    func_xref = idaapi.get_first_cref_to(func_ea)
    while func_xref != idaapi.BADADDR:
        xref_eas.append(func_xref)
        func_xref = idaapi.get_next_cref_to(func_ea, func_xref)

    return xref_eas


def get_reg_value(arg_ea: int): # -> Union[str, int]
    reg = idc.get_operand_value(arg_ea, 1)
    reg_name = idaapi.get_reg_name(reg, 8)
    func_start_ea = idaapi.get_func(arg_ea).start_ea
    ins_ea = idc.prev_head(arg_ea, func_start_ea)
    if ins_ea == idaapi.BADADDR:
        return reg_name
    while ins_ea != idaapi.BADADDR:
        if idc.get_operand_type(ins_ea, 0) == idc.o_reg and idc.get_operand_value(ins_ea, 0) == reg:
            return parse_argument(ins_ea)
        ins_ea = idc.prev_head(ins_ea, func_start_ea)
    return reg_name


def parse_argument(arg_ea: int): # -> Union[str, int]
    if arg_ea != idaapi.BADADDR:
        mnemonic = idaapi.ua_mnem(arg_ea)
        if mnemonic == 'xor':
            if idc.get_operand_value(arg_ea, 0) == idc.get_operand_value(arg_ea, 1):
                return 0
            else:
                return PARSING_ERROR
        if idc.get_operand_type(arg_ea, 1) in (idc.o_imm, idc.o_mem):
            return hex(idc.get_operand_value(arg_ea, 1))
        elif idc.get_operand_type(arg_ea, 1) == idc.o_reg:
            return get_reg_value(arg_ea)
    return PARSING_ERROR

def get_security_callback_addr(func_ea: str) -> int:
    try:
        return int(func_ea, 16)
    except ValueError:
        return 0
    except TypeError:
        return 0

def get_func_call_args(func_ea: int, arg_count: int):  # -> Union[str, int]
    xref_args = {}
    for xref_ea in find_all_func_xrefs(func_ea):
        args_addrs = idaapi.get_arg_addrs(xref_ea)
        if not args_addrs:
            args_addrs = get_call_args_manually(xref_ea, max_args=arg_count)
            args_addrs += [idaapi.BADADDR] * (arg_count - len(args_addrs))
        xref_args[hex(xref_ea)] = [parse_argument(arg_ea) for arg_ea in args_addrs] if args_addrs else []
    
    return xref_args 


def get_call_args_manually(call_ea: int, max_look_behind: int = 20, max_args: int = 8) -> List[int]:
    func_start_ea = idaapi.get_func(call_ea).start_ea
    stack_params = {}
    args = []
    ins_ea = call_ea
    for _ in range(max_look_behind):
        if len(stack_params) + len(args) == max_args:
            break
        ins_ea = idc.prev_head(ins_ea, func_start_ea)
        # print(ins_ea)
        if ins_ea == idaapi.BADADDR:
            break
        op_type = idc.get_operand_type(ins_ea, 0)
        if op_type == idc.o_displ:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, ins_ea)
            if insn.Op1.reg == 0x4: # rsp
                stack_params[idc.get_operand_value(ins_ea, 0)] = ins_ea
        elif op_type == idc.o_reg:
            reg_name = idaapi.get_reg_name(idc.get_operand_value(ins_ea, 0), 8)
            # doesn't really matter if it's out of order since subsequent inserts will fix it,
            # unless something has gone really wrong, and we've moved past the argument setup code.
            if reg_name == "rcx":
                args.insert(0, ins_ea)
            elif reg_name == "rdx":
                args.insert(1, ins_ea)
            elif reg_name == "r8":
                args.insert(2, ins_ea)
            elif reg_name == "r9":
                args.insert(3, ins_ea)
    if len(args) < 4 or len(args) >= max_args:
        return args
    return args + [stack_params[off] for off in sorted(stack_params, key=stack_params.get, reverse=True)]

def get_callback_addr_from_args(args: list) -> Optional[str]:
    """
    Functions RpcServerRegisterIf2 (7 args) and RpcServerRegisterIfEx (6 args) hold the security callback address on their last arg.
    Function RpcServerRegisterIf3 (8 args) holds the security callback address on the arg before their last arg.
    Function RpcServerRegisterIf doesn't accept a security callback address.
    """
    args_count = len(args)
    if args_count == 6 or args_count == 7:
        return args[-1]
    elif args_count == 8:
        return args[-2]
    else:
        return None       

def get_rpc_server_registration_info() -> Dict[str, List[Dict[int, Tuple]]]:
    reg_info = {}
    for func_name, func_ea in find_rpc_server_registration_funcs():
        args = get_func_call_args(func_ea, get_arg_count_for_function_name(func_name))
        security_callbacks_info = {}
        for xref_ea, xref_args in args.items():
            security_callbacks_info.update(get_security_callback_info(get_callback_addr_from_args(xref_args), xref_ea))
            reg_info.update({func_name: {"args": args, "security_callback_info": security_callbacks_info}})
    return reg_info

def get_arg_count_for_function_name(func_name: str) -> int:
    if func_name.endswith("2"):
        return 7
    elif func_name.endswith("3"):
        return 8
    elif func_name.endswith("Ex"):
        return 6
    else:
        return 3

def is_callback_uses_rpc_call_atributes(security_callback_addr: int) -> bool:
    stype = RpcCallAttrStructType(security_callback_addr)
    return stype.uses_rpc_call_attrs_struct()

def get_security_callback_info(addr: str, func_xref: str) -> Dict:
    security_callback_addr = get_security_callback_addr(addr)

    use_call_attributes = is_callback_uses_rpc_call_atributes(security_callback_addr)
    sc_info = {"use_call_attributes": use_call_attributes}

    if security_callback_addr == 0:
        return {}

    security_callback_checks = analyze_security_callback(security_callback_addr) if use_call_attributes else {}
    if security_callback_checks:
        sc_info.update({"security_callback_checks": security_callback_checks})
    
    return {func_xref: sc_info}

if __name__ == "__main__":
    idaapi.auto_wait()
    reg_info = get_rpc_server_registration_info()
    with open(TEMP_OUTPUT_FILE, "wt", newline="\n") as f:
        json.dump(reg_info, f)
    idaapi.qexit(0)
