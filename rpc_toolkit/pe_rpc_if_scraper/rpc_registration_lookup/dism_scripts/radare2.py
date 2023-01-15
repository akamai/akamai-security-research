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

import r2pipe

from typing import List, Tuple, Dict
import json

TEMP_OUTPUT_FILE = "radare2_rpc_reg_info.tmp"
PARSING_ERROR = "argument_parsing_error"
BADADDR = "0xFFFFFFFFFFFFFFFF"

r2: r2pipe.open = None


def find_rpc_server_registration_funcs() -> List[Tuple[str, int]]:
    rpc_reg_imports = []

    imports = r2.cmdj('iij')
    if not imports:
        return rpc_reg_imports

    for imp in imports:
        if imp.get("name", "").startswith("RpcServerRegisterIf"):
            rpc_reg_imports.append((imp["name"], imp["plt"]))

    return rpc_reg_imports


def find_all_func_xrefs(func_ea: int) -> List[int]:
    xref_eas = []
    for xref in r2.cmdj(f'axtj @{func_ea}'):
        if "from" not in xref:
            continue
        xref_eas.append(xref["from"])

    return xref_eas


def get_func_start(ins_ea: int) -> int:
    return r2.cmdj(f"pdj1 @{ins_ea}")[0]["fcn_addr"]


def get_reg_value(arg_ea: int, reg_name: str): # -> Union[str, int]
    func_start_ea = get_func_start(arg_ea)
    for opcode_dism in reversed(r2.cmdj(f"pDj{arg_ea-func_start_ea} @{func_start_ea}")):
        if "," not in opcode_dism["opcode"]:
            # not relevant to argument setting
            continue
        _, vals = opcode_dism["opcode"].split(" ", 1)
        dest_arg, _ = vals.split(',')
        if dest_arg == reg_name:
            return parse_argument(opcode_dism["offset"])
    return PARSING_ERROR


def is_reg(reg: str) -> bool:
    return ((reg.startswith("r") or reg.startswith("e")) and (reg.endswith("x") or reg.endswith("p") or reg.endswith("i"))) or (reg.startswith("r") and reg[1] in ["1", "8", "9"])


def parse_argument(arg_ea: int): # -> Union[str, int]
    if arg_ea != BADADDR:
        opcode_dism = r2.cmdj(f"pdj1 @{arg_ea}")[0]["disasm"]
        mnem, vals = opcode_dism.split(" ", 1)
        dest_arg, source_arg = vals.split(",")
        source_arg = source_arg.replace("[", "").replace("]", "").strip()
        if mnem == 'xor':
            if dest_arg == source_arg:
                return 0
            else:
                return PARSING_ERROR
        if source_arg.startswith("0x") or source_arg.isdecimal():
            return source_arg
        elif is_reg(source_arg):
            return get_reg_value(arg_ea, source_arg)
    return PARSING_ERROR


def get_func_call_args(func_ea: int, arg_count: int):  # -> Union[str, int]
    xref_args = {}
    for xref_ea in find_all_func_xrefs(func_ea):
        args_addrs = get_call_args_manually(xref_ea, max_args=arg_count)
        args_addrs += [BADADDR] * (arg_count - len(args_addrs))
        xref_args[hex(xref_ea)] = [parse_argument(arg_ea) for arg_ea in args_addrs] if args_addrs else []
        
    return xref_args 


def get_call_args_manually(call_ea: int, max_look_behind: int = 20, max_args: int = 8) -> List[int]:
    func_start_ea = get_func_start(call_ea)
    stack_params = {}
    rcx = rdx = r8 = r9 = None
    for opcode_dism in reversed(r2.cmdj(f"pdj-{max_look_behind} @{call_ea}")):
        if all((rcx, rdx, r8, r9)) and len(stack_params) == max_args - 4:
            break
        if opcode_dism["fcn_addr"] != func_start_ea:  # We've went outside the scope of the function call
            break
        if "," not in opcode_dism["opcode"]:
            # not relevant to argument setting
            continue
        mnem, vals = opcode_dism["opcode"].split(" ", 1)
        dest_arg = vals[:vals.find(",")]
        if '[' in dest_arg:
            # print(dest_arg)
            if dest_arg.count("+") != 1:
                continue
            reg, disp = dest_arg[dest_arg.find("[")+1:dest_arg.find("]")].split("+")
            reg = reg.strip()
            disp = disp.strip()
            # print(reg, disp)
            if reg == "rsp" or reg == "esp":
                stack_params[disp] = opcode_dism["offset"]
        else:
            # doesn't really matter if it's out of order since subsequent inserts will fix it,
            # unless something has gone really wrong, and we've moved past the argument setup code.
            if dest_arg.endswith("cx") and rcx is None:
                rcx = opcode_dism["offset"]
            elif dest_arg.endswith("dx") and rdx is None:
                rdx = opcode_dism["offset"]
            elif dest_arg.startswith("r8") and r8 is None:
                r8 = opcode_dism["offset"]
            elif dest_arg.startswith("r9") and r9 is None:
                r9 = opcode_dism["offset"]
    args = [val if val else PARSING_ERROR for val in (rcx, rdx, r8, r9)]
    if len(args) < 4 or len(args) >= max_args:
        return args
    return args + [stack_params[off] for off in sorted(stack_params, key=stack_params.get, reverse=True)]


def get_rpc_server_registration_info() -> Dict[str, List[Dict[int, Tuple]]]:
    return {
        func_name: {"args": get_func_call_args(
            func_ea,
            get_arg_count_for_function_name(func_name))
        }
        for func_name, func_ea
        in find_rpc_server_registration_funcs()
    }


def get_arg_count_for_function_name(func_name: str) -> int:
    if func_name.endswith("2"):
        return 7
    elif func_name.endswith("3"):
        return 8
    elif func_name.endswith("Ex"):
        return 6
    else:
        return 3


if __name__ == "__main__":
    r2 = r2pipe.open()
    r2.pipe_read_sleep = 0.5
    r2.cmdj("aa;aac")
    reg_info = get_rpc_server_registration_info()
    with open(TEMP_OUTPUT_FILE, "wt", newline="\n") as f:
        json.dump(reg_info, f)
    r2.quit()
