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
import idautils
import ida_ua
import ida_idp

from typing import List, Dict, Tuple, Optional

def get_import_funcs() -> Dict[str, List[Tuple]]:
    imports = {}
    current = ""

    def callback(ea: int, name: str, ordinal: int) -> bool:
        imports[current].append((ea, name, ordinal))
        return True

    nimps = idaapi.get_import_module_qty()
    for i in range(0, nimps):
        current = idaapi.get_import_module_name(i)
        imports[current] = []
        idaapi.enum_import_names(i, callback)
    return imports 

def get_imported_func_name(searched_ea: int) -> Optional[str]: 
    imports = get_import_funcs()
    for funcs in imports.values():
        for func_ea, func_name, _ in funcs:
            if func_ea == searched_ea:
                return func_name
    return

def get_call_instructions(func_addr: int) -> list: 
        call_instructions = []
        for startea, endea in idautils.Chunks(func_addr):
            for line_ea in idautils.Heads(startea, endea):
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, line_ea)
                
                if ida_idp.is_call_insn(insn): 
                    call_instructions.append(insn)
        return call_instructions
