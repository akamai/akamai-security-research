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

import idc 
import idaapi
import idautils
import ida_idp
import ida_funcs
import ida_frame
import ida_struct
import ida_hexrays
import ida_typeinf
import ida_ua

from typing import Dict, Tuple, Optional
from security_callback_analyzer.helper_funcs import get_call_instructions

################################
#         Const Values         #
################################

RPC_CALL_ATTRS_LVAR_NAME = "RpcCallAttributes"

TYPES_TO_SIZES = {idc.FF_BYTE: 1, idc.FF_WORD: 2, idc.FF_DWORD: 4, idc.FF_QWORD: 8, idc.FF_TBYTE: 10, idc.FF_STRLIT: None, 
                    idc.FF_STRUCT: None, idc.FF_OWORD: 16, idc.FF_FLOAT: 4, idc.FF_DOUBLE: 8, idc.FF_PACKREAL: 10, idc.FF_ALIGN: None}

UUID_struct_members = {
    "Data1": (0x00000000, idc.FF_DWORD),
    "Data2": (0x00000004, idc.FF_WORD),
    "Data3": (0x00000006, idc.FF_WORD),
    "Data4": (0x00000008, idc.FF_QWORD),
}

# Duplicating RPC_CALL_ATTRIBUTES_V<X>_A into RPC_CALL_ATTRIBUTES_V<X>_W on purpose. 
# Microsoft can change those structures in the future so we're leaving here both definitions in case any change should be done.

RPC_CALL_ATTRIBUTES_V1_A_struct_members = {
    "Version": (0x00000000, idc.FF_DWORD, None),
    "Flags": (0x00000004, idc.FF_DWORD, None), 
    "ServerPrincipalNameBufferLength": (0x00000008, idc.FF_DWORD, None), 
    "Padding_for_alignment_1": (0x0000000C, idc.FF_DWORD, None), 
    "ServerPrincipalName": (0x00000010, idc.FF_QWORD, None), 
    "ClientPrincipalNameBufferLength": (0x00000018, idc.FF_DWORD, None), 
    "Padding_for_alignment_2": (0x0000001c, idc.FF_DWORD, None), 
    "ClientPrincipalName": (0x00000020, idc.FF_QWORD, None), 
    "AuthenticationLevel": (0x00000028, idc.FF_DWORD, None), 
    "AuthenticationService": (0x0000002C, idc.FF_DWORD, None), 
    "NullSession": (0x00000030, idc.FF_DWORD, None)
    }

RPC_CALL_ATTRIBUTES_V1_W_struct_members = {
    "Version": (0x00000000, idc.FF_DWORD, None),
    "Flags": (0x00000004, idc.FF_DWORD, None), 
    "ServerPrincipalNameBufferLength": (0x00000008, idc.FF_DWORD, None), 
    "Padding_for_alignment_1": (0x0000000C, idc.FF_DWORD, None), 
    "ServerPrincipalName": (0x00000010, idc.FF_QWORD, None), 
    "ClientPrincipalNameBufferLength": (0x00000018, idc.FF_DWORD, None), 
    "Padding_for_alignment_2": (0x0000001c, idc.FF_DWORD, None), 
    "ClientPrincipalName": (0x00000020, idc.FF_QWORD, None), 
    "AuthenticationLevel": (0x00000028, idc.FF_DWORD, None), 
    "AuthenticationService": (0x0000002C, idc.FF_DWORD, None), 
    "NullSession": (0x00000030, idc.FF_DWORD, None)
    }

RPC_CALL_ATTRIBUTES_V2_A_struct_members = RPC_CALL_ATTRIBUTES_V1_A_struct_members
RPC_CALL_ATTRIBUTES_V2_A_struct_members.update({
    "KernelModeCaller": (0x00000034, idc.FF_DWORD, None), 
    "ProtocolSequence": (0x00000038, idc.FF_DWORD, None), 
    "IsClientLocal": (0x0000003C, idc.FF_DWORD, None), 
    "ClientPID": (0x00000040, idc.FF_QWORD, None), 
    "CallStatus": (0x00000048, idc.FF_DWORD, None), 
    "CallType": (0x0000004C, idc.FF_DWORD, None), 
    "CallLocalAddress": (0x00000050, idc.FF_QWORD, None), 
    "OpNum": (0x00000058, idc.FF_WORD, None), 
    "Padding_for_alignment_3": (0x0000005A, idc.FF_WORD, None), 
    "InterfaceUuid": (0x0000005C, idc.FF_STRUCT, "UUID"), # type UUID
    "Padding_for_alignment_4": (0x0000006C, idc.FF_DWORD, None)})


RPC_CALL_ATTRIBUTES_V2_W_struct_members = RPC_CALL_ATTRIBUTES_V1_W_struct_members
RPC_CALL_ATTRIBUTES_V2_W_struct_members.update({
    "KernelModeCaller": (0x00000034, idc.FF_DWORD, None), 
    "ProtocolSequence": (0x00000038, idc.FF_DWORD, None), 
    "IsClientLocal": (0x0000003C, idc.FF_DWORD, None), 
    "ClientPID": (0x00000040, idc.FF_QWORD, None), 
    "CallStatus": (0x00000048, idc.FF_DWORD, None), 
    "CallType": (0x0000004C, idc.FF_DWORD, None), 
    "CallLocalAddress": (0x00000050, idc.FF_QWORD, None), 
    "OpNum": (0x00000058, idc.FF_WORD, None), 
    "Padding_for_alignment_3": (0x0000005A, idc.FF_WORD, None), 
    "InterfaceUuid": (0x0000005C, idc.FF_STRUCT, "UUID"), # type UUID
    "Padding_for_alignment_4": (0x0000006C, idc.FF_DWORD, None)})


RPC_CALL_ATTRIBUTES_V3_A_struct_members = RPC_CALL_ATTRIBUTES_V2_A_struct_members
RPC_CALL_ATTRIBUTES_V3_A_struct_members.pop("Padding_for_alignment_4")
RPC_CALL_ATTRIBUTES_V3_A_struct_members.update({ 
    "ClientIdentifierBufferLength": (0x0000006C, idc.FF_DWORD, None), 
    "ClientIdentifier": (0x00000070, idc.FF_QWORD, None)
    })

RPC_CALL_ATTRIBUTES_V3_W_struct_members = RPC_CALL_ATTRIBUTES_V2_W_struct_members
RPC_CALL_ATTRIBUTES_V3_W_struct_members.pop("Padding_for_alignment_4")
RPC_CALL_ATTRIBUTES_V3_W_struct_members.update({ 
    "ClientIdentifierBufferLength": (0x0000006C, idc.FF_DWORD, None), 
    "ClientIdentifier": (0x00000070, idc.FF_QWORD, None)
    })

STRUCTS_MEMBERS = {"RPC_CALL_ATTRIBUTES_V1_A": RPC_CALL_ATTRIBUTES_V1_A_struct_members, 
                   "RPC_CALL_ATTRIBUTES_V1_W": RPC_CALL_ATTRIBUTES_V1_W_struct_members, 
                   "RPC_CALL_ATTRIBUTES_V2_A": RPC_CALL_ATTRIBUTES_V2_A_struct_members, 
                   "RPC_CALL_ATTRIBUTES_V2_W": RPC_CALL_ATTRIBUTES_V2_W_struct_members, 
                   "RPC_CALL_ATTRIBUTES_V3_A": RPC_CALL_ATTRIBUTES_V3_A_struct_members, 
                   "RPC_CALL_ATTRIBUTES_V3_W": RPC_CALL_ATTRIBUTES_V3_W_struct_members} 


def get_struc_err(errno: int) -> str:
    STRUC_ERROR_MEMBER_NAME    = -1 # already has member with this name (bad name)
    STRUC_ERROR_MEMBER_OFFSET  = -2 # already has member at this offset
    STRUC_ERROR_MEMBER_SIZE    = -3 # bad number of bytes or bad sizeof(type)
    STRUC_ERROR_MEMBER_TINFO   = -4 # bad typeid parameter
    STRUC_ERROR_MEMBER_STRUCT  = -5 # bad struct id (the 1st argument)
    STRUC_ERROR_MEMBER_UNIVAR  = -6 # unions can't have variable sized members
    STRUC_ERROR_MEMBER_VARLAST = -7 # variable sized member should be the last member in the structure

    if errno == STRUC_ERROR_MEMBER_NAME:
        return "STRUC_ERROR_MEMBER_NAME: already has member with this name (bad name)"
    elif errno == STRUC_ERROR_MEMBER_OFFSET:
        return "STRUC_ERROR_MEMBER_OFFSET: already has member at this offset"
    elif errno == STRUC_ERROR_MEMBER_SIZE:
        return "STRUC_ERROR_MEMBER_SIZE: bad number of bytes or bad sizeof(type)" 
    elif errno == STRUC_ERROR_MEMBER_TINFO:
        return "STRUC_ERROR_MEMBER_TINFO: bad typeid parameter" 
    elif errno == STRUC_ERROR_MEMBER_STRUCT:
        return "STRUC_ERROR_MEMBER_STRUCT: bad struct id (the 1st argument)" 
    elif errno == STRUC_ERROR_MEMBER_UNIVAR:
        return "STRUC_ERROR_MEMBER_UNIVAR: unions can't have variable sized members" 
    elif errno == STRUC_ERROR_MEMBER_VARLAST:
        return "STRUC_ERROR_MEMBER_VARLAST: variable sized member should be the last member in the structure" 

################################
#        Get Struct Type       #
################################

class RpcCallAttrStructType():
    def __init__(self, func_addr: int):
        self.func_addr = func_addr
        self.func = ida_funcs.get_func(self.func_addr)
        # RPC_CALL_ATTRIBUTES struct is initialized by the function RpcServerInqCallAttributesX <A/W>
        self.struct_init_func_name = ""
        self.struct_init_insn = self._get_struct_init_info()
    
    def uses_rpc_call_attrs_struct(self) -> bool:
        return self.struct_init_insn != None

    def _is_unicode_struct(self) -> bool: 
        if self.struct_init_func_name.endswith('W'):
            return True
        return False
        
    def _is_stack_buffer(self, addr: int, index: int) -> bool:
        inst = idautils.DecodeInstruction(addr)
        return ida_frame.get_stkvar(inst, inst[index], inst[index].addr) != None 
    
    def _get_struct_init_info(self) -> Optional[idaapi.insn_t]:
        for call in get_call_instructions(self.func_addr):	
            func_name = idc.get_name(idc.get_operand_value(call.ea, 0))
            if 'RpcServerInqCallAttributes' in func_name:
                    self.struct_init_func_name = func_name
                    return call
        return
    
    def _get_lea_insn(self) -> Optional[idaapi.insn_t]:
        if not self.struct_init_insn:
            return 

        # go backwards and locate the RpcCallAttribute that is passed to the function (passed in rdx) - locate the lea command into rdx   
        opnd = 'rdx'
        addr = self.struct_init_insn.ea
        while addr >= self.func_addr:
            addr = idc.prev_head(addr)
            op = idc.print_insn_mnem(addr).lower()    
            if op in ("ret", "retn", "jmp", "b") or addr < self.func_addr:
                break
            elif op == "lea" and idc.print_operand(addr, 0) == opnd:
                # We found the destination buffer, check to see if it is on the stack
                if self._is_stack_buffer(addr, 1):
                    insn = idaapi.insn_t()
                    idaapi.decode_insn(insn, addr)
                    return insn
        return 
    
    def _get_struct_version(self, lea_insn: idaapi.insn_t) -> Optional[int]:
        """
        Locate the value that is being passed to the version attribute of the RpcCallAttributes struct as mentioned in get_struct_type documentation.
        """
        addr = self.struct_init_insn.ea
        dst_opnd = idc.get_operand_value(lea_insn.ea, 1)
        while addr >= self.func_addr:
            addr = idc.prev_head(addr)
            op = idc.print_insn_mnem(addr).lower()    
            if op in ("ret", "retn", "jmp", "b") or addr < self.func_addr:
                break
            elif op == "mov":
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, addr)
                if idc.get_operand_value(insn.ea, 0) == dst_opnd:
                    if insn.Op2.is_imm(insn.Op2.value): 
                        version = idc.get_operand_value(insn.ea, 1)
                        if not (version >= 1 and version <= 3):
                            return 
                        return version
                    elif insn.Op2.is_reg(insn.Op2.reg):
                        print(idc.get_operand_value(insn.ea, 1))
                        dst_opnd = idc.get_operand_value(insn.ea, 1)
        return     
    
    def get_struct_type(self) -> str:
        """
        lea     rdx, [rbp-49h]  ; RpcCallAttributes
        mov     [rbp+57h+RpcCallAttributes], 3
        mov     rcx, rsi        ; ClientBinding
        call    cs:__imp_RpcServerInqCallAttributesW

        1. First locate the call instructionto RpcServerInqCallAttributesW / RpcServerInqCallAttributesA inside the security callback (and determine if we need to use the A or W version of the struct)
        2. Than go back to the lea instruction to find the address of RpcCallAttributes variable (passed in rdx to the RpcServerInqCallAttributes function)
        3. Iterate backwards on the instructions to extract the struct version number - 1 / 2 / 3
        """
        lea_insn = self._get_lea_insn()
        if not lea_insn:
            return ""
        struct_version = self._get_struct_version(lea_insn)
        if not struct_version:
            print("Error getting the struct version")
            return ""
        
        return "RPC_CALL_ATTRIBUTES_V%d_%s" % (struct_version, 'W' if self._is_unicode_struct() else 'A')

################################
#          Add Struct          #
################################

def define_uuid_st() -> int:
    uuid_sid = ida_struct.add_struc(idaapi.BADADDR, "UUID", 0)
    for member_name, (offset, mtype) in UUID_struct_members.items():
        type_inf = (mtype|idc.FF_DATA)&0xFFFFFFFF
        size = TYPES_TO_SIZES[mtype]
        idc.add_struc_member(uuid_sid, member_name, offset, type_inf, -1, size)
    return uuid_sid

def validate_struct_member(sid: int, member_stype: str) -> int:
    member_sid = idc.get_struc_id(member_stype)
    if idaapi.as_signed(sid) != -1: 
        if member_stype == "UUID":
            return define_uuid_st()
    return member_sid

def get_struct_members(name: str) -> Dict[str, Tuple]:
        if name in STRUCTS_MEMBERS.keys():
            return STRUCTS_MEMBERS[name]
        return {} 

def add_struct_members(sid: int, struct_members: Dict[str, Tuple]) -> bool:
    error_occured = False
    for member_name, (offset, mtype, mem_stype) in struct_members.items():
        type_inf = (mtype|idc.FF_DATA)&0xFFFFFFFF
        member_sid = validate_struct_member(sid, mem_stype) if mem_stype else -1 # should be the sid only if the member is a struct
        size = ida_struct.get_struc_size(member_sid) if mem_stype else TYPES_TO_SIZES[mtype]
        res = idc.add_struc_member(sid, member_name, offset, type_inf, member_sid, size)
        if res:
            print("There was an error adding struct member %s: %s" % (member_name, get_struc_err(res)))
            error_occured = True

    return error_occured 

def add_new_struct(name: str, force=False) -> bool:
    # Create the struct: 
    sid = ida_struct.get_struc_id(name)
    if idaapi.as_signed(sid) != -1: 
        print("Struct already exists")
        if not force:
            return True
        ida_struct.del_struc(ida_struct.get_struc(sid))
    sid = ida_struct.add_struc(idaapi.BADADDR, name, 0)
        
    # Add struct members:
    struct_members = get_struct_members(name)
    res = add_struct_members(sid, struct_members)

    # Save struct: 
    struct = ida_struct.get_struc(sid)
    ida_struct.save_struc(struct, True) 

    return not res

################################
#          Set Struct          #
################################

class RpcCallAttrFuncDecompiler:
    def __init__(self, func_addr: int, struct_name: str, lvar_name=RPC_CALL_ATTRS_LVAR_NAME):
        self.struct_name = struct_name
        self.func_addr = func_addr
        self.lvar_name = lvar_name
        self.typeinf = self._get_type_info()
        self.decompiled_func = idaapi.decompile(self.func_addr)
    
    def _get_type_info(self) -> idaapi.tinfo_t:
        type_info = idaapi.tinfo_t()
        type_info.get_named_type(idaapi.get_idati(), self.struct_name)
        return type_info
    
    def _set_lvar_type(self, lvar: ida_hexrays.lvar_t) -> bool:
        lvar_saved_info = ida_hexrays.lvar_saved_info_t()
        lvar_saved_info.ll = lvar
        lvar_saved_info.type = ida_typeinf.tinfo_t(self.typeinf)
        if not ida_hexrays.modify_user_lvar_info(self.func_addr, ida_hexrays.MLI_TYPE, lvar_saved_info):
            print("Could not modify lvar type for lvar %s" % lvar.name)
            return False
        return True
    
    def apply_struct(self) -> bool:
        for lvar in self.decompiled_func.lvars:
            if lvar.name == self.lvar_name:
                if self._set_lvar_type(lvar):
                    self.decompiled_func.refresh_func_ctext()
                    self.decompiled_func = idaapi.decompile(self.func_addr) # Needs to recompile the function again to apply the changes
                    return True
        print("Couldn't locate local var %s in the function" % self.lvar_name)
        return False
    
    def get_decompiled_func(self) -> ida_hexrays.cfuncptr_t:
        return self.decompiled_func


def apply_rpc_call_attrs_struct(func_addr: int, struct_name: str) -> Optional[ida_hexrays.cfuncptr_t]:
    # Add struct to local types
    if not add_new_struct(struct_name):
        return

    # Apply struct on RPC_CALL_ATTRIBUTES_V<>_<> struct inside the Security Callback:
    set_struct = RpcCallAttrFuncDecompiler(func_addr, struct_name)
    if not set_struct.apply_struct():
        return 

    return set_struct.get_decompiled_func()
