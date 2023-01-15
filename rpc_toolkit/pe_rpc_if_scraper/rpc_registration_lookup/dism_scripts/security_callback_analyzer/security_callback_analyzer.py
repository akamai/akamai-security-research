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

import ida_hexrays
import idaapi
import ida_struct

import json

from collections import defaultdict
from security_callback_analyzer.helper_funcs import get_imported_func_name
from security_callback_analyzer.rpc_call_attributes_struct import RpcCallAttrStructType, apply_rpc_call_attrs_struct

from typing import List, Tuple, Dict, Optional

class SecurityCallbackAnalyzer(ida_hexrays.ctree_visitor_t):
    """
    This class is an extension for the ida_hexrays.ctree_visitor_t class. 
    It implements the virtual functions of visit_insn and visit_expr. 
    When calling the apply_to() function of this class to apply it on a decompiled function, it will run visit_insn for every instruction item and visit_expr for every expression item. 
    More documentation can be found here: 
    https://hex-rays.com/products/decompiler/manual/sdk/structctree__visitor__t.shtml
    """
    def __init__(self, struct_type):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)
        self.mapping = defaultdict(list)
        self.struct_type = struct_type
        self.security_callback_info = []
    
    @staticmethod
    def is_op_signed(expr: ida_hexrays.cexpr_t) -> str:
        if expr.op in [idaapi.cot_asgsshr, idaapi.cot_asgsdiv, idaapi.cot_asgsmod, idaapi.cot_sge, idaapi.cot_sle, idaapi.cot_sgt, idaapi.cot_slt, idaapi.cot_sshr, idaapi.cot_sdiv, idaapi.cot_smod]:
            return "Signed"
        elif expr.op in [idaapi.cot_asgushr, idaapi.cot_asgudiv, idaapi.cot_asgumod, idaapi.cot_uge, idaapi.cot_ule, idaapi.cot_ugt, idaapi.cot_ult, idaapi.cot_ushr, idaapi.cot_udiv, idaapi.cot_umod]:
            return "Unsigned"
        return "-"

    @staticmethod
    def get_if_type(expr: ida_hexrays.cexpr_t) -> str: 
        op_to_arithmeric_sign = {idaapi.cot_ne: "!=", idaapi.cot_eq: "==", idaapi.cot_memref: "==",
                                idaapi.cot_call: "call", idaapi.cot_sge: ">=", idaapi.cot_uge: ">=",
                                idaapi.cot_sle: "<=", idaapi.cot_ule: "<=", idaapi.cot_sgt: ">", 
                                idaapi.cot_ugt: ">", idaapi.cot_slt: "<", idaapi.cot_ult: "<", 
                                idaapi.cot_sub: "-", idaapi.cot_add: "+"}

        if expr.op in op_to_arithmeric_sign.keys():
            return op_to_arithmeric_sign[expr.op]
        return "Unsupported condition type (%s)" % expr.opname
           
    def _get_member_name_by_offset(self, offset: int) -> str:
        sid = ida_struct.get_struc_id(self.struct_type)
        st = ida_struct.get_struc(sid)
        mid = ida_struct.get_member_id(st, offset)
        return ida_struct.get_member_fullname(mid)

    def _get_member_name_by_memref(self, expr: ida_hexrays.cexpr_t) -> Optional[str]:
        if expr.opname == "memref" or expr.opname == "ref":
           if expr.x.opname == "var" and expr.x.type.get_type_name() == self.struct_type:
                if expr.m:
                    return self._get_member_name_by_offset(expr.m)
                elif expr.x.v:
                    return expr.x.v.getv().name
        return None
    
    def _parse_memref(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        """ 
        Handle if from type: "if (Struct.member) {...}" 
        """
        member_name = self._get_member_name_by_memref(expr)
        condition_type = self.get_if_type(expr)
        return [(member_name, "True", True, condition_type, self.is_op_signed(expr))]
    
    def _parse_comparison(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        """
        Handle comparison if
        """ 
        member_name = ""
        has_comp_var = False
        comp_var = 0
        condition_type = self.get_if_type(expr)
        signness = self.is_op_signed(expr)
        for op in expr.operands.values():
                if type(op) != ida_hexrays.cexpr_t and type(op) != int:
                    continue
                if type(op) != int and op.opname == "memref":
                    member_name = self._get_member_name_by_memref(op)
                elif type(op) == int:
                    comp_var = op
                    has_comp_var = True
                elif op.opname == "num":
                    if op.n and op.n.value(op.type):
                        comp_var = op.n.value(op.type)
                        has_comp_var = True
                elif op.opname == "cast":
                    if op.x.opname == "num":
                        if op.x.n and op.x.n.value(op.x.type):
                            comp_var = op.x.n.value(op.x.type)
                            has_comp_var = True
                    elif op.x.opname in ["sub", "add"]:
                        _member_name, _comp_var, _, _condition_type, _ = self._parse_comparison(op.x)[0]
                        member_name = "%s %s %s" % (_member_name, _condition_type, _comp_var)
        
        return [(member_name, comp_var, has_comp_var, condition_type, signness)]
    
    def _parse_call(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        member_name = ""
        func_name = "" 
        if expr.x.opname == "helper":
            func_name = expr.x.helper
        elif expr.x.opname == "obj": 
            func_name = get_imported_func_name(expr.x.obj_ea) 
        
        args = expr.a
        for arg in args:
            if arg and (arg.opname == "memref" or arg.opname == "ref"):
                member_name = self._get_member_name_by_memref(arg)
            elif arg.x and (arg.x.opname == "memref" or arg.x.opname == "ref"):
                member_name = self._get_member_name_by_memref(arg.x)

        print("%s %s %s" % (member_name, func_name, "used in function"))
        return [(member_name, func_name, False, "used in function", "-")]
    
    def _parse_not(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        if expr.x.opname == "memref":
            member_name, comp_var, has_comp_var, condition_type, signness = self._parse_memref(expr.x)[0]
            not_cond_expr = ida_hexrays.lnot(ida_hexrays.cexpr_t(expr))
            condition_type = self.get_if_type(not_cond_expr)
            return [(member_name, comp_var, has_comp_var, condition_type, signness)]
        
        if expr.x.opname == "var":
            return [(None, None, None, None, None)]
        
        return [(None, None, None, None, None)]
    
    def _parse_complex_if(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        """
        Handle if from type: 
        ( RpcCallAttributes.ProtocolSequence != 3
        || RpcCallAttributes.NullSession
        || RpcCallAttributes.AuthenticationLevel != 6
        || RpcCallAttributes.AuthenticationService != 0xA )
        """   
        res = []
        ops = expr.operands.values()
        for op in ops:
            res += self._parse_if_expr(op)
        return res

    def _parse_if_expr(self, expr: ida_hexrays.cexpr_t) -> List[Tuple]:
        if expr.opname == "memref":
            return self._parse_memref(expr)
        elif expr.opname in ["land", "lor"]:
            return self._parse_complex_if(expr)
        elif expr.opname == "lnot":
            return self._parse_not(expr)
        elif expr.opname in ["eq", "ne", "sge", "uge", "sle", "ule", "sgt", "ugt", "slt" ,"ult"]:
            return self._parse_comparison(expr)
        elif expr.opname == "call":
            return self._parse_call(expr)
        return []
        
    def visit_insn(self, insn: idaapi.insn_t) -> int:
        """
        When calling to apply_to() function, this function will be called for every instruction item.
        The function should return 0 if there was no error.
        """
        if ( insn.op != idaapi.cit_if ):
            return 0 
        if not insn.cif.expr:
            return 0

        res = self._parse_if_expr(insn.cif.expr)
        for member_name, comp_var, has_comp_var, condition_type, signness in res:
            if (member_name and has_comp_var) or (member_name and not has_comp_var and condition_type == "used in function"):
                self.security_callback_info.append({'struct_attribute_name': member_name, 'compared_to': comp_var, 'condition_type': condition_type, 'signness': signness})
        return 0
        
    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int: 
        """
        When calling to apply_to() function, this function will be called for every expression item
        The function should return 0 if there was no error.
        """
        return 0
    
    def pprint(self) -> None:
        for member_name, comp_var, has_comp_var, condition_type, signness in self.res:
            if member_name and has_comp_var:
                print("The function checks if the attribute %s is %s (%s) to %s" % (member_name, condition_type, signness, str(comp_var)))
            if member_name and not has_comp_var and condition_type == "used in function":
                print("The function calls the function %s with the attribute %s" % (str(comp_var), member_name))



################################
#         Execute Code         #
################################

def analyze_security_callback(func_addr: int) -> List[Dict[str, any]]:
    stype = RpcCallAttrStructType(func_addr)
    if not stype.uses_rpc_call_attrs_struct():
        return {} 

    struct_type = stype.get_struct_type()
    if not struct_type:
        return {}

    cfunc = apply_rpc_call_attrs_struct(func_addr, struct_type)
    if not cfunc:
        return {}
    
    fa = SecurityCallbackAnalyzer(struct_type)
    fa.apply_to(cfunc.body, None) # Traverse ctree.

    return fa.security_callback_info
