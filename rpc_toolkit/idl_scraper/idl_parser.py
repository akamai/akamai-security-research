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

from typing import Iterator, Tuple, List
import pandas as pd
import argparse
import os
import re

_OUTPUT_FILENAME = 'idl_functions.csv'
_typedefs = {}


def get_interfaces(idl_content):
    # Returns an iterator of regex matches where:
    # First group is the interface name;
    # Second group is the interface block content
    return re.finditer('(?:interface|coclass)\s([\w\s:]+){(.*?)};?\s*$', idl_content, flags=re.DOTALL | re.MULTILINE)


def get_interface_name(interface_name_raw):
    return interface_name_raw.split(':')[0].strip()


def get_interface_uuid(content_block: str) -> str:
    return next(
        re.finditer("([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", content_block)
    ).group(0)


def get_functions(idl_content):
    return re.finditer('(\w+)\s+(\w+)(?:\n\s+)?\((.*?)\);', idl_content, flags=re.DOTALL)


def drop_compilation_attributes(declaration_str: str) -> str:
    return re.sub('\[.+?\] ', '', declaration_str)


def get_typedefs(idl_name: str, idl_content: str) -> None:
    if idl_name in _typedefs:
        return
    else:
        _typedefs[idl_name] = {}
    for typedef in re.findall('typedef (.+);', idl_content):
        typedef = drop_compilation_attributes(typedef)
        name_ind = typedef.rfind(' ')
        _typedefs[idl_name][typedef[name_ind+1:]] = typedef[:name_ind]


def get_import_typedefs(idl_folder: str, imports: List[str]) -> None:
    for idl_name in imports:
        if idl_name in _typedefs:
            continue
        idl_path = os.path.join(idl_folder, idl_name)
        if not os.path.exists(idl_path):
            print(f"Can't find idl import {idl_name}")
            continue
        with open(idl_path, 'rt') as f:
            get_typedefs(idl_name, f.read())


def parse_function_parameters(parameters: str, idl_deps: List[str]) -> Iterator[Tuple[str]]:
    parameters = parameters.strip()
    if not parameters or parameters.lower() == 'void':
        return
    clean_params = drop_compilation_attributes(parameters)  # Drop the direction attributes that drop in compilation
    for param in clean_params.split(','):
        param = param.strip()
        if '\n' in param:
            for mparam in param.split('\n'):
                name_ind = mparam.rfind(' ')
                yield mparam[:name_ind].strip(), mparam[name_ind + 1:].strip()
        else:
            name_ind = param.rfind(' ')
            yield param[:name_ind].strip(), param[name_ind+1:].strip()


def parse_idl(idl_folder: str, idl_name: str) -> pd.DataFrame:
    idl_df = pd.DataFrame(
        columns=['idl_name', 'interface_uuid', 'interface_name', 'function_return_type', 'function_name', 'function_params'],
        dtype=object)
    with open(os.path.join(idl_folder, idl_name), 'rt') as fp:
        content = fp.read()
    interfaces = get_interfaces(content)
    start = 0
    for interface in interfaces:
        interface_uuid = get_interface_uuid(content[start:interface.start()])
        func_count = 0
        start = interface.start()
        ifc_decl, ifc_block = interface.groups()
        functions = get_functions(ifc_block)
        for func in functions:
            func_count += 1
            ret_type, func_name, func_params = func.groups()
            if ret_type == "define":
                continue
            row = {'idl_name': idl_name.replace('.idl', ''),
                   'interface_uuid': interface_uuid,
                   'interface_name': get_interface_name(ifc_decl),
                   'function_name': func_name,
                   'function_return_type': ret_type,
                   'function_params': list(parse_function_parameters(func_params, []))
                   }
            idl_df = idl_df.append(row, ignore_index=True)
        if not func_count:
            idl_df = idl_df.append(
                {
                    'idl_name': idl_name.replace('.idl', ''),
                    'interface_uuid': interface_uuid,
                    'interface_name': get_interface_name(ifc_decl),
                    'function_name': None,
                    'function_return_type': None,
                    'function_params': None
                },
                ignore_index=True
            )
    return idl_df


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_path", help="folder or file we wish to parse", type=str)
    parser.add_argument("output_path", help="path for csv output file", default=_OUTPUT_FILENAME, type=str, nargs='?')
    parser.add_argument("-r", help="parse recursively", dest="should_recurse", action='store_true', default=False)
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    if os.path.isfile(args.input_path):
        folder, name = os.path.split(args.input_path)
        output = parse_idl(folder, name)
    elif args.should_recurse:
        output = pd.concat([parse_idl(root, f) for root, _, files in os.walk(args.input_path) for f in files])
    else:
        output = pd.concat([parse_idl(args.input_path, f) for f in os.listdir(args.input_path)])
    output.to_csv(args.output_path, index=False)
