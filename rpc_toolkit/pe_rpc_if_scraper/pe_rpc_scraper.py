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

from rpc_registration_lookup.base_rpc_registration_scraper import BaseRpcRegistrationExtractor
from rpc_registration_lookup import disassemblers, rpc_registration_scraper_factory
from pe_rpc_if_analysis import PeRpcInterfaceScraper
from scraper_exceptions import *

from typing import Dict, Optional
import argparse
import json
import os

OUTPUT_FILENAME = "rpc_interfaces.json"


def scrape_folder(folder_path: str, disassembler: Optional[BaseRpcRegistrationExtractor] = None) -> Dict[str, Dict]:
    output_dict = {}
    interface_scraper = PeRpcInterfaceScraper(disassembler)
    for filename in os.listdir(folder_path):
        if not (filename.lower().endswith('dll') or filename.lower().endswith('exe')):
            continue
        pe_path = os.path.join(folder_path, filename)
        try:
            print(filename)
            output_dict[filename] = interface_scraper.scrape_executable(pe_path)
        except (NoRpcImportException, CantDetermineRpcSideException, DotNetPeException, CantFindRDataSectionException) as e:
            pass
    return output_dict


def scrape_file(file_path: str, disassembler: Optional[BaseRpcRegistrationExtractor]  = None) -> Dict[str, Dict]:
    interface_scraper = PeRpcInterfaceScraper(disassembler)
    return {os.path.split(file_path)[1]: interface_scraper.scrape_executable(file_path)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scrape_path", help="path we wish to scrape, could be file or folder", type=str)
    parser.add_argument("--output_path", help="path for json output file", default=OUTPUT_FILENAME, type=str)
    parser.add_argument(
        "-r",
        help="parse recursively, will only work on folder paths (obviously)",
        dest="should_recurse", action='store_true', default=False
    )
    parser.add_argument(
        "-d",
        help="Disassembler to use for rpc registration info extraction",
        dest="disassembler",
        choices=disassemblers,
        default=None
    )
    parser.add_argument(
        "-P",
        help="Disassembler executable path",
        dest="disassembler_path",
        default=None
    )
    args = parser.parse_args()
    dism = rpc_registration_scraper_factory(args.disassembler)(args.disassembler_path) if args.disassembler else None
    if args.should_recurse:
        output = dict()
        for root, _, _ in os.walk(args.scrape_path):
            output.update(scrape_folder(root, dism))
    else:
        if os.path.isdir(args.scrape_path):
            output = scrape_folder(args.scrape_path, dism)
        else:
            output = scrape_file(args.scrape_path, dism)

    with open(args.output_path, 'wt', newline='\n') as out:
        json.dump(output, out)
