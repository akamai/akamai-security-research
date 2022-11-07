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

from rpc_registration_lookup.base_rpc_registration_scraper import BaseRpcRegistrationExtractor, DismExtractorFailue

from typing import Dict, List
import subprocess
import json
import os

SCRIPT_PATH = os.path.join(os.path.split(__file__)[0], "dism_scripts", "ida_python.py")
TEMP_OUTPUT_FILE = "ida_pro_rpc_reg_info.tmp"


class IdaDBOpenException(Exception):
    def __init__(self, pe_path: str) -> None:
        super().__init__(f"Running IDA dism failed, return code 4. Please close the IDA instance open for the file and retry. PE path: {pe_path}")


class IdaProRpcRegistrationExtractor(BaseRpcRegistrationExtractor):
    _default_dism_path = "C:\\Program Files\\IDA Pro 7.6\\idat64.exe"

    def _get_rpc_registration_info(self, pe_path: str) -> Dict[str, Dict[str, List]]:
        p = subprocess.run(
            [self._dism_path, f"-S{SCRIPT_PATH}", "-A", pe_path, "-t"],
            stdout=subprocess.PIPE
        )
        if p.returncode != 0:
            if p.returncode == 4:
                raise IdaDBOpenException(pe_path)
            raise DismExtractorFailue(p.returncode)

        with open(TEMP_OUTPUT_FILE, "rt") as f:
            reg_info = json.load(f)
        os.remove(TEMP_OUTPUT_FILE)

        return reg_info
