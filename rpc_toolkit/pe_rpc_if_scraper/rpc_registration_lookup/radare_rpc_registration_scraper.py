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

SCRIPT_PATH = os.path.join(os.path.split(__file__)[0], "dism_scripts", "radare2.py")
TEMP_OUTPUT_FILE = "radare2_rpc_reg_info.tmp"


class Radare2RpcRegistrationExtractor(BaseRpcRegistrationExtractor):
    _default_dism_path: str = "r2"

    def _get_rpc_registration_info(self, pe_path: str) -> Dict[str, Dict[str, List]]:
        p = subprocess.run(
            [self._dism_path, "-q", "-i", SCRIPT_PATH, pe_path],
            stdout=subprocess.PIPE
        )
        if p.returncode != 0:
            raise DismExtractorFailue(p.returncode)

        with open(TEMP_OUTPUT_FILE, "rt") as f:
            reg_info = json.load(f)
        os.remove(TEMP_OUTPUT_FILE)

        return reg_info
