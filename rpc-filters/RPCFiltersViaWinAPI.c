/* RPC Filters
 * Copyright 2022 Akamai Technologies, Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy
 * of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <Windows.h>
#include <fwpmu.h>
#include <sddl.h>
#include <rpc.h>
#include <stdio.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

void AddInterfaceFilter(HANDLE engineHandle, TCHAR* interfaceString, GUID layerkey)
{
	FWPM_FILTER0			fwpFilter;
	DWORD					result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0	fwpCondition;
	UUID					interfaceUUID;

	UuidFromString(interfaceString, &interfaceUUID);

	ZeroMemory(&fwpCondition, sizeof(fwpCondition));
	fwpCondition.matchType = FWP_MATCH_EQUAL;
	fwpCondition.fieldKey = FWPM_CONDITION_RPC_IF_UUID;
	fwpCondition.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
	fwpCondition.conditionValue.byteArray16 = &interfaceUUID;

	ZeroMemory(&fwpFilter, sizeof(fwpFilter));
	fwpFilter.layerKey = layerkey;
	fwpFilter.action.type = FWP_ACTION_BLOCK;
	fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
	fwpFilter.numFilterConditions = 1;
	fwpFilter.displayData.name = L"RPC filter block interface";
	fwpFilter.displayData.description = L"Filter to block all inbound connections to the rpc interface";
	fwpFilter.filterCondition = &fwpCondition;

	fwpFilter.subLayerKey = FWPM_SUBLAYER_RPC_AUDIT;
	fwpFilter.rawContext = 1; // needed for auditing to work, IDK why!

	printf("Adding filter\n");
	result = FwpmFilterAdd(engineHandle, &fwpFilter, NULL, NULL);

	if (result != ERROR_SUCCESS)
		printf("FwpmFilterAdd0 failed. Return value: %x.\n", result);
	else
		printf("Filter added successfully.\n");
}

void AddIPv4Filter(HANDLE engineHandle, CHAR* remoteIP, GUID layerkey)
{
	FWPM_FILTER0			fwpFilter;
	DWORD					result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0	fwpCondition;
	UINT32					ipv4;

	inet_pton(AF_INET, remoteIP, &ipv4);

	ZeroMemory(&fwpCondition, sizeof(fwpCondition));
	fwpCondition.matchType = FWP_MATCH_EQUAL;
	fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V4;
	fwpCondition.conditionValue.type = FWP_UINT32;
	fwpCondition.conditionValue.uint32 = ipv4;

	ZeroMemory(&fwpFilter, sizeof(fwpFilter));
	fwpFilter.layerKey = layerkey;
	fwpFilter.action.type = FWP_ACTION_BLOCK;
	fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
	fwpFilter.numFilterConditions = 1;
	fwpFilter.displayData.name = L"RPC filter block ip";
	fwpFilter.displayData.description = L"Filter to block all inbound connections from an ip";
	fwpFilter.filterCondition = &fwpCondition;

	fwpFilter.subLayerKey = FWPM_SUBLAYER_RPC_AUDIT;
	fwpFilter.rawContext = 1; // needed for auditing to work, IDK why!

	printf("Adding filter\n");
	result = FwpmFilterAdd0(engineHandle, &fwpFilter, NULL, NULL);

	if (result != ERROR_SUCCESS)
		printf("FwpmFilterAdd0 failed. Return value: %x.\n", result);
	else
		printf("Filter added successfully.\n");
}

void AddSidFilter(HANDLE engineHandle, CHAR* sidStr, GUID layerkey)
{
	FWPM_FILTER0			fwpFilter;
	DWORD					result = ERROR_SUCCESS;
	FWPM_FILTER_CONDITION0	fwpCondition;
	FWP_TOKEN_INFORMATION	tokenInfo;
	SID						sid;
	SID_AND_ATTRIBUTES		sidAttr;

	result = ConvertStringSidToSidA(sidStr, &sid);
	if (!result)
		printf("ConvertStringSidToSidA failed. Return value: %x.\n", GetLastError());
	else
		printf("ConvertStringSidToSidA successfully.\n");
	sidAttr.Sid = &sid;
	sidAttr.Attributes = 0;
	tokenInfo.restrictedSidCount = 0;
	tokenInfo.restrictedSids = NULL;
	tokenInfo.sidCount = 1;
	tokenInfo.sids = &sidAttr;

	ZeroMemory(&fwpCondition, sizeof(fwpCondition));
	fwpCondition.matchType = FWP_MATCH_EQUAL;
	fwpCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS_V4;
	fwpCondition.conditionValue.type = FWP_TOKEN_INFORMATION_TYPE;
	fwpCondition.conditionValue.tokenInformation = &tokenInfo;

	ZeroMemory(&fwpFilter, sizeof(fwpFilter));
	fwpFilter.layerKey = layerkey;
	fwpFilter.action.type = FWP_ACTION_BLOCK;
	fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
	fwpFilter.numFilterConditions = 1;
	fwpFilter.displayData.name = L"RPC filter block user token";
	fwpFilter.displayData.description = L"Filter to block all inbound connections from a user token";
	fwpFilter.filterCondition = &fwpCondition;

	fwpFilter.subLayerKey = FWPM_SUBLAYER_RPC_AUDIT;
	fwpFilter.rawContext = 1; // needed for auditing to work, IDK why!

	printf("Adding filter\n");
	result = FwpmFilterAdd0(engineHandle, &fwpFilter, NULL, NULL);

	if (result != ERROR_SUCCESS)
		printf("FwpmFilterAdd0 failed. Return value: %x.\n", result);
	else
		printf("Filter added successfully.\n");
}

int main()
{
	FWPM_SESSION0	session;
	HANDLE			engineHandle = NULL;
	DWORD			result	= ERROR_SUCCESS;
	TCHAR			sessionKey[39];

	ZeroMemory(&session, sizeof(session));
	session.kernelMode = FALSE;
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	
	printf("opening filter engine\n");
	result = FwpmEngineOpen0(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&engineHandle);

	if (result != ERROR_SUCCESS)
		printf("FwpmEngineOpen0 failed. Return value: %x", result);
	else
	{
		StringFromGUID2(&session.sessionKey, sessionKey, sizeof(sessionKey));
		wprintf(L"Filter engine opened successfully. session key: %s\n", sessionKey);
	}

	AddInterfaceFilter(engineHandle, L"f6beaff7-1e19-4fbb-9f8f-b89e2018337c", FWPM_LAYER_RPC_UM); //win-evt
	//AddInterfaceFilter(engineHandle, L"338CD001-2244-31F1-AAAA-900038001003", FWPM_LAYER_RPC_UM); //win-reg
	//AddInterfaceFilter(engineHandle, L"367ABB81-9844-35F1-AD32-98F038001003", FWPM_LAYER_RPC_UM); //scmr
	//AddIPv4Filter(engineHandle, "172.17.0.61", FWPM_LAYER_RPC_UM);
	//AddSidFilter(engineHandle, "BA", FWPM_LAYER_RPC_UM);
	system("pause");
	FwpmEngineClose0(engineHandle);
	return 0;
}
