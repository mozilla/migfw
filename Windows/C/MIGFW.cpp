/********************************************************************
Copyright (C) Microsoft. All Rights Reserved.

Abstract:
    This C++ file includes code for enumerating Windows Firewall
    rules using the Microsoft Windows Firewall APIs. This code will
	be used in a Go library using CGO.

********************************************************************/

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <comutil.h>
#include <atlcomcli.h>
#include <netfw.h>
#include <string>
#include <iostream>
#include <vector>
using namespace std;

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

// Structure to hold all information about firewall rules
struct rules {
	BSTR Name;
	BSTR Description;
	BSTR ApplicationName;
	BSTR LocalPorts;
	BSTR RemotePorts;
	BSTR LocalAddress;
	BSTR RemoteAddress;
	BSTR Direction;
	BSTR Action;
	BSTR InterfaceType;
	BSTR Protocol;

	BSTR ICMP_Typecode;
	long Lval;
};

// Declarations for global variables
HRESULT hrComInit = S_OK;
HRESULT hr = S_OK;

ULONG cFetched = 0; 
CComVariant var;


IUnknown *pEnumerator;
IEnumVARIANT* pVariant = NULL;

INetFwPolicy2 *pNetFwPolicy2 = NULL;
INetFwRules *pFwRules = NULL;
INetFwRule *pFwRule = NULL;

long fwRuleCount;

// Forward declarations for global functions
void        DumpFWRulesInCollection(INetFwRule* FwRule);
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);
void		cleanUp();
bool		init();
rules		GetRules(INetFwRule* FwRule);

/**
 * Function to retrieve the the firewall rules, and update global variables
 * @param: void
 * @return: bool - true for successful init else false;
 */
bool init() {
	// Initialize COM.
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );

    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
    // initialized with a different mode. Since we don't care what the mode is,
    // we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE)
    {
        if (FAILED(hrComInit))
        {
            wprintf(L"CoInitializeEx failed: 0x%08lx\n", hrComInit);
            cleanUp();
			return false;
        }
    }

    // Retrieve INetFwPolicy2
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr))
    {
		cleanUp();
		return false;
    }

    // Retrieve INetFwRules
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr))
    {
        wprintf(L"get_Rules failed: 0x%08lx\n", hr);
        cleanUp();
		return false;
    }

    // Obtain the number of Firewall rules
    hr = pFwRules->get_Count(&fwRuleCount);
    if (FAILED(hr))
    {
        wprintf(L"get_Count failed: 0x%08lx\n", hr);
		cleanUp();
		return false;
    }
    
    // Iterate through all of the rules in pFwRules
	pFwRules->get__NewEnum(&pEnumerator);

    if(pEnumerator)
    {
        hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void **) &pVariant);
    }
	return true;
}

void cleanUp() {
	// Release pFwRule
    if (pFwRule != NULL)
    {
        pFwRule->Release();
    }

    // Release INetFwPolicy2
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
    {
        CoUninitialize();
    }
}

// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
    HRESULT hr = S_OK;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2), 
        NULL, 
        CLSCTX_INPROC_SERVER, 
        __uuidof(INetFwPolicy2), 
        (void**)ppNetFwPolicy2);

    if (FAILED(hr))
    {
        wprintf(L"CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;        
    }

Cleanup:
    return hr;
}

/*
 * Function to getFirewall rules by matching ip string
 */
vector <rules> GetRulesByIP(std::string ip) {
	vector <rules> r;

	// Initialize COM and ...
	// Retrieve all firewall rules to pfrules object (global)
	if (!init()) {
		// initialize failed
		// return an empty vector
		return r;
	}

	// Convert the char * ip to BSTR for match
	std::wstring ws;
	ws.assign(ip.begin(), ip.end());
	BSTR ipString = SysAllocStringLen(ws.data(), ws.size());

	BSTR localAddress;

	while(SUCCEEDED(hr) && hr != S_FALSE)
    {
        var.Clear();
        hr = pVariant->Next(1, &var, &cFetched);

        if (S_FALSE != hr)
        {
            if (SUCCEEDED(hr))
            {
                hr = var.ChangeType(VT_DISPATCH);
            }
            if (SUCCEEDED(hr))
            {
                hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
            }

            if (SUCCEEDED(hr))
            {
                // Output the properties of this rule
				pFwRule->get_LocalAddresses(&localAddress);
				
				// Match the given ip string with current ip
				// @todo - convert the ip in argument to a structure such that you
				// do a int based comparision, and devise a method for ip range search as well
				if (wcsstr(localAddress, ipString) != NULL) {
					r.push_back(GetRules(pFwRule));
				}
				
            }
        }
    }
	cleanUp();

	return r;
}

rules GetRules(INetFwRule* FwRule) {
		rules ret;
		if (!SUCCEEDED(FwRule->get_Name(&ret.Name))) {
			// @todo - do something
		}

		if (!SUCCEEDED(FwRule->get_Description(&ret.Description)))
		{
			// @todo - do something
		}

		if (!SUCCEEDED(FwRule->get_ApplicationName(&ret.ApplicationName)))
		{
			// @todo - do something
		}

		if (!SUCCEEDED(FwRule->get_LocalAddresses(&ret.LocalAddress)))
		{
			// @todo - do something
		}

		if (!SUCCEEDED(FwRule->get_RemoteAddresses(&ret.RemoteAddress)))
		{
			// @todo - do something
		}

		if (SUCCEEDED(FwRule->get_Protocol(&ret.Lval)))
		{
			switch(ret.Lval)
			{
				case NET_FW_IP_PROTOCOL_TCP: 

					ret.Protocol =  NET_FW_IP_PROTOCOL_TCP_NAME;
					break;

				case NET_FW_IP_PROTOCOL_UDP: 

					ret.Protocol = NET_FW_IP_PROTOCOL_UDP_NAME;
					break;

				default:
					ret.Protocol = L"Undefined";
					break;
			}

			if(ret.Lval != NET_FW_IP_VERSION_V4 && ret.Lval != NET_FW_IP_VERSION_V6)
			{
				if (!SUCCEEDED(FwRule->get_LocalPorts(&ret.LocalPorts)))
				{
					// @todo - do something
				}

				if (!SUCCEEDED(FwRule->get_RemotePorts(&ret.RemotePorts)))
				{
					// @todo - do something
				}
			}
			else
			{
				if (!SUCCEEDED(FwRule->get_IcmpTypesAndCodes(&ret.ICMP_Typecode)))
				{
					// @todo - do something
				}
			}
		}

		NET_FW_RULE_DIRECTION fwDirection;
		NET_FW_ACTION fwAction;

		if (SUCCEEDED(FwRule->get_Direction(&fwDirection)))
		{
			switch(fwDirection)
			{
			case NET_FW_RULE_DIR_IN:
				ret.Direction = NET_FW_RULE_DIR_IN_NAME;
				break;
			case NET_FW_RULE_DIR_OUT:
				ret.Direction = NET_FW_RULE_DIR_OUT_NAME;
				break;
			default:
				break;
			}
		}

		if (SUCCEEDED(FwRule->get_Action(&fwAction)))
		{
			switch(fwAction)
			{
			case NET_FW_ACTION_BLOCK:
				ret.Action = NET_FW_RULE_ACTION_BLOCK_NAME;
				break;
			case NET_FW_ACTION_ALLOW:
				ret.Action = NET_FW_RULE_ACTION_ALLOW_NAME;
				break;
			default:
				break;
			}
		}
		return ret;
}




// ----------------------------------------------------
// Temporary function for current debugging purposes
// Alter when this code will be served as library

// Function to print the properties of rules structure passed
// as an argument, to console
void DumpRule(rules r) {
	wprintf(L" -------------------------------------------\n ");
	wprintf(L" Name: %s\n ", r.Name);
	wprintf(L" Description: %s\n ", r.Description);
	
	wprintf(L" Application Name: %s\n ", r.ApplicationName);
	wprintf(L" local address: %s\n ", r.LocalAddress);
	wprintf(L" remote address: %s\n ", r.RemoteAddress);
	wprintf(L" IP Protocol: %s\n ", r.Protocol);
	
	if(r.Lval != NET_FW_IP_VERSION_V4 && r.Lval != NET_FW_IP_VERSION_V6) {
		wprintf(L" remote ports: %s\n ", r.RemotePorts);
		wprintf(L" local ports: %s\n ", r.LocalPorts);
    } else wprintf(L" ICMP TypeCode: %s\n ", r.ICMP_Typecode);

	wprintf(L" Direction: %s\n ", r.Direction);
	wprintf(L" Action: %s\n ", r.Action);
}

void printMatchingRules(std::string s) {
	vector <rules> r = GetRulesByIP(s);

	wprintf(L" No of matching rules: %d \n", r.size());
	;
	for(int i = 0; i < r.size(); i++) {
		DumpRule(r[i]);
	}
}

int __cdecl main()
{

	wprintf(L"Enter IP address you want to find rule for");
	std::string s;
	std::cin>>s;
	std::cout<<"Attempting for "<<s<<"\n";

	printMatchingRules(s);

	getchar();
	getchar();
    return 0;
}

