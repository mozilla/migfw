#include "stdafx.h"
#include "migfw.h"
using namespace std;

// Declarations for global variables
HRESULT hrComInit = S_OK;
HRESULT hr = S_OK;
ULONG cFetched = 0; 
CComVariant var;

INetFwPolicy2 *pNetFwPolicy2 = NULL;
INetFwRules *pFwRules = NULL;
INetFwRule *pFwRule = NULL;

IUnknown *pEnumerator;
IEnumVARIANT* pVariant = NULL;

long fwRuleCount;

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

/**
 * Function to clean the object created for retrieving firewall rules
 * @param: void
 * @return: void
 */
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

/**
 * Function to Instantiate INetFwPolicy2
 * @param: INetFwPolicy2** ppNetFwPolicy2, reference to ptr to INetFwPolicy2 object
 * @return: HRESULT status
 */
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

/**
 * Function to read firewallRules one by one and return
 *  a vector of rules that matches the rules
 * @param: 
 */
vector <rules> GetRulesByFilter(std::string ip) {
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


/**
 * Function to read firewallRules one by one and return
 *  a vector of rules that matches the rules
 * @param: mask (int) - each bit represent which all filter
 *		conditions are active, ex 0010110, means those with one need to be checked.
 *		bit-0: Name, bit-1: local Address, bit-2: remote addr, bit-3: local port
 *		bit-4: remote port, bit-5: protocol, bit-6: direction, bit-7: Action
 *		mask = 0, means no filter rules, enumerate all rules
 * @param: string Name - substring of the firewall rule
 */
vector <rules> GetRulesByFilter(int mask, std::string ip) {
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
				// Get the information about this rule
				rules rule = GetRules(pFwRule);

				if ((mask & 1) != 0) {
					// Means bit - 0 is set, need to check for name
				}

				if ((mask & 2) != 0) {
					// means bit - 1 is set need to check for local Address 
				}

				if ((mask & 4) != 0) {
					// means bit - 2 is set need to check for remote Address 
				}

				if ((mask & 8) != 0) {
					// means bit - 3 is set need to check for local ports
					// Match the given ip string with current ip
					// @todo - convert the ip in argument to a structure such that you
					// do a int based comparision, and devise a method for ip range search as well
					if (wcsstr(rule.LocalAddress, ipString) == NULL) continue;
				}

				if ((mask & 16) != 0) {
					// means bit - 4 is set need to check for remote ports
				}

				if ((mask & 32) != 0) {
					// means bit - 5 is set need to check for protocol 
				}

				if ((mask & 64) != 0) {
					// means bit - 6 is set need to check for direction 
				}

				if ((mask & 128) != 0) {
					// means bit - 7 is set need to check for action 
				}

				
				// Rule passed every filter hence, it should be returned back!
				// push it to vector
				r.push_back(GetRules(pFwRule));
            }
        }
    }
	cleanUp();

	return r;
}


// ----- helper functions ----------

// Take input of form a.b.c.d and return its IP_ADDRESS Object
IP_ADDRESS IPStringtoIP(std::string ipstring) {
	IP_ADDRESS addr;
	addr.mask = 32;
	// ^ since it represnt a single ip address

	int status = 0, i = 0, len = ipstring.length();
	for(; i < len; i++) {
		if (ipstring[i] == '.') status++;
		else {
			addr.value[status] = addr.value[status] * 10 + (ipstring[i] - '0');
		}

		if (status > 3) break;
	}
	return addr;
}

// Take input of form a.b.c1.d1-a.b.c2.d2 and return a.b.c.d/mask
IP_ADDRESS IPRangetoIP(std::string iprange) {
	// possible algo split on '-', get ip for both and then compute the subnet

}
