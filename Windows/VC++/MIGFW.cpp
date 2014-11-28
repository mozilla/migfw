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
				ret.Direction = DIRECTION_IN;
				break;
			case NET_FW_RULE_DIR_OUT:
				ret.Direction = DIRECTION_OUT;
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
				ret.Action = ACTION_BLOCK;
				break;
			case NET_FW_ACTION_ALLOW:
				ret.Action = ACTION_ALLOW;
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
vector <rules> GetRulesByFilter(int mask, std::string name, std::string local_ip,
								std::string remote_ip, std::string local_port,
								std::string remote_port, int protocol, int direction, int action) {
	vector <rules> r;

	// Initialize COM and ...
	// Retrieve all firewall rules to pfrules object (global)
	if (!init()) {
		// initialize failed
		// return an empty vector
		return r;
	}

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
					std::wstring ws;
					ws.assign(name.begin(), name.end());
					BSTR name = SysAllocStringLen(ws.data(), ws.size());
					if (wcsstr(rule.Name, name) == NULL) continue;
				}

				if ((mask & 2) != 0) {
					// means bit - 1 is set need to check for local Address
					// parse the ip string for this rule and check if the given range belongs to any of those
					IP_RANGE rneedle = IPRangetoIP(local_ip), rhaystack;
					std::string iprangestr;
					
					int start = 0, end = 0, i;
					std::string localAddress = BstrToStdString(rule.LocalAddress);
					int len = localAddress.length();
					for(i = 0; i <= len; i++) {
						if (i == len) {
							// last case
							iprangestr = localAddress.substr(start, len + 1);
							rhaystack = IPRangetoIP(iprangestr);
							if (inRange(rhaystack, rneedle)) break;
						} else {
							if (localAddress[i] == ',') {
								iprangestr = localAddress.substr(start, i);
								rhaystack = IPRangetoIP(iprangestr);
								if (inRange(rhaystack, rneedle)) break;
								start = i + 1;
							}
						}
					}
					if (i == len + 1) continue;
				}

				if ((mask & 4) != 0) {
					// means bit - 2 is set need to check for remote Address
					IP_RANGE rneedle = IPRangetoIP(remote_ip), rhaystack;
					std::string iprangestr;
					
					int start = 0, end = 0, i;
					std::string remoteAddress = BstrToStdString(rule.RemoteAddress);
					int len = remoteAddress.length();
					for(i = 0; i <= len; i++) {
						if (i == len) {
							// last case
							iprangestr = remoteAddress.substr(start, len + 1);
							rhaystack = IPRangetoIP(iprangestr);
							if (inRange(rhaystack, rneedle)) break;
						} else {
							if (remoteAddress[i] == ',') {
								iprangestr = remoteAddress.substr(start, i);
								rhaystack = IPRangetoIP(iprangestr);
								if (inRange(rhaystack, rneedle)) break;
								start = i + 1;
							}
						}
					}
					if (i == len + 1) continue;
				}

				if ((mask & 8) != 0) {
					// means bit - 3 is set need to check for local ports
					// if the rule value is * means it allows every value, so
					// filter can be skipped, else check
					if (rule.LocalPorts[0] != '*') {
						// convert the string to int array
						// sort it, similarly do for input one
						// check if each value exist in rule
						if (!isSubVector(BstrToStdString(rule.LocalPorts), local_port)) continue;
					}
				}

				if ((mask & 16) != 0) {
					// means bit - 4 is set need to check for remote ports
					// Exception if set as IPHTTPS, option available in windows firewall
					// @todo - deal with ^ above type of cases
					if (rule.RemotePorts[0] != '*') {
						if (!isSubVector(BstrToStdString(rule.RemotePorts), remote_port)) continue;
					}
				}

				if ((mask & 32) != 0) {
					// means bit - 5 is set need to check for protocol 
					// @todo - so the protocol matching, maintain definations for each of
					// protocols as integer and update code in retrieving and cheking values
				}

				if ((mask & 64) != 0) {
					// means bit - 6 is set need to check for direction
					if (direction != rule.Direction) continue;
				}

				if ((mask & 128) != 0) {
					// means bit - 7 is set need to check for action
					if (action != rule.Action) continue;
				}

				
				// Hurray!! Rule passed every filter hence, it should be returned back!
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
			if (ipstring[i] > '9' || ipstring[i] < '0') break;
			addr.value[status] = addr.value[status] * 10 + (ipstring[i] - '0');
		}

		if (status > 3) break;
	}
	return addr;
}


// Take input of form a.b.c1.d1-a.b.c2.d2 or  and return iprange in our struct
IP_RANGE IPRangetoIP(std::string iprange) {
	// possible algo split on '-', get ip for both and then compute the subnet
	bool subnet = true;
	int position = 0;

	// check if is it of a.b.c.d/subnet mask or a.b.c.d-a1.b1.c1.d1
	// start from 7th bit because thats the minimum possible
	for(int i = 7; i < iprange.length(); i++) {
		position = i;
		if (iprange[i] == '-') {
			subnet = false;
			break;
		} else if (iprange[i] == '/') {
			break;
		}
	}

	std::string ip1 = iprange.substr(0, position);
	std::string ip2 = iprange.substr(position + 1);
	IP_RANGE range;

	if (subnet) {
		range.add1 = IPStringtoIP(ip1);	
		range.add2 = IPStringtoIP(ip2);
		int i;
		for(i = 0; i < 4; i++) {
			if (range.add2.value[i] != 255) {
				range.add2.value[i] = range.add1.value[i] + (255 - range.add2.value[i]);
				++i;
				break;
			} else {
				range.add2.value[i] = range.add1.value[i];
				// ^ all other takes the max value by default
			}
		}
		for(; i < 4; i++) range.add2.value[i] = 255;
	} else {
		range.add1 = IPStringtoIP(ip1);
		range.add2 = IPStringtoIP(ip2);
	}
	return range;
}


/**
 * Function to check if r2 lies in r1,
 * If checking for one value keep, r2.add1 = r2.add2
 */
bool inRange(IP_RANGE r1, IP_RANGE r2) {
	// r2.add1 >= r1.add1 and r1 and
	// r2.add2 <= r1.add2
	for(int i = 0; i < 4; i++) {
		if (r2.add1.value[i] < r1.add1.value[i]) return false;
	}

	for(int i = 0; i < 4; i++) {
		if (r2.add2.value[i] > r1.add2.value[i]) return false;
	}

	return true;
}

// --- Additional helper functions

// convert a BSTR to a std::string. 
std::string& BstrToStdString(const BSTR bstr, std::string& dst, int cp)
{
    if (!bstr)
    {
        // define NULL functionality. I just clear the target.
        dst.clear();
        return dst;
    }

    // request content length in single-chars through a terminating
    //  nullchar in the BSTR. note: BSTR's support imbedded nullchars,
    //  so this will only convert through the first nullchar.
    int res = WideCharToMultiByte(cp, 0, bstr, -1, NULL, 0, NULL, NULL);
    if (res > 0)
    {
        dst.resize(res);
        WideCharToMultiByte(cp, 0, bstr, -1, &dst[0], res, NULL, NULL);
    }
    else
    {    // no content. clear target
        dst.clear();
    }
    return dst;
}

std::string BstrToStdString(BSTR bstr, int cp)
{
    std::string str;
    BstrToStdString(bstr, str, cp);
    return str;
}

/**
 * Function to take ports list in string and return it as vector of integers
 */
vector <int> PortStringToSortedVector(std::string ports) {
	vector <int>v;
	int val = 0;
	for(int i = 0; i < ports.length(); i++) {
		if (ports[i] == ',') {
			v.push_back(val);
			val = 0;
		} else {
			if (ports[i] > '9' || ports[i] < '0') break;
			val = val * 10 + (ports[i] - '0');
		}
		
	}
	v.push_back(val);
	sort(v.begin(), v.end());
	return v;
}

// code to check all port values of n exist in h
bool isSubVector(std::string h, std::string n) {
	vector <int> haystack = PortStringToSortedVector(h);
	vector <int> needle = PortStringToSortedVector(n);
	int hptr = 0, nptr = 0;
	int hmax = haystack.size();
	int nmax = needle.size();

	while(nptr < nmax) {
		// max limit of hptr reached
		if (hptr == hmax) return false;

		if (haystack[hptr] == needle[nptr]) {
			hptr++;
			nptr++;
		} else if (haystack[hptr] < needle[nptr]){
			hptr++;
		} else return false;
	}
	return true;
}
