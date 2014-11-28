/**
 * Header file for migfw windows
 * Supports both read rules and write rules
 */

#ifndef MIGFW
#define MIGFW

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

// Standard definations to be used later in library
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

// Structure to store an ip address, with mask value
struct IP_ADDRESS {
	int value[4];
	int mask;
	IP_ADDRESS() {
		value[0] = value[1] = value[2] = value[3] = 0;
	}
};

// Forward declaration to helper functions
IP_ADDRESS IPStringtoIP(std::string ipstring);
IP_ADDRESS IPRangetoIP(std::string iprange);

// Forward declarations for global functions
void        DumpFWRulesInCollection(INetFwRule* FwRule);
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);
void		cleanUp();
bool		init();
rules		GetRules(INetFwRule* FwRule);
vector<rules> GetRulesByFilter(std::string ip);
vector <rules> GetRulesByFilter(int mask, std::string ip);

#endif