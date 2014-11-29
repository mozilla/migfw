/********************************************************************
Copyright (C) Microsoft. All Rights Reserved.

Abstract:
    This C++ file includes code for enumerating Windows Firewall
    rules using the Microsoft Windows Firewall APIs. This code will
	be used in a Go library using CGO.

********************************************************************/

// Note this file is a placeholder to use the library funcitons for now
// meant purely for debugging purposes for now

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include "migfw.h"
#include <string>
#include <iostream>
#include <vector>

using namespace std;

// ----------------------------------------------------
// Temporary function for current debugging purposes
// Alter when this code will be served as library
// ----------------------------------------------------

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

	wprintf(L" Direction: %s\n ", (r.Direction == 1)?L"IN":L"OUT");
	wprintf(L" Action: %s\n ", r.Action == 1 ? L"ALLOW" : L"BLOCK");
}



// @todo - recieve command line arguments and use the migfw api to generate report.
// take raw input for now, switch it to JSON based later both input and output
int __cdecl main()
{
	// Testing read rule API
	std::vector <rules> r;
	r = GetRulesByFilter(223, (string)"google", "23.22.33.22/255.255.255.250", "22.22.22.22/255.255.255.255",
		"23", "22,33", 0, 0, 1);

	wprintf(L" No of matching rules: %d \n", r.size());
	for(int i = 0; i < r.size(); i++) {
		DumpRule(r[i]);
	}

	// Testing write rule API
	cout<<"-------------------------------\n";
	cout<<"Write rule"<<endl;
	if (createRule(255, "TEST_FW_WRITE_RULE", "192.168.100.1/255.255.255.255",
				"23.22.12.0/255.255.255.0", "23",
				"25", 17, 0, 1, true)) {
		cout<<"SUCCESS"<<endl;
	} else cout<<"FAILED"<<endl;


	getchar();
	getchar();
    return 0;
}

