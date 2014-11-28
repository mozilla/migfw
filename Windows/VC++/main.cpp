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
	std::vector <rules> r = GetRulesByFilter(s);

	wprintf(L" No of matching rules: %d \n", r.size());
	for(int i = 0; i < r.size(); i++) {
		DumpRule(r[i]);
	}

	r.clear();
	wprintf(L"\n ?????????????????? \nAttempting new function\n");
	r = GetRulesByFilter(8, s);

	wprintf(L" No of matching rules: %d \n", r.size());
	for(int i = 0; i < r.size(); i++) {
		DumpRule(r[i]);
	}
}


// @todo - recieve command line arguments and use the migfw api to generate report.
// take raw input for now, switch it to JSON based later both input and output
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

