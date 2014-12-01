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
#include "jsoncons/json.hpp"

using namespace std;
using namespace jsoncons;

// print json output for all resulting rules
void DumpRule(std::vector <rules> r) {
	json fwrules(json::an_array);
	for(int i = 0; i < r.size(); i++) {
		json obj;
		obj["name"] = BstrToStdString(r[i].Name);
		obj["description"] = BstrToStdString(r[i].Description);
		obj["application"] = BstrToStdString(r[i].ApplicationName);
		obj["local_addr"] = BstrToStdString(r[i].LocalAddress);
		obj["remote_addr"] = BstrToStdString(r[i].RemoteAddress);
		obj["local_port"] = BstrToStdString(r[i].LocalPorts);
		obj["remote_port"] = BstrToStdString(r[i].RemotePorts);
		/*obj["protocol"] = r.Protocol;*/

		if (r[i].Direction == 1) obj["direction"] = "IN";
		else  obj["direction"] = "OUT";

		if (r[i].Action == 1) obj["action"] = "ALLOW";
		else  obj["action"] = "BLOCK";
		fwrules.add(obj);
	}
	cout<<pretty_print(fwrules)<<endl;
	/*
	if(r.Lval != NET_FW_IP_VERSION_V4 && r.Lval != NET_FW_IP_VERSION_V6) {
		wprintf(L" remote ports: %s\n ", r.RemotePorts);
		wprintf(L" local ports: %s\n ", r.LocalPorts);
    } else wprintf(L" ICMP TypeCode: %s\n ", r.ICMP_Typecode);
	*/
}



// @todo - recieve command line arguments and use the migfw api to generate report.
// take raw input for now, switch it to JSON based later both input and output
int __cdecl main()
{
	// Testing read rule API
	std::vector <rules> r;
	r = GetRulesByFilter(223, (string)"google", "23.22.33.22/255.255.255.250", "22.22.22.22/255.255.255.255",
		"23", "22,33", 0, 0, 1);

	wprintf(L"GENERAL DATA:\nNo of matching rules: %d \nJSON:\n", r.size());
	DumpRule(r);

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

