Reading the firewall rules
Currently data is returned in following structure:

```c++
struct rules {
	BSTR Name;
	BSTR Description;
	BSTR ApplicationName;
	BSTR LocalPorts;
	BSTR RemotePorts;
	BSTR LocalAddress;
	BSTR RemoteAddress;
	int Direction;
	int Action;
	BSTR InterfaceType;
	BSTR Protocol;

	BSTR ICMP_Typecode;
	long Lval;
};
```

So rules can be read and filtered according to any member of the structure.

In c++, the filters can be used by function call like:
```
GetRulesByFilter(223, "google", "23.22.33.22/255.255.255.250",
 "22.22.22.22/255.255.255.255", "23", "22,33", 0, 0, 1);

```
Where first parameter is used for masking the filters, as `223` = `011011111` so those values with bit set are checked for filters and others are ignored. Such parameters can be sent as an empty string!
