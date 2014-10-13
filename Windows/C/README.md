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
	BSTR Direction;
	BSTR Action;
	BSTR InterfaceType;
	BSTR Protocol;

	BSTR ICMP_Typecode;
	long Lval;
};
```

So rules can be read and filtered according to any member of the structure.
