/**
 * Code to progmatically inject firewall rules in OS X
 *
 * Logic: add configuration to pf.con
 */
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex>
using namespace std; 

#define ANCHOR_FILE_PATH "/etc/pf.anchors/migfw"

// Function Declarations from here
int addRules(string ip, string table);

// Function Definations from here


/**
 * Function to add IPs to existing tables to block them (for ex)
 *
 * @params: ip (char *) - ip address to block
 * @params: table (char *) - table to which ip has to be added
 * 
 * @returns: 1 for successfull addition, 0 otherwise
 */
inline int addRules(char *ip, char *table)
{
	char command[50];
	sprintf(command,"sudo pfctl -t %s -Tadd %s", table, ip);
	try {
		system(command);
		//^ #todo: same as @todo-1 below
		return 1;
	} catch (int e) {
		#ifdef DEBUG
			cout<<"\n [ERROR] [Function: addRules] [ip: "<<ip<<"] [table: "<<table<<"] [ERROR_CODE: "<<e<<"]";
		#endif
		return 0;
	}
}

/**
 * Function to call system command to flush existing rules and
 * Read (& load) new conf
 *
 * @params: void
 * 
 * @returns - (int) 1 for successful run, 0 otherwise
 */
int pf_refresh()
{
	char command[50];
	sprintf(command,"sudo pfctl -v -n -f %s", ANCHOR_FILE_PATH);
	try {
		system(command);
		// ^ #todo-1: this should not print anything to command line, or just parse the o/p
		// ...... to retrieve meaningful information, try catch block won't help to get errors
		// ...... need to parse the o/p and make sure no errors have occured.
		return 1;
	} catch (int e) {
		#ifdef DEBUG
			cout<<"\n [ERROR] [Function: pf_refresh] [ERROR_CODE: "<<e<<"]";
		#endif
		return 0;
	}
}

/**
 * Function to validate weather or not given ipv4 is valid or not
 *
 * @params: ip (char pointer) - ip address
 *
 * @returns: bool - true for correct IP, fals other wise
 */
bool validateIP(char *ip) {
	// ip structure
	// [0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}
	return std::regex_match (ip, std::regex("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}"));
}



int main() {
	pf_refresh();
	return 0;
}

