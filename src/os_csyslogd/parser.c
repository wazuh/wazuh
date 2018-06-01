#include "parser.h"

char regexList[][100] = {
   "\\(([^)]*)",
   "\\s([^-]*)",
   "([^>]*)->",
   ">([^.]*)",
   "WinEvtLog:\\s([^:]*):\\s([^:]*):\\s([^:]*):\\s([^:]*):\\s([^:]*):\\s([^:]*):\\s([^:]*)",
   "Logon Type:\\s\\s\\s([^ ])",
   ".*[^Account Name:\\s\\s[^ ]*]*(Account Name:\\s\\s[^ ]*)",
   "Account Name:\\s\\s([^ ]*)",
   ".*[^Account Domain:\\s\\s[^ ]*]*(Account Domain:\\s\\s[^ ]*)",
   "Account Domain:\\s\\s([^ ]*)",
   ".*[^Logon ID:\\s\\s[^ ]*]*(Logon ID:\\s\\s[^ ]*)",
   "Logon ID:\\s\\s([^ ]*)",
   "\\(([^)]*)",
   "(pci.*)" 
};
  
/*
int main()
{
	struct TestValues{
	    char* testvalue1;
	    char* testvalue2;
	    char* testvalue3;
	};

	struct TestValues* testers = malloc(sizeof(struct TestValues));
	testers->testvalue1 = "(shost) src->location";
	testers->testvalue2 = "src->location";
	testers->testvalue3 = "Sep 05 08:51:37 WinEvtLog: Security: AUDIT_SUCCESS(4624): Microsoft-Windows-Security-Auditing: (no user): no domain: Prosoc3-PC: An account was successfully logged on.    Subject:   Security ID:  S-1-5-18   Account Name:  PROSOC3-PC$   Account Domain:  WORKGROUP   Logon ID:  0x3e7    Logon Type:   2    New Logon:   Security ID:  S-1-5-21-3372000298-2906898488-3573625560-1000   Account Name:  Prosoc3   Account Domain:  Prosoc3-PC   Logon ID:  0x194b9   Logon GUID:  {00000000-0000-0000-0000-000000000000}    Process Information:   Process ID:  0x1b4   Process Name:  C:\Windows\System32\winlogon.exe    Network Information:   Workstation Name: PROSOC3-PC   Source Network Address: 127.0.0.1   Source Port:  0    Detailed Authentication Information:   Logon Process:  User32    Authentication Package: Negotiate   Transited Services: -   Package Name (NTLM only): -   Key Length:  0    This event is generated when a logon session is created. It is generated on the computer that was accessed.    The subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.    The logon type field indicates the kind of lo\0";
	//declare this struct to pass to the functions so you can unpack the strings after.
	struct KeyStore* workingKeyStore = malloc(sizeof(struct KeyStore));
	
	//first test string is an ideal case.
	printf("First Test String:\n");
	parseString(testers->testvalue1, "Summary", workingKeyStore);
	//printf("\nThis is outside of the function scope:\n");
	//printf("original string: \"(Hello) World -> blahblahblah\"\n");
	printf("shost: %s\n", workingKeyStore->shost);
	printf("src: %s\n", workingKeyStore->src);
	printf("location: %s\n", workingKeyStore->location);
	return 0;
}
*/

void parseString(char *inputString, char fieldname[MAX_STR_LEN], struct KeyStore* workingKeyStore)
{ 
    strcpy((workingKeyStore->original), inputString);

    if((workingKeyStore->original)[0] == '\0')
	exit(0);
      
    workingKeyStore->shost[0] = '\0';
    workingKeyStore->src[0] = '\0';
    workingKeyStore->location[0] = '\0';
    workingKeyStore->externalId[0] = '\0';
    workingKeyStore->sntdom[0] = '\0';
    workingKeyStore->msg[0] = '\0';
    workingKeyStore->cn1[0] = '\0';
    workingKeyStore->duser[0] = '\0';
    workingKeyStore->destinationDnsDomain[0] = '\0';
    workingKeyStore->duid[0] = '\0';
    workingKeyStore->cat[0] = '\0';
 
    int indexList[3];
    unsigned int i = 0;
    unsigned int loopEnd = 0;
    
    if (strcmp(fieldname, "Summary") == 0){
	if((workingKeyStore->original)[0] == '('){
	    // we will need indices 0, 1, and 3
	    indexList[0] = 0;
	    indexList[1] = 1;
	    indexList[2] = 3;
	    loopEnd = 3;
	}
	else{
	    // we will need indices 2, 3
	    indexList[0] = 2;
	    indexList[1] = 3;
	    loopEnd = 2;
	}
    }
    else if (strcmp(fieldname, "dsm") == 0){
	// we will need indices 4 (for group 2)
	// groups 2, 6, 7
	indexList[0] = 4;
	loopEnd = 1;
    }
    else if (strcmp(fieldname, "cn1") == 0){
	// we will need index 5
	indexList[0] = 5;
	loopEnd = 1;
    }
    else if (strcmp(fieldname, "duser") == 0){
	// we will need index 6, 7
	indexList[0] = 6;
	loopEnd = 1;
    }
    else if (strcmp(fieldname, "destinationDnsDomain") == 0){
	// we will need index 8, 9
	indexList[0] = 8;
	loopEnd = 1;
    }
    else if (strcmp(fieldname, "duid") == 0){
	// we will need index 10, 11
	indexList[0] = 10;
	loopEnd = 1;
    }
    else if (strcmp(fieldname, "cat") == 0){
	// we will need index 13
	indexList[0] = 13;
	loopEnd = 1;
    }
 
    for(i = 0; i < loopEnd; i++)
    {
        findMatch(indexList[i], fieldname, (workingKeyStore->original), workingKeyStore);
    }  
 
}

void findMatch(int regexIndex, char field[MAX_STR_LEN], char inputOriginal[MAX_SIZE], struct KeyStore* workingKeyStore)
{
    int retval = 0;
    regex_t re;
    regmatch_t rm[10];
    size_t maxrm = 10;
    int res = regcomp(&re, regexList[regexIndex], REG_EXTENDED);
    
    if (res == 0 && inputOriginal[0]) 
    {
        inputOriginal[strlen(inputOriginal)] = '\0';
        
        if ((retval = regexec(&re, inputOriginal, maxrm, rm, 0)) == 0)
        {  
            unsigned int g = 0;
 
	    for (g = 1; g < maxrm; g++)
            {
                if (rm[g].rm_so == (size_t)-1)
              	    break;  // No more groups

          	char sourceCopy[strlen(inputOriginal) + 1];
          	strcpy(sourceCopy, inputOriginal);
          	sourceCopy[rm[g].rm_eo] = 0;
          	if (DEBUG != 0) printf("Group %u: [%2u-%2u]: %s\n",
          	       g, rm[g].rm_so, rm[g].rm_eo,
         	       sourceCopy + rm[g].rm_so);

		strcpy((workingKeyStore->match), sourceCopy + rm[g].rm_so);
		
		if (g == 1){
		    if (regexIndex == 0){
			strcpy(workingKeyStore->shost, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 1){
		        strcpy(workingKeyStore->src, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 2){
		        strcpy(workingKeyStore->src, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 3){
		        strcpy(workingKeyStore->location, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 5){
			strcpy(workingKeyStore->cn1, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 6){
			findMatch(7, field, (workingKeyStore->match), workingKeyStore);
 		    }
		    else if (regexIndex == 7){
			strcpy(workingKeyStore->duser, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 8){
			findMatch(9, field, (workingKeyStore->match), workingKeyStore);
		    }
		    else if (regexIndex == 9){
			strcpy(workingKeyStore->destinationDnsDomain, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 10){
			findMatch(11, field, (workingKeyStore->match), workingKeyStore);
		    }
		    else if (regexIndex == 11){
			strcpy(workingKeyStore->duid, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 12){
			strcpy(workingKeyStore->externalId, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		    }
		    else if (regexIndex == 13){
			strcpy(workingKeyStore->cat, workingKeyStore->match);
		        if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->cat);	
		    } 
		     
		}
		else{
		    if (regexIndex == 4){
		        if (g == 2){
			    findMatch(12, field, (workingKeyStore->match), workingKeyStore);
		        }
		        else if (g == 6){
			    strcpy(workingKeyStore->sntdom, workingKeyStore->match); 
		            if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		        }	
		        else if (g == 7){
			    strcpy(workingKeyStore->msg, workingKeyStore->match);
		            if (DEBUG != 0) printf("DEBUG: match: %s\n", workingKeyStore->match);	
		        }
		    }
		}
		
            }
        }
    }
    else{
    	fprintf(stderr, "Failed to compile regex %u '%s'\n", regexIndex, regexList[regexIndex]);
    } 
}
 
