#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define MAX_KEY_LENGTH 255
#define MAX_KEY	2048
#define MAX_VALUE_NAME 16383
 
char *(ignore_list[]) = {"SOFTWARE\\Classes","test123",NULL};
HKEY hk;
int open_key(char *subkey);
int max_deep = 4;
	
void QueryKey(HKEY hKey, char *p_key) 
{ 
    TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string 
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 

    DWORD i, retCode; 

    TCHAR  achValue[MAX_VALUE_NAME +1]; 
    TCHAR  achData[MAX_VALUE_NAME +1]; 
    DWORD cchValue = MAX_VALUE_NAME; 
    DWORD cchData = MAX_VALUE_NAME; 

    // Get the class name and the value count. 
    retCode = RegQueryInfoKey(
            hKey,                    // key handle 
            achClass,                // buffer for class name 
            &cchClassName,           // size of class string 
            NULL,                    // reserved 
            &cSubKeys,               // number of subkeys 
            &cbMaxSubKey,            // longest subkey size 
            &cchMaxClass,            // longest class string 
            &cValues,                // number of values for this key 
            &cchMaxValue,            // longest value name 
            &cbMaxValueData,         // longest value data 
            &cbSecurityDescriptor,   // security descriptor 
            &ftLastWriteTime);       // last write time 

    // Enumerate the subkeys, until RegEnumKeyEx fails.

    if (cSubKeys)
    {
        printf( "\nNumber of subkeys: %d\n", cSubKeys);

        for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                    achKey, 
                    &cbName, 
                    NULL, 
                    NULL, 
                    NULL, 
                    &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {
                char f_key[1024];

                f_key[1023] = '\0';
                if(p_key)
                {
                    snprintf(f_key, 1023, TEXT("%s\\%s"),p_key, achKey);
                }
                else
                {
                    snprintf(f_key, 1023, "%s",achKey);
                }
                _tprintf(TEXT("KEY: (%d) %s\n"), i+1, f_key);

                open_key(f_key);

            }
        }
    } 


    /* Getting cvalues */
    if (cValues) 
    {
	int i = 0;    
        FILE *fp;
	char tmp_file[MAX_KEY +1];
	tmp_file[MAX_KEY] = '\0';

	printf("h?\n");
	strncpy(tmp_file, p_key, MAX_KEY);
	while(tmp_file[i] != '\0')
	{
	   if(tmp_file[i] == '\\')
	      tmp_file[i] = '-';
	   i++;	   
	}

        fp = fopen(tmp_file, "w");
        if(!fp)
        {
            printf("error opening %s\n", tmp_file);
            return;
        }

        fprintf(fp, "Number of values: %d\r\n", cValues);

        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
            retCode = RegEnumValue(hKey, i, 
                    achValue, 
                    &cchValue, 
                    NULL, 
                    NULL,
                    achData,
                    &cchData);

            if (retCode == ERROR_SUCCESS ) 
            {
                fprintf(fp, "VALUE: (%d) %s - %s\r\n", i+1, achValue, achData); 
            } 
        }
        fclose(fp);
    }
}

int open_key(char *subkey)
{
   int i = 0;	
   HKEY hTestKey;

   /* List to ignore */
   if(subkey)
   {
      while(ignore_list[i] != NULL)
      {
         if(strcasecmp(ignore_list[i], subkey) == 0)
            return(0);
         i++;      
      }
   }

   if( RegOpenKeyEx(hk,
	subkey,
        0,
        KEY_READ,
        &hTestKey) == ERROR_SUCCESS
      )
   {
      QueryKey(hTestKey, subkey);
      RegCloseKey(hk);
   }
   else
   {
	   printf("Error opening: %s\n", subkey);
   }

}


int main(void)
{
	hk = HKEY_LOCAL_MACHINE;
	char *rk = NULL;

	printf("starting\n");
	open_key(rk);

	return(0);
}

