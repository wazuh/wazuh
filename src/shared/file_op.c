/*      $OSSEC, file_op.c, v0.2, 2004/08/03, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS.
 * Available at http://www.ossec.net/hids/
 */

/* Functions to handle operation with files 
 */


#include "shared.h"


/* Sets the name of the starting progran */
void OS_SetName(char *name)
{
    __local_name = name;
    return;
}


int File_DateofChange(char *file)
{
    struct stat file_status;

    if(stat(file, &file_status) < 0)
        return(-1);

    return (file_status.st_mtime);
}

int IsDir(char *file)
{
    struct stat file_status;
    if(stat(file,&file_status) < 0)
        return(-1);
    if(S_ISDIR(file_status.st_mode))
        return(0);
    return(-1);
}


int CreatePID(char *name, int pid)
{
    char file[256];
    FILE *fp;
    
    if(isChroot())
    {
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,pid);
    }
    else
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,pid);
    }

    fp = fopen(file,"a");
    if(!fp)
        return(-1);
        
    fprintf(fp,"%d\n",pid);
    
    fclose(fp);
    
    return(0);
}

int DeletePID(char *name)
{
    char file[256];
    
    if(isChroot())
    {
        snprintf(file,255,"%s/%s-%d.pid",OS_PIDFILE,name,(int)getpid());
    }
    else
    {
        snprintf(file,255,"%s%s/%s-%d.pid",DEFAULTDIR,
                OS_PIDFILE,name,(int)getpid());
    }

    if(File_DateofChange(file) < 0)
        return(-1);
    
    unlink(file);	
    
    return(0);
}

#ifndef WIN32
/* getuname; Get uname and returns a string with it.
 * Memory must be freed after use
 */
char *getuname()
{
    struct utsname uts_buf;

    if(uname(&uts_buf) == 0)
    {
        char *ret;

        ret = calloc(256, sizeof(char));
        if(ret == NULL)
            return(NULL);

        snprintf(ret, 255, "%s %s %s %s %s", 
                                 uts_buf.sysname,
                                 uts_buf.nodename,
                                 uts_buf.release,
                                 uts_buf.version,
                                 uts_buf.machine);

        return(ret);
    }

    return(NULL);
}

/* goDaemon: Daemonize a process..
 *
 */
void goDaemon()
{
    int fd;
    pid_t pid;

    pid = fork();

    if(pid < 0)
    {
        merror(FORK_ERROR, __local_name);
        return;
    }
    else if(pid)
    {
        exit(0);
    }

    /* becoming session leader */
    if(setsid() < 0)
    {
        merror(SETSID_ERROR, __local_name);
        return;
    }

    /* forking again */
    pid = fork();
    if(pid < 0)
    {
        merror(FORK_ERROR, __local_name);
        return;
    }
    else if(pid)
    {
        exit(0);
    }


    /* Dup stdin, stdout and stderr to dev/null */
    if((fd = open("/dev/null", O_RDWR)) >= 0)
    {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
    }


    /* Going to / */
    chdir("/");

    
    /* Closing stdin, stdout and stderr */
    /*
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    */

    /* Openining stdin, stdout and stderr to dev null */
    /*
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);
    */
    
    return;
}


#else
/** get uname for windows **/
char *getuname()
{
    int ret_size = OS_MAXSTR -2;
    char *ret = NULL;

    typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);


    /* Extracted from ms web site 
     * http://msdn.microsoft.com/library/en-us/sysinfo/base/getting_the_system_version.asp
     */
    OSVERSIONINFOEX osvi;
    SYSTEM_INFO si;
    PGNSI pGNSI;
    BOOL bOsVersionInfoEx;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if(!(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)))
    {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) 
            return(NULL);
    }

    /* Allocating the memory */
    os_calloc(OS_MAXSTR +1, sizeof(char), ret);
    ret[OS_MAXSTR] = '\0';
    
    switch(osvi.dwPlatformId)
    {
        /* Test for the Windows NT product family. */
        case VER_PLATFORM_WIN32_NT:
            if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 )
            {
                if(osvi.wProductType == VER_NT_WORKSTATION )
                    strncat(ret, "Microsoft Windows Vista ", ret_size -1);
                else
                {
                    strncat(ret, "Windows Server Longhorn ", ret_size -1);
                }

                ret_size-=strlen(ret) +1;
            }

            else if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
            {
                pGNSI = (PGNSI) GetProcAddress(
                        GetModuleHandle("kernel32.dll"), 
                        "GetNativeSystemInfo");
                if(NULL != pGNSI)
                    pGNSI(&si);

                if( GetSystemMetrics(89) )
                    strncat(ret, "Microsoft Windows Server 2003 R2 ", 
                                 ret_size -1);
                else if(osvi.wProductType == VER_NT_WORKSTATION &&
                        si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
                {
                    strncat(ret, 
                            "Microsoft Windows XP Professional x64 Edition ",
                           ret_size -1 );
                }
                else
                {
                    strncat(ret, "Microsoft Windows Server 2003, ",ret_size-1);
                }
                
                ret_size-=strlen(ret) +1;
            }

            else if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
            {
                strncat(ret, "Microsoft Windows XP ", ret_size -1);

                ret_size-=strlen(ret) +1;
            }
            
            else if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
            {
                strncat(ret, "Microsoft Windows 2000 ", ret_size -1);

                ret_size-=strlen(ret) +1;
            }

            else if (osvi.dwMajorVersion <= 4)
            {
                strncat(ret, "Microsoft Windows NT ", ret_size -1);

                ret_size-=strlen(ret) +1;
            }
            else
            {
                strncat(ret, "Microsoft Windows Unknown ", ret_size -1);

                ret_size-=strlen(ret) +1;
            }

            /* Test for specific product on Windows NT 4.0 SP6 and later. */
            if(bOsVersionInfoEx)
            {
                /* Test for the workstation type. */
                if (osvi.wProductType == VER_NT_WORKSTATION &&
                    si.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_AMD64)
                {
                    if( osvi.dwMajorVersion == 4 )
                        strncat(ret, "Workstation 4.0 ", ret_size -1);
                    else if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
                        strncat(ret, "Home Edition ", ret_size -1);
                    else 
                        strncat(ret, "Professional ",ret_size -1);

                    /* Fixing size */
                    ret_size-=strlen(ret) +1;    
                }

                /* Test for the server type. */
                else if( osvi.wProductType == VER_NT_SERVER || 
                        osvi.wProductType == VER_NT_DOMAIN_CONTROLLER )
                {
                    if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==2)
                    {
                        if (si.wProcessorArchitecture==
                            PROCESSOR_ARCHITECTURE_IA64 )
                        {
                            if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret, 
                                "Datacenter Edition for Itanium-based Systems ",
                                ret_size -1);
                            else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret,
                                "Enterprise Edition for Itanium-based Systems ",
                                 ret_size -1);

                            ret_size-=strlen(ret) +1;    
                        }

                        else if ( si.wProcessorArchitecture==
                                PROCESSOR_ARCHITECTURE_AMD64 )
                        {
                            if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret, "Datacenter x64 Edition ",
                                             ret_size -1 );
                            else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret, "Enterprise x64 Edition ",
                                             ret_size -1 );
                            else 
                                strncat(ret, "Standard x64 Edition ",
                                             ret_size -1 );

                            ret_size-=strlen(ret) +1;    
                        }

                        else
                        {
                            if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret, "Datacenter Edition ",
                                              ret_size -1 );
                            else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret,"Enterprise Edition ",ret_size -1);
                            else if ( osvi.wSuiteMask == VER_SUITE_BLADE )
                                strncat(ret,"Web Edition ",ret_size -1 );
                            else 
                                strncat(ret, "Standard Edition ",ret_size -1);

                            ret_size-=strlen(ret) +1;    
                        }
                    }
                    else if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==0)
                    {
                        if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                            strncat(ret, "Datacenter Server ",ret_size -1);
                        else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                            strncat(ret, "Advanced Server ",ret_size -1 );
                        else 
                            strncat(ret, "Server ",ret_size -1);

                        ret_size-=strlen(ret) +1;        
                    }
                    else  /* Windows NT 4.0  */
                    {
                        if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                            strncat(ret, "Server 4.0, Enterprise Edition ",
                                         ret_size -1 );
                        else 
                            strncat(ret, "Server 4.0 ",ret_size -1);
                        
                        ret_size-=strlen(ret) +1;
                    }
                }
            }
            /* Test for specific product on Windows NT 4.0 SP5 and earlier */
            else  
            {
                HKEY hKey;
                char szProductType[81];
                DWORD dwBufLen=80;
                LONG lRet;

                lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                        "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
                        0, KEY_QUERY_VALUE, &hKey );
                if(lRet == ERROR_SUCCESS)
                {
                    char __wv[32];
                    
                    lRet = RegQueryValueEx( hKey, "ProductType", NULL, NULL,
                            (LPBYTE) szProductType, &dwBufLen);
                    RegCloseKey( hKey );

                    if((lRet == ERROR_SUCCESS) && (dwBufLen < 80) )
                    {
                        if (lstrcmpi( "WINNT", szProductType) == 0 )
                            strncat(ret, "Workstation ",ret_size -1);
                        else if(lstrcmpi( "LANMANNT", szProductType) == 0 )
                            strncat(ret, "Server ",ret_size -1);
                        else if(lstrcmpi( "SERVERNT", szProductType) == 0 )
                            strncat(ret, "Advanced Server " ,ret_size -1);

                        ret_size-=strlen(ret) +1;

                        memset(__wv, '\0', 32);
                        snprintf(__wv, 31, 
                                "%d.%d ",
                                osvi.dwMajorVersion, osvi.dwMinorVersion );

                        strncat(ret, __wv, ret_size -1);
                        ret_size-=strlen(__wv) +1;
                    }
                }
            }

            /* Display service pack (if any) and build number. */

            if( osvi.dwMajorVersion == 4 && 
                    lstrcmpi( osvi.szCSDVersion, "Service Pack 6" ) == 0 )
            { 
                HKEY hKey;
                LONG lRet;
                char __wp[64];

                memset(__wp, '\0', 64);
                /* Test for SP6 versus SP6a. */
                lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009",
                        0, KEY_QUERY_VALUE, &hKey );
                if( lRet == ERROR_SUCCESS )
                    snprintf(__wp, 63, "Service Pack 6a (Build %d)", 
                            osvi.dwBuildNumber & 0xFFFF );         
                else /* Windows NT 4.0 prior to SP6a */
                {
                    snprintf(__wp, 63, "%s (Build %d)",
                            osvi.szCSDVersion,
                            osvi.dwBuildNumber & 0xFFFF);
                }

                strncat(ret, __wp, ret_size -1);
                ret_size-=strlen(__wp) +1;
                RegCloseKey( hKey );
            }
            else
            {
                char __wp[64];

                memset(__wp, '\0', 64);

                snprintf(__wp, 63, "%s (Build %d)",
                        osvi.szCSDVersion,
                        osvi.dwBuildNumber & 0xFFFF);

                strncat(ret, __wp, ret_size -1);
                ret_size-=strlen(__wp) +1;
            }
            break;

        /* Test for the Windows Me/98/95. */
        case VER_PLATFORM_WIN32_WINDOWS:

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
            {
                strncat(ret, "Microsoft Windows 95 ", ret_size -1);
                ret_size-=strlen(ret) +1;
            } 

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
            {
                strncat(ret, "Microsoft Windows 98 ", ret_size -1);
                ret_size-=strlen(ret) +1;
            } 

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
            {
                strncat(ret, "Microsoft Windows Millennium Edition",
                        ret_size -1);

                ret_size-=strlen(ret) +1;
            } 
            break;

        case VER_PLATFORM_WIN32s:

            strncat(ret, "Microsoft Win32s", ret_size -1);
            ret_size-=strlen(ret) +1;
            break;
    }

    /* Returning system information */
    return(ret); 

}
#endif

/* EOF */
