#include <stdio.h>
#include "../headers/file_op.h"



FILE * wfopen(const char * pathname, const char * modes) {
#ifdef WIN32
    HANDLE hFile;
    DWORD dwDesiredAccess = 0;
    const DWORD dwShareMode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwCreationDisposition = 0;
    const DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    int flags = _O_TEXT;
    SECURITY_ATTRIBUTES sa;
    int fd;
    FILE * fp;
    int i;

    for (i = 0; modes[i]; ++i) {
        switch (modes[i]) {
        case '+':
            dwDesiredAccess |= GENERIC_WRITE | GENERIC_READ;
            flags &= ~_O_RDONLY;
            break;
        case 'a':
            dwDesiredAccess = FILE_APPEND_DATA;
            dwCreationDisposition = OPEN_ALWAYS;
            flags = _O_CREAT | _O_APPEND;
            break;
        case 'b':
            flags &= ~_O_TEXT;
            break;
        case 'r':
            dwDesiredAccess = GENERIC_READ;
            dwCreationDisposition = OPEN_EXISTING;
            flags |= _O_RDONLY;
            break;
        case 't':
            flags |= _O_TEXT;
            break;
        case 'w':
            dwDesiredAccess = GENERIC_WRITE;
            dwCreationDisposition = CREATE_ALWAYS;
        }
    }

    if (!(dwDesiredAccess && dwCreationDisposition)) {
        errno = EINVAL;
        return NULL;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    hFile = CreateFile(pathname, dwDesiredAccess, dwShareMode, &sa, dwCreationDisposition, dwFlagsAndAttributes, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    if (fd = _open_osfhandle((intptr_t)hFile, flags), fd < 0) {
        CloseHandle(hFile);
        return NULL;
    }

    if (fp = _fdopen(fd, modes), fp == NULL) {
        CloseHandle(hFile);
        return NULL;
    }

    return fp;

#else
    FILE *fp = fopen(pathname, modes);

    if(fp) {
    	w_file_cloexec(fp);
    }

    return fp;

#endif
}
