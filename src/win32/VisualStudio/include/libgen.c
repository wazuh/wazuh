#include "libgen.h"

#define _MAX_SPLITPATH (_MAX_DRIVE + _MAX_DIR + _MAX_FNAME + _MAX_EXT)

static char dirname_path[_MAX_SPLITPATH];
static char basename_path[_MAX_SPLITPATH];

char *dirname(char *path)
{
    size_t len = strlen(path);
    
    if (!path || !*path || len < _MAX_DRIVE) return ".";
    
    int use_backslash = 0;
    
    char *ptr = strrchr(path, '/');
    if (!ptr)
    {
        ptr = strrchr(path, '\\');
        if (ptr == NULL) return ".";
        
        use_backslash = 1;
    }
    
    char drive[_MAX_DRIVE] = {'\0'}, dir[_MAX_DIR] = {'\0'};
    
    _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    
    snprintf(dirname_path, _MAX_SPLITPATH, "%s%s", drive, dir);
    
    size_t pos = (strlen(dirname_path) - 1);
    
    if (dirname_path[pos] == '/' || (use_backslash && dirname_path[pos] == '\\')) dirname_path[pos] = '\0';
    
    return dirname_path;
}

char *basename(char *path)
{
    size_t len = strlen(path);
    
    if (!path || !*path || len < _MAX_DRIVE) return ".";
    
    int use_backslash = 0;
    
    char *ptr = strrchr(path, '/');
    if (!ptr)
    {
        ptr = strrchr(path, '\\');
        if (ptr == NULL) return ".";
        
        use_backslash = 1;
    }
    
    snprintf(basename_path, _MAX_SPLITPATH, path);
    
    if (basename_path[len - 1] == '/' || (use_backslash && basename_path[len - 1] == '\\')) basename_path[len - 1] = '\0';
    
    char fname[_MAX_FNAME] = {'\0'}, ext[_MAX_EXT] = {'\0'};
    
    _splitpath_s(basename_path, NULL, 0, NULL, 0, fname, _MAX_FNAME, ext, _MAX_EXT);
    
    snprintf(basename_path, _MAX_SPLITPATH, "%s%s", fname, ext);
    
    return basename_path;
}