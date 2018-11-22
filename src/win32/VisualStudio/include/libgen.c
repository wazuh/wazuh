#include "libgen.h"

#define _MAX_SPLITPATH (_MAX_DRIVE + _MAX_DIR + _MAX_FNAME + _MAX_EXT)

static char dirname_path[_MAX_SPLITPATH];
static char basename_path[_MAX_SPLITPATH];

char *dirname(char *path)
{
    if (path == NULL || *path == NULL) return ".";
    
    char drive[_MAX_DRIVE] = {'\0'}, dir[_MAX_DIR] = {'\0'};
    
    memset(dirname_path, 0, _MAX_SPLITPATH);
    
    size_t len = strlen(path);
    if (len < _MAX_DRIVE) return ".";
    
    _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    
    snprintf(dirname_path, _MAX_SPLITPATH, "%s%s", drive, dir);
    
    size_t pos = strlen(dirname_path) - 1;
    
    if (dirname_path[pos] == '\\' || dirname_path[pos] == '/') dirname_path[pos] = '\0';
    
    return dirname_path;
}

char *basename(char *path)
{
    if (path == NULL || *path == NULL) return ".";
    
    char drive[_MAX_DRIVE] = {'\0'}, dir[_MAX_DIR] = {'\0'};
    
    memset(dirname_path, 0, _MAX_SPLITPATH);
    
    size_t len = strlen(path);
    if (len < _MAX_DRIVE) return ".";
    
    _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    
    snprintf(dirname_path, _MAX_SPLITPATH, "%s%s", drive, dir);
    
    size_t pos = strlen(dirname_path) - 1;
    
    if (dirname_path[pos] == '\\' || dirname_path[pos] == '/') dirname_path[pos] = '\0';
    
    return dirname_path;
}