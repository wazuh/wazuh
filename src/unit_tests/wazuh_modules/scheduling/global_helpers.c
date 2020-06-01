void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    return ;
}

void __wrap__mtwarn(const char *tag, const char * file, int line, const char * func, const char *msg, ...){
    return;
}

int __wrap_StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type)
{
    return (0);
}
