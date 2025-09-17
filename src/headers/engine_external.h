#ifndef CLIENT
#ifndef WIN32

#ifndef ENGINE_READ_CNF_HPP
#define ENGINE_READ_CNF_HPP

#include <stddef.h>
#include <stdlib.h>


char* read_engine_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size);

#endif // ENGINE_READ_CNF_HPP
#endif // WIN32
#endif // CLIENT
