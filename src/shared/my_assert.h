#pragma once

#ifndef NDEBUG
#define _DEBUG
#endif

#define _CONCAT(x,y) x ## y
#define CONCAT(x,y) _CONCAT(x,y)
#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x

#ifdef _DEBUG
/** A compile time assertion check.
 *
 *  Validate at compile time that the predicate is true without
 *  generating code. This can be used at any point in a source file
 *  where typedef is legal.
 *
 *  On success, compilation proceeds normally.
 *
 *  On failure, attempts to typedef an array type of negative size. The
 *  offending line will look like
 *      typedef assertion_failed_file_h_42[-1]
 *  where file is the content of the second parameter which should
 *  typically be related in some obvious way to the containing file
 *  name, 42 is the line number in the file on which the assertion
 *  appears, and -1 is the result of a calculation based on the
 *  predicate failing.
 *
 *  \param predicate The predicate to test. It must evaluate to
 *  something that can be coerced to a normal C boolean.
 *
 *  \param file A sequence of legal identifier characters that should
 *  uniquely identify the source file in which this condition appears.
 */
#define STATIC_ASSERT(predicate)                    \
    typedef char CONCAT(COMPILE_TIME_ASSERT_FAILED_, \
                        __COUNTER__)[(predicate) ? 1 : -1];

void my_assert(const char *, const char *, const char *, int);
void my_assert_msg(const char *expr,
                   const char *file,
                   const char *func,
                   int line,
                   char *fmt,
                   ...);

#define ASSERT(expr) \
    if (!(expr))     \
        my_assert(STRINGIFY(expr), __FILE__, __func__, __LINE__);
#define ASSERT_MSG(expr, msg, ...)     \
    if (!(expr))                       \
        my_assert_msg(STRINGIFY(expr), \
                      __FILE__,        \
                      __func__,        \
                      __LINE__,        \
                      msg,             \
                      ##__VA_ARGS__);
#else
#define ASSERT(x)
#define ASSERT_MSG(x, y, ...)
#define STATIC_ASSERT(a);
#endif
