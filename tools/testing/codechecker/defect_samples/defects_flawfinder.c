/*
 * defects_flawfinder.c — Flawfinder detection validation samples.
 *
 * Each function contains exactly ONE pattern that Flawfinder flags.
 * These mirror the real findings from ebpf_whodata.cpp (Coverity CID 1671524/
 * 1671525) so the selftest validates the same checker classes seen in
 * production scans.
 *
 * Defect map
 * ----------
 *   defect_toctou_chmod   -> flawfinder.race.chmod   (CWE-362)
 *   defect_toctou_access  -> flawfinder.race.access  (CWE-362/CWE-367)
 *   defect_buffer_gets    -> flawfinder.buffer.gets  (CWE-119)
 *   defect_buffer_strcpy  -> flawfinder.buffer.strcpy (CWE-119)
 *   defect_format_sprintf -> flawfinder.format.sprintf (CWE-134)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* flawfinder.race.chmod (CWE-362) -------------------------------------------
 * chmod() is TOCTOU-prone: the file can be replaced between the path
 * resolution and the permission change.  Mirrors ebpf_whodata.cpp:245.
 */
void defect_toctou_chmod(const char *path)
{
    chmod(path, 0644);
}

/* flawfinder.race.access (CWE-362/CWE-367) ----------------------------------
 * access() followed by open() is a classic TOCTOU pair: the condition
 * checked by access() may have changed by the time open() runs.
 * Mirrors ebpf_whodata.cpp:669 / ebpf_whodata.cpp:689.
 */
int defect_toctou_access(const char *path)
{
    if (access(path, R_OK) == 0)
        return open(path, O_RDONLY);
    return -1;
}

/* flawfinder.buffer.gets (CWE-119) ------------------------------------------
 * gets() has no bounds parameter — any input overflows the buffer.
 */
void defect_buffer_gets(void)
{
    char buf[64];
    gets(buf);
}

/* flawfinder.buffer.strcpy (CWE-119) ----------------------------------------
 * strcpy() performs no length check on the source; oversized input overflows.
 */
void defect_buffer_strcpy(const char *src)
{
    char buf[64];
    strcpy(buf, src);
}

/* flawfinder.format.sprintf (CWE-134) ---------------------------------------
 * Passing a caller-controlled string as the format argument allows arbitrary
 * format specifiers to read or write memory.
 */
void defect_format_sprintf(const char *fmt)
{
    char buf[256];
    sprintf(buf, fmt);
}
