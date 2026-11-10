#define _GNU_SOURCE
/* Fuzzer for the wazuh OS_Regex engine (component-API harness).
 *
 * Threat model:
 * - Wazuh's detection pipeline matches attacker-influenced log messages and
 *   event strings against rules/decoders patterns through the hand-written
 *   os_regex engine (OS_Regex / OS_Match2 / OS_WordMatch). The matched
 *   string is attacker-controlled content; patterns also carry arbitrary
 *   bytes via custom rules and decoders. These entry points are the trust
 *   boundary for detection matching.
 * - A real finding here is a memory-safety violation (out-of-bounds
 *   read/write, use of uninitialized memory, per-iteration leak) or a
 *   pathological blowup in compile/match for arbitrary NUL-terminated
 *   pattern/string pairs.
 *
 * Harness contract (legitimate input): the engine consumes C strings, so
 * the fuzz input is split at the first NUL byte into `pattern` and `str`;
 * when no NUL exists the input is halved and both halves are terminated
 * explicitly. Every piece returned by OS_StrBreak is freed, so leaks are
 * never harness-owned.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex/os_regex.h"
#include "regex_op.h"

#define FZ_MAX_INPUT (64u * 1024u)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FZ_MAX_INPUT) {
        return 0;
    }

    /* Two C strings: pattern <NUL> str (halved when no NUL is present). */
    const uint8_t *sep = memchr(data, '\0', size - 1);
    size_t plen = sep ? (size_t) (sep - data) : size / 2;
    size_t slen = size - plen - (sep ? 1u : 0u);

    char *pattern = strndup((const char *) data, plen);
    char *str = strndup((const char *) data + plen + (sep ? 1u : 0u), slen);
    if (pattern == NULL || str == NULL) {
        free(pattern);
        free(str);
        return 0;
    }

    if (OS_Regex(pattern, str)) {
    }
    if (OS_Match2(pattern, str)) {
    }
    if (OS_WordMatch(pattern, str)) {
    }
    if (OS_StrIsNum(str)) {
    }
    (void) OS_StrHowClosedMatch(pattern, str);
    (void) OS_PRegex(str, pattern);

    /* Split on a delimiter taken from the input; the engine treats a
     * backslash-escaped delimiter specially, so that path is exercised. */
    char delimiter = (data[0] == '\0') ? ',' : (char) data[0];
    char **pieces = OS_StrBreak(delimiter, str, 8);
    if (pieces != NULL) {
        for (size_t i = 0; pieces[i] != NULL; i++) {
            free(pieces[i]);
        }
        free(pieces);
    }

    free(pattern);
    free(str);
    return 0;
}
