#define _GNU_SOURCE
/* Fuzzer for the wazuh shared string utilities (shared/src/string_op.c).
 *
 * Threat model:
 * - These helpers post-process attacker-influenced strings all over wazuh:
 *   log fields, decoded event values, shell commands built from event data
 *   (os_shell_escape), numeric fields (w_remove_zero_dec), group lists
 *   (wstr_delete_repeated_groups), tokenisers and escape/unescape rounds.
 *   Malformed or adversarial strings reach them through the event pipeline.
 * - A real finding is a memory-safety violation (OOB read/write, overflowed
 *   fixed buffer, per-iteration leak) or a pathological blowup for
 *   arbitrary NUL-terminated inputs.
 *
 * Harness contract (legitimate input): all functions take C strings and
 * caller-writable buffers. Documented preconditions are enforced:
 * wstr_replace() is skipped for an empty search string and
 * w_strtok_r_str_delim() for an empty delimiter (callers never pass those).
 * Every returned buffer is freed and in-place helpers run on private copies,
 * so leaks are never harness-owned.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "string_op.h"

#define FZ_MAX_INPUT (32u * 1024u)
#define FZ_SUB_DEST 4096u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 6 || size > FZ_MAX_INPUT) {
        return 0;
    }

    /* Layout: <str1> NUL <str2> NUL <3 flag bytes> */
    const uint8_t *sep1 = memchr(data, '\0', size - 1);
    if (sep1 == NULL) {
        return 0;
    }
    size_t s1_len = (size_t) (sep1 - data);

    const uint8_t *rest = sep1 + 1;
    size_t rest_len = size - s1_len - 1u;
    if (rest_len < 4u) {
        return 0;
    }
    const uint8_t *sep2 = memchr(rest, '\0', rest_len - 1u);
    size_t s2_len = sep2 ? (size_t) (sep2 - rest) : rest_len - 3u;
    if (s2_len >= rest_len - 3u + 1u) {
        return 0;
    }
    const uint8_t *tail = rest + rest_len - 3u;

    char *s1 = strndup((const char *) data, s1_len);
    char *s2 = strndup((const char *) rest, s2_len);
    if (s1 == NULL || s2 == NULL) {
        free(s1);
        free(s2);
        return 0;
    }

    char ch1 = tail[0] ? (char) tail[0] : ' ';
    char ch2 = tail[1] ? (char) tail[1] : ',';
    char ch3 = tail[2] ? (char) tail[2] : '\\';
    size_t len1 = strlen(s1);

    /* In-place helpers on a private copy. */
    char *work = strndup(s1, len1);
    if (work != NULL) {
        os_trimcrlf(work);
        w_strtrim(work);
        free(work);
    }

    char *stripped = os_strip_char(s1, ch1);
    free(stripped);

    char *escaped = os_shell_escape(s1);
    free(escaped);

    (void) os_strcnt(s1, ch1);

    char *filtered = filter_special_chars(s1);
    free(filtered);

    if (s2[0] != '\0') {
        char *replaced = wstr_replace(s1, s2, s2);
        free(replaced);
    }

    /* wstr_chr_escape() is a strchr-style locator: the result points into
       the input (or is NULL) and must not be freed. */
    (void) wstr_chr_escape(s1, ch1, ch2);

    char *esc_dst = calloc(2u * len1 + 8u, 1u);
    if (esc_dst != NULL) {
        (void) wstr_escape(esc_dst, 2u * len1 + 8u, s1, ch2, ch1);
        (void) wstr_unescape(esc_dst, 2u * len1 + 8u, s1, ch2);
        free(esc_dst);
    }

    char *cat = NULL;
    if (wm_strcat(&cat, s2, ch1) == 0) {
        free(cat);
    }

    char *work2 = strndup(s1, len1);
    if (work2 != NULL) {
        (void) wstr_end(work2, s2);
        free(work2);
    }

    const char *haystack[2] = { s2, NULL };
    (void) w_str_in_array(s1, haystack);

    char *groups = wstr_delete_repeated_groups(s1);
    free(groups);

    char *num = strndup(s2, s2_len);
    if (num != NULL) {
        w_remove_zero_dec(num);
        free(num);
    }

    char sub[FZ_SUB_DEST];
    size_t position = (size_t) ch1 % (len1 + 1u);
    (void) os_substr(sub, s1, position, (ssize_t) (ch2 ? (ch2 % 64u) + 1u : 8u));

    if (s2[0] != '\0') {
        char *remaining = strndup(s1, len1);
        if (remaining != NULL) {
            /* w_strtok_r_str_delim() advances *remaining_str into the
               buffer; the caller frees the original base pointer. */
            char *base = remaining;
            (void) w_strtok_r_str_delim(s2, &remaining);
            free(base);
        }
    }

    free(s1);
    free(s2);
    return 0;
}
