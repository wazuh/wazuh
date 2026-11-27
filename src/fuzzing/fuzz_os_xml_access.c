#define _GNU_SOURCE
/* Fuzzer for the wazuh XML access API (os_xml_access + parser error paths).
 *
 * Threat model:
 * - Wazuh agents and the manager consume XML from untrusted sources:
 *   manager-pushed shared configuration, decoders/rules shipped as XML,
 *   and command output wrapped in XML. After parsing, lookups go through
 *   the access API (OS_GetOneContentforElement, OS_GetContents,
 *   OS_GetAttributes, OS_GetAttributeContent, OS_ElementExist, ...) with
 *   element path expressions. Both the document and the queried paths are
 *   attacker-relevant inputs crossing the trust boundary.
 * - A real finding is a memory-safety violation or a pathological blowup
 *   while parsing attacker-controlled XML, or while resolving attacker-
 *   influenced path expressions against it.
 *
 * Harness contract (legitimate input): OS_ReadXMLString() takes a
 * NUL-terminated document; element paths are NULL-terminated arrays of
 * components; attributes are C strings. Input layout:
 *   <xml document> NUL <path, '/'-separated> [NUL <attribute name>]
 * Every string is copied and NUL-terminated, every returned list is fully
 * freed, and OS_ClearXML() always runs, so leaks are never harness-owned.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os_xml/os_xml.h"

#define FZ_MAX_INPUT (32u * 1024u)
#define FZ_MAX_COMPONENTS 8u

static void
free_string_list(char **list)
{
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; list[i] != NULL; i++) {
        free(list[i]);
    }
    free(list);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4 || size > FZ_MAX_INPUT) {
        return 0;
    }

    /* Layout: <xml> NUL <path> [NUL <attr>] */
    const uint8_t *sep1 = memchr(data, '\0', size - 1);
    if (sep1 == NULL) {
        return 0;
    }
    size_t xml_len = (size_t) (sep1 - data);

    const uint8_t *rest = sep1 + 1;
    size_t rest_len = size - xml_len - 1;
    const uint8_t *sep2 = memchr(rest, '\0', rest_len);
    size_t path_len = sep2 ? (size_t) (sep2 - rest) : rest_len;
    size_t attr_len = sep2 ? rest_len - path_len - 1u : 0u;

    char *xml_doc = strndup((const char *) data, xml_len);
    char *path = strndup((const char *) rest, path_len);
    char *attr =
        strndup((const char *) rest + path_len + (sep2 ? 1u : 0u), attr_len);
    if (xml_doc == NULL || path == NULL || attr == NULL) {
        free(xml_doc);
        free(path);
        free(attr);
        return 0;
    }

    /* NULL-terminated component array built from the '/'-separated path. */
    char *components[FZ_MAX_COMPONENTS + 1];
    const char *element_name[FZ_MAX_COMPONENTS + 1];
    memset(components, 0, sizeof(components));
    size_t n = 0;
    const char *cursor = path;
    while (n < FZ_MAX_COMPONENTS && cursor != NULL) {
        const char *slash = strchr(cursor, '/');
        components[n] =
            strndup(cursor, slash ? (size_t) (slash - cursor) : strlen(cursor));
        if (components[n] == NULL) {
            break;
        }
        element_name[n] = components[n];
        n++;
        cursor = slash ? slash + 1 : NULL;
    }
    element_name[n] = NULL;

    OS_XML lxml;
    if (OS_ReadXMLString(xml_doc, &lxml) >= 0 && n > 0) {
        (void) OS_ElementExist(&lxml, element_name);
        (void) OS_RootElementExist(&lxml, components[0]);

        free_string_list(OS_GetAttributes(&lxml, element_name));
        free_string_list(OS_GetElements(&lxml, element_name));
        free_string_list(OS_GetElementContent(&lxml, element_name));
        free_string_list(OS_GetContents(&lxml, element_name));

        char *one = OS_GetOneContentforElement(&lxml, element_name);
        free(one);

        char *attr_content = OS_GetAttributeContent(&lxml, element_name, attr);
        free(attr_content);
    }
    OS_ClearXML(&lxml);

    for (size_t i = 0; i < n; i++) {
        free(components[i]);
    }
    free(xml_doc);
    free(path);
    free(attr);
    return 0;
}
