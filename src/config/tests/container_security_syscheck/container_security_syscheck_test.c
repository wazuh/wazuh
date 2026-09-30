/* Contract test for the <container_security><syscheck> configuration parser.
 *
 * Drives the REAL parser (config/src/container-security-syscheck.c) through the
 * REAL XML reader against XML fixtures, and asserts on the resulting
 * syscheck_config. Standalone `make check`, no CMake, matching
 * ../container_security/ which covers the modulesd half of the same section. */

#include "shared.h"
#include "config.h"
#include "syscheck-config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void log_reset(void);
int log_contains(const char* needle);
void log_dump(void);
extern int g_error_count;
extern int g_warn_count;

static int g_failures = 0;
static int g_checks = 0;

static syscheck_config g_syscheck;

static void Check(int condition, const char* what)
{
    g_checks++;
    printf("  %-72s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition)
    {
        g_failures++;
    }
}

/* Parse one XML document into a fresh syscheck_config. */
static syscheck_config* ParseXml(const char* xml_text)
{
    char tmp[] = "/tmp/cs_syscheck_testXXXXXX";
    const int fd = mkstemp(tmp);

    if (fd < 0)
    {
        return NULL;
    }

    if (write(fd, xml_text, strlen(xml_text)) < 0)
    {
        close(fd);
        return NULL;
    }

    close(fd);

    memset(&g_syscheck, 0, sizeof(g_syscheck));

    if (initialize_syscheck_configuration(&g_syscheck) != 0)
    {
        unlink(tmp);
        return NULL;
    }

    OS_XML xml;

    if (OS_ReadXML(tmp, &xml) < 0)
    {
        unlink(tmp);
        return NULL;
    }

    xml_node** root = OS_GetElementsbyNode(&xml, NULL);

    for (int i = 0; root && root[i]; i++)
    {
        if (root[i]->element && strcmp(root[i]->element, "container_security") == 0)
        {
            Read_ContainerSecuritySyscheck(&xml, root[i], &g_syscheck);
        }
    }

    OS_ClearNode(root);
    OS_ClearXML(&xml);
    unlink(tmp);

    return &g_syscheck;
}

static size_t CountDirs(const syscheck_config* cfg)
{
    size_t count = 0U;

    for (OSListNode* it = OSList_GetFirstNode(cfg->container_directories); it != NULL;
         it = OSList_GetNext(cfg->container_directories, it))
    {
        count++;
    }

    return count;
}

/* The entry for `path` scoped to `name` (NULL meaning the catch-all entry). */
static const directory_t* FindDir(const syscheck_config* cfg, const char* path, const char* name)
{
    for (OSListNode* it = OSList_GetFirstNode(cfg->container_directories); it != NULL;
         it = OSList_GetNext(cfg->container_directories, it))
    {
        const directory_t* dir = (const directory_t*)it->data;

        if (dir == NULL || dir->path == NULL || strcmp(dir->path, path) != 0)
        {
            continue;
        }

        if (name == NULL && dir->container.name == NULL)
        {
            return dir;
        }

        if (name != NULL && dir->container.name != NULL && strcmp(dir->container.name, name) == 0)
        {
            return dir;
        }
    }

    return NULL;
}

static void CaseBlockEnablesByDefault(void)
{
    printf("case 1: writing <syscheck> is the opt-in\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories>/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && c->container_enabled == 1, "enabled without an explicit <enabled>");
    Check(c && CountDirs(c) == 1, "one container directory registered");
    Check(c && FindDir(c, "/data", NULL) != NULL, "/data registered with no selector");
    Check(c && OSList_GetFirstNode(c->directories) == NULL, "host directory list untouched");
    Check(g_error_count == 0, "no errors");
}

static void CaseBlockAbsent(void)
{
    printf("case 2: no <syscheck> block leaves container file monitoring off\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security>"
                                  "  <container_instances><type>docker</type></container_instances>"
                                  "</container_security>");
    Check(c && c->container_enabled == 0, "container_enabled stays 0");
    Check(c && CountDirs(c) == 0, "no container directories");
    Check(g_warn_count == 0, "modulesd's half is stepped over silently");
}

static void CaseDisabledKeepsDirectories(void)
{
    printf("case 3: <enabled>no</enabled> is an off switch, not a delete\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <enabled>no</enabled>"
                                  "  <directories>/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && c->container_enabled == 0, "disabled");
    Check(c && CountDirs(c) == 1, "the directory is still parsed and kept");
}

static void CaseTrueIsAccepted(void)
{
    printf("case 4: <enabled>true</enabled> is accepted, as it is on the modulesd half\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <enabled>true</enabled>"
                                  "  <directories>/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && c->container_enabled == 1, "enabled");
    Check(g_error_count == 0, "no errors");
}

static void CaseBadEnabledFailsClosed(void)
{
    printf("case 5: a malformed <enabled> disables rather than aborting\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <enabled>maybe</enabled>"
                                  "  <directories>/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && c->container_enabled == 0, "disabled");
    Check(g_error_count > 0, "reported as an error");
}

/* The reason container entries live in their own list: fim_insert_directory()
 * keys on the bare path, so in syscheck->directories the second of these would
 * have replaced the first. */
static void CaseSamePathTwoContainers(void)
{
    printf("case 6: the same path scoped to two containers is two entries\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories container_name=\"A\">/data</directories>"
                                  "  <directories container_name=\"B\">/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 2, "both entries survive");
    Check(c && FindDir(c, "/data", "A") != NULL, "the entry for A is present");
    Check(c && FindDir(c, "/data", "B") != NULL, "the entry for B is present");
}

static void CaseSamePathSameSelector(void)
{
    printf("case 7: the same path and the same selector is one entry, last wins\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories container_name=\"A\" recursion_level=\"1\">/data</directories>"
                                  "  <directories container_name=\"A\" recursion_level=\"4\">/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 1, "one entry");
    const directory_t* dir = c ? FindDir(c, "/data", "A") : NULL;
    Check(dir && dir->recursion_level == 4, "the later entry won");
}

static void CaseCatchAllAndScopedCoexist(void)
{
    printf("case 8: a scoped entry and a catch-all for the same path coexist\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories>/data</directories>"
                                  "  <directories container_name=\"A\">/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 2, "both entries survive");
    Check(c && FindDir(c, "/data", NULL) != NULL, "the catch-all is present");
}

static void CaseWildcardRejected(void)
{
    printf("case 9: a wildcard cannot be expanded from the host and is rejected\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories>/data/*</directories>"
                                  "  <directories>/etc</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 1, "only the literal path registered");
    Check(c && FindDir(c, "/etc", NULL) != NULL, "the good entry still registered");
    Check(log_contains("Wildcards are not supported"), "the wildcard is named in the warning");
}

static void CaseTraversalRejected(void)
{
    printf("case 10: a path with '..' would escape the container rootfs\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories>/data/../../etc</directories>"
                                  "  <directories>relative/path</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 0, "neither entry registered");
    Check(log_contains("absolute path without"), "the reason is stated");
}

static void CaseHostOnlyAttributesRefused(void)
{
    printf("case 11: realtime/whodata/follow_symbolic_link do not apply here\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories realtime=\"yes\" whodata=\"yes\" "
                                  "follow_symbolic_link=\"yes\">/data</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 1, "the entry is still registered");
    const directory_t* dir = c ? FindDir(c, "/data", NULL) : NULL;
    Check(dir && (dir->options & REALTIME_ACTIVE) == 0, "realtime not applied");
    Check(dir && (dir->options & WHODATA_ACTIVE) == 0, "whodata not applied");
    Check(dir && (dir->options & CHECK_FOLLOW) == 0, "follow_symbolic_link not applied");
    Check(g_warn_count >= 3, "each one warned about");
}

static void CaseCheckAttributesShared(void)
{
    printf("case 12: check_* attributes mean the same as in <syscheck>\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories check_sha256sum=\"no\" check_md5sum=\"no\">/data</directories>"
                                  "</syscheck></container_security>");
    const directory_t* dir = c ? FindDir(c, "/data", NULL) : NULL;
    Check(dir != NULL, "entry registered");
    Check(dir && (dir->options & CHECK_SHA256SUM) == 0, "sha256 turned off");
    Check(dir && (dir->options & CHECK_MD5SUM) == 0, "md5 turned off");
    Check(dir && (dir->options & CHECK_SHA1SUM) != 0, "sha1 left on by default");
    Check(dir && (dir->options & CHECK_SIZE) != 0, "check_all defaults still applied");
}

static void CaseTrailingSeparatorNormalised(void)
{
    printf("case 13: a trailing separator is not a second entry\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories>/data</directories>"
                                  "  <directories>/data/</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 1, "one entry");
}

static void CaseCommaSeparatedPaths(void)
{
    printf("case 14: one element may carry several comma-separated paths\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <directories container_name=\"A\">/data,/var/log</directories>"
                                  "</syscheck></container_security>");
    Check(c && CountDirs(c) == 2, "both paths registered");
    Check(c && FindDir(c, "/var/log", "A") != NULL, "the selector applies to each path");
}

static void CaseUnknownChildWarns(void)
{
    printf("case 15: an unknown child of <syscheck> is named\n");
    log_reset();
    ParseXml("<container_security><syscheck>"
             "  <frequency>300</frequency>"
             "  <directories>/data</directories>"
             "</syscheck></container_security>");
    Check(log_contains("frequency"), "the unknown element is quoted back");
    Check(g_warn_count > 0, "a warning was emitted");
}

static void CaseEnabledWithoutDirectories(void)
{
    printf("case 16: enabled with nothing to watch says so\n");
    log_reset();
    syscheck_config* c = ParseXml("<container_security><syscheck>"
                                  "  <enabled>yes</enabled>"
                                  "</syscheck></container_security>");
    Check(c && c->container_enabled == 1, "enabled");
    Check(log_contains("nothing to watch"), "the operator is told");
}

/* tags="container" used to be the container selector. Breaking it outright would
 * otherwise be completely silent: the entry still parses, it just stops meaning
 * what it meant. */
static void CaseRetiredContainerTagWarns(void)
{
    printf("case 17: tags=\"container\" in <syscheck> is called out as retired\n");
    log_reset();

    char tmp[] = "/tmp/cs_syscheck_tagXXXXXX";
    const int fd = mkstemp(tmp);
    const char* doc = "<syscheck><directories tags=\"container,prod\">/etc</directories></syscheck>";

    if (fd < 0 || write(fd, doc, strlen(doc)) < 0)
    {
        Check(0, "fixture written");
        return;
    }

    close(fd);

    memset(&g_syscheck, 0, sizeof(g_syscheck));
    initialize_syscheck_configuration(&g_syscheck);

    OS_XML xml;

    if (OS_ReadXML(tmp, &xml) < 0)
    {
        unlink(tmp);
        Check(0, "fixture parsed");
        return;
    }

    xml_node** root = OS_GetElementsbyNode(&xml, NULL);
    xml_node** children = OS_GetElementsbyNode(&xml, root[0]);

    Read_Syscheck(&xml, children, &g_syscheck, NULL);

    OS_ClearNode(children);
    OS_ClearNode(root);
    OS_ClearXML(&xml);
    unlink(tmp);

    Check(OSList_GetFirstNode(g_syscheck.directories) != NULL, "the entry is still a host directory");
    Check(CountDirs(&g_syscheck) == 0, "but it selects no container");
    Check(log_contains("no longer scopes"), "the operator is told it stopped scoping");
    Check(log_contains("<container_security>"), "and where it moved to");
}

int main(void)
{
    printf("<container_security><syscheck> configuration parser contract\n\n");

    CaseBlockEnablesByDefault();
    CaseBlockAbsent();
    CaseDisabledKeepsDirectories();
    CaseTrueIsAccepted();
    CaseBadEnabledFailsClosed();
    CaseSamePathTwoContainers();
    CaseSamePathSameSelector();
    CaseCatchAllAndScopedCoexist();
    CaseWildcardRejected();
    CaseTraversalRejected();
    CaseHostOnlyAttributesRefused();
    CaseCheckAttributesShared();
    CaseTrailingSeparatorNormalised();
    CaseCommaSeparatedPaths();
    CaseUnknownChildWarns();
    CaseEnabledWithoutDirectories();
    CaseRetiredContainerTagWarns();

    printf("\n%d check(s), %d failure(s)\n", g_checks, g_failures);

    if (g_failures)
    {
        printf("\nFAILURES\n");
        log_dump();
        return 1;
    }

    printf("\nALL OK\n");
    return 0;
}
