/* Contract test for the <container_security> configuration parser.
 *
 * Drives the REAL parser (config/src/wmodules-container-instances.c) through
 * the REAL XML reader against XML fixtures, and asserts on the resulting
 * wm_container_instances_t. Standalone `make check`, no CMake, in the manner
 * of the contract tests under src/syscheckd/src/ebpf/tests/. */

#include "wmodules.h"
#include "wm_container_instances.h"

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
static wmodule* g_last_modules = NULL;

static void Check(int condition, const char* what)
{
    g_checks++;
    printf("  %-72s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition)
    {
        g_failures++;
    }
}

/* Parse one XML document and hand back the module config it produced. */
static wm_container_instances_t* ParseXml(const char* xml_text)
{
    static char path[] = "/tmp/ci_cfg_testXXXXXX";
    char tmp[] = "/tmp/ci_cfg_testXXXXXX";
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
    strcpy(path, tmp);

    OS_XML xml;
    if (OS_ReadXML(path, &xml) < 0)
    {
        unlink(path);
        return NULL;
    }

    xml_node** root = OS_GetElementsbyNode(&xml, NULL);
    wmodule* modules = NULL;

    for (int i = 0; root && root[i]; i++)
    {
        if (root[i]->element && strcmp(root[i]->element, "container_security") == 0)
        {
            Read_ContainerSecurity(&xml, root[i], &modules);
        }
    }

    OS_ClearNode(root);
    OS_ClearXML(&xml);
    unlink(path);

    g_last_modules = modules;

    for (wmodule* it = modules; it; it = it->next)
    {
        if (it->tag && strcmp(it->tag, "container-instances") == 0)
        {
            return (wm_container_instances_t*)it->data;
        }
    }

    return NULL;
}

/* The syscollector module as the last ParseXml() call left it, or NULL when the
 * parse never reached <container_security><syscollector>. */
static wm_sys_t* LastSyscollector(void)
{
    for (wmodule* it = g_last_modules; it; it = it->next)
    {
        if (it->tag && strcmp(it->tag, "syscollector") == 0)
        {
            return (wm_sys_t*)it->data;
        }
    }

    return NULL;
}

static void CaseDualRuntime(void)
{
    printf("case 1: one block per runtime enables dual-runtime monitoring\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances>"
        "    <enabled>yes</enabled><type>docker</type>"
        "    <socket_path>/run/d.sock</socket_path>"
        "  </container_instances>"
        "  <container_instances>"
        "    <enabled>yes</enabled><type>kubernetes</type>"
        "    <node_name>node-a</node_name>"
        "    <ownership_poll_interval>300</ownership_poll_interval>"
        "  </container_instances>"
        "</container_security>");

    Check(c != NULL, "configuration parsed");
    if (!c) return;
    Check(c->enabled == 1, "module enabled");
    Check(c->docker_present == 1, "docker source registered");
    Check(c->kubernetes_present == 1, "kubernetes source registered");
    Check(c->docker_socket_path && strcmp(c->docker_socket_path, "/run/d.sock") == 0, "docker socket_path read");
    Check(c->kubernetes.node_name && strcmp(c->kubernetes.node_name, "node-a") == 0, "kubernetes node_name read");
    Check(c->kubernetes.ownership_poll_interval == 300, "ownership_poll_interval read");
    Check(c->kubernetes.kubeconfig && strcmp(c->kubernetes.kubeconfig, WM_CONTAINER_INSTANCES_DEF_KUBECONFIG) == 0,
          "kubeconfig defaulted");
    Check(g_error_count == 0, "no errors");
}

static void CaseSingleRuntime(void)
{
    printf("case 2: a single docker block leaves kubernetes unregistered\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>yes</enabled><type>docker</type></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 1, "module enabled");
    if (!c) return;
    Check(c->docker_present == 1, "docker registered");
    Check(c->kubernetes_present == 0, "kubernetes NOT registered");
    Check(g_error_count == 0, "no errors");
}

static void CaseTrueIsAccepted(void)
{
    printf("case 3: <enabled>true</enabled> is accepted (the HLD spells it this way)\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>true</enabled><type>docker</type></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 1, "module enabled by 'true'");
    Check(c && c->docker_present == 1, "docker registered");
    Check(g_error_count == 0, "no errors");
}

static void CaseDisabledBlock(void)
{
    printf("case 4: a disabled block is not registered as a source\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>no</enabled><type>docker</type></container_instances>"
        "  <container_instances><enabled>yes</enabled><type>kubernetes</type></container_instances>"
        "</container_security>");

    Check(c && c->docker_present == 0, "disabled docker block NOT registered");
    Check(c && c->kubernetes_present == 1, "enabled kubernetes block registered");
    Check(c && c->enabled == 1, "module still enabled by the other block");
}

static void CaseAllDisabled(void)
{
    printf("case 5: every block disabled disables the module\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>no</enabled><type>docker</type></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 0, "module disabled");
    Check(log_contains("no enabled <container_instances> block"), "the reason names what is missing");
}

static void CaseMissingType(void)
{
    printf("case 6: a block without <type> is rejected, module disabled, agent not aborted\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>yes</enabled><socket_path>/run/d.sock</socket_path></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 0, "module disabled");
    Check(log_contains("missing its <type>"), "the error names the missing <type>");
}

static void CaseUnknownType(void)
{
    printf("case 7: an unknown <type> is rejected and both candidates are named\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>yes</enabled><type>podman</type></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 0, "module disabled");
    Check(log_contains("podman"), "the rejected value is quoted back");
    Check(log_contains("expected 'docker' or 'kubernetes'"), "the accepted values are named");
}

static void CaseDuplicateType(void)
{
    printf("case 8: two blocks of the same type are rejected (multi-socket is descoped)\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances><enabled>yes</enabled><type>docker</type></container_instances>"
        "  <container_instances><enabled>yes</enabled><type>docker</type></container_instances>"
        "</container_security>");

    Check(c && c->enabled == 0, "module disabled");
    Check(c && c->docker_present == 0, "the first block is unregistered too, not silently kept");
    Check(log_contains("Duplicate"), "the error says duplicate");
}

static void CaseOptionOrderIndependent(void)
{
    printf("case 9: <type> after its runtime's options still routes them\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances>"
        "    <node_name>node-z</node_name>"
        "    <type>kubernetes</type>"
        "    <enabled>yes</enabled>"
        "  </container_instances>"
        "</container_security>");

    Check(c && c->kubernetes_present == 1, "kubernetes registered");
    Check(c && c->kubernetes.node_name && strcmp(c->kubernetes.node_name, "node-z") == 0,
          "node_name read although it preceded <type>");
}

static void CaseWrongRuntimeOption(void)
{
    printf("case 10: a kubernetes option inside a docker block warns and is ignored\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances>"
        "    <enabled>yes</enabled><type>docker</type>"
        "    <node_name>nope</node_name>"
        "  </container_instances>"
        "</container_security>");

    Check(c && c->docker_present == 1, "docker still registered");
    Check(c && c->kubernetes.node_name == NULL, "the stray option did not leak into kubernetes");
    Check(g_warn_count > 0, "a warning was emitted");
    Check(log_contains("node_name"), "the warning names the option");
}

static void CasePollIntervalClamped(void)
{
    printf("case 11: ownership_poll_interval below the minimum is clamped, not rejected\n");
    log_reset();
    wm_container_instances_t* c = ParseXml(
        "<container_security>"
        "  <container_instances>"
        "    <enabled>yes</enabled><type>kubernetes</type>"
        "    <ownership_poll_interval>5</ownership_poll_interval>"
        "  </container_instances>"
        "</container_security>");

    Check(c && c->kubernetes.ownership_poll_interval == WM_CONTAINER_INSTANCES_MIN_POLL_INTERVAL,
          "clamped to the minimum");
    Check(c && c->enabled == 1, "module still enabled");
}

static void CaseEmptyRoot(void)
{
    printf("case 12: <container_security> with no blocks disables the module\n");
    log_reset();
    wm_container_instances_t* c = ParseXml("<container_security></container_security>");
    Check(c == NULL || c->enabled == 0, "module disabled");
}

static void CaseSyscollectorBlock(void)
{
    printf("case 13: <syscollector> configures the container inventory pass\n");
    log_reset();
    ParseXml("<container_security>"
             "  <container_instances><type>docker</type></container_instances>"
             "  <syscollector><enabled>yes</enabled><interval>5m</interval></syscollector>"
             "</container_security>");
    wm_sys_t* sys = LastSyscollector();
    Check(sys != NULL, "syscollector module registered");
    Check(sys && sys->flags.container_baseline == 1, "container baseline enabled");
    Check(sys && sys->container_baseline_interval == 300, "interval parsed as 5m");
    Check(sys && sys->interval == WM_SYSCOLLECTOR_DEFAULT_INTERVAL, "host interval left at its default");
    Check(g_error_count == 0, "no errors");
}

static void CaseSyscollectorDefaultsOn(void)
{
    printf("case 14: writing <syscollector> is the opt-in\n");
    log_reset();
    ParseXml("<container_security>"
             "  <container_instances><type>docker</type></container_instances>"
             "  <syscollector></syscollector>"
             "</container_security>");
    wm_sys_t* sys = LastSyscollector();
    Check(sys && sys->flags.container_baseline == 1, "enabled without an explicit <enabled>");
}

static void CaseSyscollectorAbsent(void)
{
    printf("case 15: no <syscollector> block leaves container inventory off\n");
    log_reset();
    ParseXml("<container_security>"
             "  <container_instances><type>docker</type></container_instances>"
             "</container_security>");
    Check(LastSyscollector() == NULL, "syscollector module not registered at all");
}

static void CaseSyscollectorDisabled(void)
{
    printf("case 16: <syscollector><enabled>no</enabled> keeps the pass off\n");
    log_reset();
    ParseXml("<container_security>"
             "  <container_instances><type>docker</type></container_instances>"
             "  <syscollector><enabled>no</enabled><interval>10m</interval></syscollector>"
             "</container_security>");
    wm_sys_t* sys = LastSyscollector();
    Check(sys && sys->flags.container_baseline == 0, "container baseline disabled");
    Check(sys && sys->container_baseline_interval == 600, "interval still parsed");
}

static void CaseSyscollectorBadInterval(void)
{
    printf("case 17: a malformed <interval> fails closed\n");
    log_reset();
    ParseXml("<container_security>"
             "  <container_instances><type>docker</type></container_instances>"
             "  <syscollector><interval>5x</interval></syscollector>"
             "</container_security>");
    wm_sys_t* sys = LastSyscollector();
    Check(sys && sys->flags.container_baseline == 0, "container inventory disabled");
    Check(g_error_count > 0, "reported as an error");
}

static void CaseSyscheckSiblingIgnored(void)
{
    printf("case 18: syscheckd's half of the block is stepped over silently\n");
    log_reset();
    wm_container_instances_t* c = ParseXml("<container_security>"
                                           "  <container_instances><type>docker</type></container_instances>"
                                           "  <syscheck><enabled>yes</enabled>"
                                           "    <directories>/data</directories></syscheck>"
                                           "</container_security>");
    Check(c && c->enabled == 1, "module still enabled");
    Check(g_warn_count == 0, "no warning about <syscheck>");
    Check(!log_contains("Unknown option"), "not reported as an unknown option");
}

/* Both options moved under <container_security><syscollector>. Falling through to
 * the generic unknown-element branch would abort modulesd's config read with
 * "No such tag", which says nothing about where they went. */
static void CaseRetiredSyscollectorOptions(void)
{
    printf("case 19: the retired syscollector options name their replacement\n");

    const char* retired[] = {"container_baseline", "container_baseline_interval"};

    for (int k = 0; k < 2; k++)
    {
        log_reset();

        char tmp[] = "/tmp/ci_sys_retiredXXXXXX";
        const int fd = mkstemp(tmp);
        char doc[256];

        snprintf(doc, sizeof(doc), "<wodle name=\"syscollector\"><%s>yes</%s></wodle>", retired[k], retired[k]);

        if (fd < 0 || write(fd, doc, strlen(doc)) < 0)
        {
            Check(0, "fixture written");
            return;
        }

        close(fd);

        OS_XML xml;

        if (OS_ReadXML(tmp, &xml) < 0)
        {
            unlink(tmp);
            Check(0, "fixture parsed");
            return;
        }

        xml_node** root = OS_GetElementsbyNode(&xml, NULL);
        xml_node** children = OS_GetElementsbyNode(&xml, root[0]);
        wmodule module;

        memset(&module, 0, sizeof(module));

        const int rc = wm_syscollector_read(&xml, children, &module);

        OS_ClearNode(children);
        OS_ClearNode(root);
        OS_ClearXML(&xml);
        unlink(tmp);

        /* The full rendered string, not a substring: unit_tests/config/test_wmodules-config.c
         * matches it with expect_string(), so a reword here has to fail here too. */
        char expected[256];

        snprintf(expected,
                 sizeof(expected),
                 "'%s' has moved to <container_security><syscollector> and is no longer read at module "
                 "'syscollector'.",
                 retired[k]);

        Check(rc < 0, "the configuration is rejected");
        Check(log_contains(expected), "the exact message the cmocka test expects");
    }
}

int main(void)
{
    printf("<container_security> configuration parser contract\n\n");

    CaseDualRuntime();
    CaseSingleRuntime();
    CaseTrueIsAccepted();
    CaseDisabledBlock();
    CaseAllDisabled();
    CaseMissingType();
    CaseUnknownType();
    CaseDuplicateType();
    CaseOptionOrderIndependent();
    CaseWrongRuntimeOption();
    CasePollIntervalClamped();
    CaseEmptyRoot();
    CaseSyscollectorBlock();
    CaseSyscollectorDefaultsOn();
    CaseSyscollectorAbsent();
    CaseSyscollectorDisabled();
    CaseSyscollectorBadInterval();
    CaseSyscheckSiblingIgnored();
    CaseRetiredSyscollectorOptions();

    printf("\n%d check(s), %d failure(s)\n", g_checks, g_failures);
    if (g_failures)
    {
        printf("\nFAILURES\n");
        return 1;
    }
    printf("\nALL OK\n");
    return 0;
}
