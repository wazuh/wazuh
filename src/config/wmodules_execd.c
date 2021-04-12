#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_execd.h"

int wm_execd_read(const OS_XML* xml, XML_NODE node, int modules, wmodule* module)
{
    if (module && !module->data) {
        module->context = &WM_EXECD_CONTEXT;
        module->tag     = strdup(module->context->name);
        //module->data    =
    }
    return ReadActiveResponses(xml, node, NULL);
}