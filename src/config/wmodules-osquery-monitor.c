#include "wazuh_modules/wmodules.h"


static const char *XML_DISABLED = "disabled";
static const char *XML_BINPATH = "binpath";
static const char *XML_LOGPATH = "logpath";

//Función de lectura
int wm_osquery_monitor_read(xml_node **nodes, wmodule *module)
{
    unsigned int i;
    wm_osquery_monitor_t *osquery_monitor;

    os_calloc(1, sizeof(wm_osquery_monitor_t), osquery_monitor);
    osquery_monitor->bin_path = NULL;
    osquery_monitor->log_path = NULL;
    int disable = 1;
    module->context = &WM_OSQUERYMONITOR_CONTEXT;
    module->data = osquery_monitor;

    for(i = 0; nodes[i]; i++)
    {

        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_DISABLED))
        {
            if (!strcmp(nodes[i]->content, "yes"))
                osquery_monitor->disable = 1;
            else if (!strcmp(nodes[i]->content, "no"))
            {
                osquery_monitor->disable = 0;
            }
            else
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSQUERYMONITOR_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if(!strcmp(nodes[i]->element, XML_BINPATH))
        {
         
           osquery_monitor->bin_path = strdup(nodes[i]->content);
           
        }
        else if(!strcmp(nodes[i]->element, XML_LOGPATH))
        {
            if(fopen (nodes[i]->content, "w+"))  //CHECK IF FILE EXISTS
            {
                osquery_monitor->log_path = strdup(nodes[i]->content);
                mdebug2("LOGPATH LEIDO: %s", osquery_monitor->log_path);
            }
            else
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_LOGPATH, WM_OSQUERYMONITOR_CONTEXT.name);
                return OS_INVALID;
            }
        }

    }
    return 0;
}