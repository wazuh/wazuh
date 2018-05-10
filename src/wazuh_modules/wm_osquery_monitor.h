#include "../headers/shared.h"

#ifndef WM_OSQUERYMONITOR
#define WM_OSQUERYMONITOR

#define WM_OSQUERYMONITOR_LOGTAG ARGV0 ":osquery"

extern const wm_context WM_OSQUERYMONITOR_CONTEXT;

typedef struct wm_osquery_monitor_t {
   char* bin_path;
   char* log_path;
   char* config_path;
   int disable;
} wm_osquery_monitor_t;

int wm_osquery_monitor_read(xml_node **nodes, wmodule *module);

#endif