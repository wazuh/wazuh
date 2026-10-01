
#include "system.h"

#include <rpm/rpmmacro.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmts.h>

#include "rpmplugins.h"
#include <dlfcn.h>


#define STR1(x) #x
#define STR(x) STR1(x)

static rpmRC rpmpluginsCallInit(rpmPlugin plugin, rpmts ts);

struct rpmPlugin_s {
    char *name;
    char *opts;
    void *handle;
    void *priv;
    rpmPluginHooks hooks;
};

struct rpmPlugins_s {
    rpmPlugin *plugins;
    int count;
    rpmts ts;
};

static rpmPlugin rpmpluginsGetPlugin(rpmPlugins plugins, const char *name)
{
    int i;
    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	if (rstreq(plugin->name, name)) {
	    return plugin;
	}
    }
    return NULL;
}

int rpmpluginsPluginAdded(rpmPlugins plugins, const char *name)
{
    return (rpmpluginsGetPlugin(plugins, name) != NULL);
}

rpmPlugins rpmpluginsNew(rpmts ts)
{
    rpmPlugins plugins = (rpmPlugins)xcalloc(1, sizeof(*plugins));
    plugins->ts = ts;
    return plugins;
}

/* ASAN upstream recommends avoiding dlclose() */
static void mydlclose(void *handle)
{
#ifndef ENABLE_ASAN
    dlclose(handle);
#endif
}

static rpmPlugin rpmPluginNew(const char *name, const char *path,
			      const char *opts)
{
    rpmPlugin plugin = NULL;
    rpmPluginHooks hooks = NULL;
    char *error;
    char *hooks_name = NULL;

    void *handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
	rpmlog(RPMLOG_ERR, _("Failed to dlopen %s %s\n"), path, dlerror());
	return NULL;
    }

    /* make sure the plugin has the supported hooks flag */
    hooks_name = rstrscat(NULL, name, "_hooks", NULL);
    /* clear out any old errors that weren't fetched */
    dlerror();
    hooks = (rpmPluginHooks)dlsym(handle, hooks_name);
    if ((error = dlerror()) != NULL) {
	rpmlog(RPMLOG_ERR, _("Failed to resolve symbol %s: %s\n"),
	       hooks_name, error);
	mydlclose(handle);
    } else {
	plugin = (rpmPlugin)xcalloc(1, sizeof(*plugin));
	plugin->name = xstrdup(name);
	plugin->handle = handle;
	plugin->hooks = hooks;
	if (opts)
	    plugin->opts = xstrdup(opts);
    }
    free(hooks_name);

    return plugin;
}

static rpmPlugin rpmPluginFree(rpmPlugin plugin)
{
    if (plugin) {
	rpmPluginHooks hooks = plugin->hooks;
	if (hooks->cleanup)
	    hooks->cleanup(plugin);
	mydlclose(plugin->handle);
	free(plugin->name);
	free(plugin->opts);
	free(plugin);
    }
    return NULL;
}

const char *rpmPluginName(rpmPlugin plugin)
{
    return (plugin != NULL) ? plugin->name : NULL;
}

const char *rpmPluginOpts(rpmPlugin plugin)
{
    return (plugin != NULL) ? plugin->opts : NULL;
}

void * rpmPluginGetData(rpmPlugin plugin)
{
    return (plugin != NULL) ? plugin->priv : NULL;
}

void rpmPluginSetData(rpmPlugin plugin, void *data)
{
    if (plugin)
	plugin->priv = data;
}

rpmRC rpmpluginsAdd(rpmPlugins plugins, const char *name, const char *path,
		    const char *opts)
{
    rpmRC rc;
    rpmPlugin plugin = rpmPluginNew(name, path, opts);

    if (plugin == NULL)
	return RPMRC_FAIL;
    
    rc = rpmpluginsCallInit(plugin, plugins->ts);

    if (rc == RPMRC_OK) {
	plugins->plugins = xrealloc(plugins->plugins,
			    (plugins->count + 1) * sizeof(*plugins->plugins));
	plugins->plugins[plugins->count] = plugin;
	plugins->count++;
    } else {
	rpmPluginFree(plugin);
    }

    return rc;
}

rpmRC rpmpluginsAddPlugin(rpmPlugins plugins, const char *type, const char *name)
{
    char *path;
    char *options;
    rpmRC rc = RPMRC_FAIL;

    path = rpmExpand("%{?__", type, "_", name, "}", NULL);
    if (!path || rstreq(path, "")) {
	rpmlog(RPMLOG_DEBUG, _("Plugin %%__%s_%s not configured\n"),
	       type, name);
	rc = RPMRC_NOTFOUND;
	goto exit;
    }

    /* split the options from the path */
#define SKIPSPACE(s)    { while (*(s) &&  risspace(*(s))) (s)++; }
#define SKIPNONSPACE(s) { while (*(s) && !risspace(*(s))) (s)++; }
    options = path;
    SKIPNONSPACE(options);
    if (risspace(*options)) {
	*options = '\0';
	options++;
	SKIPSPACE(options);
    }
    if (*options == '\0') {
	options = NULL;
    }

    rc = rpmpluginsAdd(plugins, name, path, options);

  exit:
    _free(path);
    return rc;
}

rpmPlugins rpmpluginsFree(rpmPlugins plugins)
{
    if (plugins) {
	for (int i = 0; i < plugins->count; i++) {
	    rpmPlugin plugin = plugins->plugins[i];
	    rpmPluginFree(plugin);
	}
	plugins->plugins = _free(plugins->plugins);
	plugins->ts = NULL;
	_free(plugins);
    }

    return NULL;
}

#define RPMPLUGINS_GET_PLUGIN(name) \
	plugin = rpmpluginsGetPlugin(plugins, name); \
	if (plugin == NULL || plugin->handle == NULL) { \
		rpmlog(RPMLOG_ERR, _("Plugin %s not loaded\n"), name); \
		return RPMRC_FAIL; \
	}

/* Common define for all rpmpluginsCall* hook functions */
#define RPMPLUGINS_SET_HOOK_FUNC(hook) \
	rpmPluginHooks hooks = (plugin != NULL) ? plugin->hooks : NULL; \
	hookFunc = (hooks != NULL) ? hooks->hook : NULL; \
	if (hookFunc) { \
	    rpmlog(RPMLOG_DEBUG, "Plugin: calling hook %s in %s plugin\n", \
		   STR(hook), plugin->name); \
	}

static rpmRC rpmpluginsCallInit(rpmPlugin plugin, rpmts ts)
{
    rpmRC rc = RPMRC_OK;
    plugin_init_func hookFunc;
    RPMPLUGINS_SET_HOOK_FUNC(init);
    if (hookFunc) {
        rc = hookFunc(plugin, ts);
        if (rc != RPMRC_OK && rc != RPMRC_NOTFOUND)
            rpmlog(RPMLOG_ERR, "Plugin %s: hook init failed\n", plugin->name);
    }
    return rc;
}

rpmRC rpmpluginsCallTsmPre(rpmPlugins plugins, rpmts ts)
{
    plugin_tsm_pre_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(tsm_pre);
	if (hookFunc && hookFunc(plugin, ts) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook tsm_pre failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }

    return rc;
}

rpmRC rpmpluginsCallTsmPost(rpmPlugins plugins, rpmts ts, int res)
{
    plugin_tsm_post_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(tsm_post);
	if (hookFunc && hookFunc(plugin, ts, res) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_WARNING, "Plugin %s: hook tsm_post failed\n", plugin->name);
	}
    }

    return rc;
}

rpmRC rpmpluginsCallPsmPre(rpmPlugins plugins, rpmte te)
{
    plugin_psm_pre_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(psm_pre);
	if (hookFunc && hookFunc(plugin, te) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook psm_pre failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }

    return rc;
}

rpmRC rpmpluginsCallPsmPost(rpmPlugins plugins, rpmte te, int res)
{
    plugin_psm_post_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(psm_post);
	if (hookFunc && hookFunc(plugin, te, res) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_WARNING, "Plugin %s: hook psm_post failed\n", plugin->name);
	}
    }

    return rc;
}

rpmRC rpmpluginsCallScriptletPre(rpmPlugins plugins, const char *s_name, int type)
{
    plugin_scriptlet_pre_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(scriptlet_pre);
	if (hookFunc && hookFunc(plugin, s_name, type) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook scriplet_pre failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }

    return rc;
}

rpmRC rpmpluginsCallScriptletForkPost(rpmPlugins plugins, const char *path, int type)
{
    plugin_scriptlet_fork_post_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(scriptlet_fork_post);
	if (hookFunc && hookFunc(plugin, path, type) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook scriplet_fork_post failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }

    return rc;
}

rpmRC rpmpluginsCallScriptletPost(rpmPlugins plugins, const char *s_name, int type, int res)
{
    plugin_scriptlet_post_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(scriptlet_post);
	if (hookFunc && hookFunc(plugin, s_name, type, res) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_WARNING, "Plugin %s: hook scriplet_post failed\n", plugin->name);
	}
    }

    return rc;
}

static char *abspath(rpmfi fi, const char *path)
{
    if (*path == '/')
	return xstrdup(path);
    else
	return rstrscat(NULL, rpmfiDN(fi), path, NULL);
}

rpmRC rpmpluginsCallFsmFilePre(rpmPlugins plugins, rpmfi fi, const char *path,
			       mode_t file_mode, rpmFsmOp op)
{
    plugin_fsm_file_pre_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;
    char *apath = abspath(fi, path);

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(fsm_file_pre);
	if (hookFunc && hookFunc(plugin, fi, apath, file_mode, op) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook fsm_file_pre failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }
    free(apath);

    return rc;
}

rpmRC rpmpluginsCallFsmFilePost(rpmPlugins plugins, rpmfi fi, const char *path,
                                mode_t file_mode, rpmFsmOp op, int res)
{
    plugin_fsm_file_post_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;
    char *apath = abspath(fi, path);

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(fsm_file_post);
	if (hookFunc && hookFunc(plugin, fi, apath, file_mode, op, res) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_WARNING, "Plugin %s: hook fsm_file_post failed\n", plugin->name);
	}
    }
    free(apath);

    return rc;
}

rpmRC rpmpluginsCallFsmFilePrepare(rpmPlugins plugins, rpmfi fi,
				   int fd, const char *path, const char *dest,
				   mode_t file_mode, rpmFsmOp op)
{
    plugin_fsm_file_prepare_func hookFunc;
    int i;
    rpmRC rc = RPMRC_OK;
    char *apath = abspath(fi, path);

    for (i = 0; i < plugins->count; i++) {
	rpmPlugin plugin = plugins->plugins[i];
	RPMPLUGINS_SET_HOOK_FUNC(fsm_file_prepare);
	if (hookFunc && hookFunc(plugin, fi, fd, apath, dest, file_mode, op) == RPMRC_FAIL) {
	    rpmlog(RPMLOG_ERR, "Plugin %s: hook fsm_file_prepare failed\n", plugin->name);
	    rc = RPMRC_FAIL;
	}
    }
    free(apath);

    return rc;
}
