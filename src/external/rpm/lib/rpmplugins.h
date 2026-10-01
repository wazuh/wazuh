#ifndef _PLUGINS_H
#define _PLUGINS_H

#include <rpm/rpmtypes.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmplugin.h>

/** \ingroup rpmplugins
 * Create a new plugins structure
 * @param ts		transaction set
 * @return		new plugin structure
 */
RPM_GNUC_INTERNAL
rpmPlugins rpmpluginsNew(rpmts ts);

/** \ingroup rpmplugins
 * Destroy a plugins structure
 * @param plugins	plugins structure to destroy
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
rpmPlugins rpmpluginsFree(rpmPlugins plugins);

/** \ingroup rpmplugins
 * Add and open a plugin
 * @param plugins	plugins structure to add a plugin to
 * @param name		name to access plugin
 * @param path		path of plugin to open
 * @param opts		options to pass to the plugin
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsAdd(rpmPlugins plugins, const char *name, const char *path, const char *opts);

/** \ingroup rpmplugins
 * Add and open a rpm plugin
 * @param plugins	plugins structure to add a plugin to
 * @param type     type of plugin
 * @param name		name of plugin
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsAddPlugin(rpmPlugins plugins, const char *type, const char *name);

/** \ingroup rpmplugins
 * Determine if a plugin has been added already
 * @param plugins	plugins structure
 * @param name		name of plugin to check
 * @return		1 if plugin name has already been added, 0 otherwise
 */
RPM_GNUC_INTERNAL
int rpmpluginsPluginAdded(rpmPlugins plugins, const char *name);

/** \ingroup rpmplugins
 * Call the pre transaction plugin hook
 * @param plugins	plugins structure
 * @param ts		processed transaction
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallTsmPre(rpmPlugins plugins, rpmts ts);

/** \ingroup rpmplugins
 * Call the post transaction plugin hook
 * @param plugins	plugins structure
 * @param ts		processed transaction
 * @param res		transaction result code
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallTsmPost(rpmPlugins plugins, rpmts ts, int res);

/** \ingroup rpmplugins
 * Call the pre transaction element plugin hook
 * @param plugins	plugins structure
 * @param te		processed transaction element
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallPsmPre(rpmPlugins plugins, rpmte te);

/** \ingroup rpmplugins
 * Call the post transaction element plugin hook
 * @param plugins	plugins structure
 * @param te		processed transaction element
 * @param res		transaction element result code
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallPsmPost(rpmPlugins plugins, rpmte te, int res);

/** \ingroup rpmplugins
 * Call the pre scriptlet execution plugin hook
 * @param plugins	plugins structure
 * @param s_name	scriptlet name
 * @param type		indicates the scriptlet execution flow, see rpmScriptletExecutionFlow
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallScriptletPre(rpmPlugins plugins, const char *s_name, int type);

/** \ingroup rpmplugins
 * Call the post fork scriptlet plugin hook.
 * @param plugins	plugins structure
 * @param path		scriptlet path
 * @param type		indicates the scriptlet execution flow, see rpmScriptletExecutionFlow
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallScriptletForkPost(rpmPlugins plugins, const char *path, int type);

/** \ingroup rpmplugins
 * Call the post scriptlet execution plugin hook
 * @param plugins	plugins structure
 * @param s_name	scriptlet name
 * @param type		indicates the scriptlet execution flow, see rpmScriptletExecutionFlow
 * @param res		scriptlet execution result code
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallScriptletPost(rpmPlugins plugins, const char *s_name, int type, int res);

/** \ingroup rpmplugins
 * Call the fsm file pre plugin hook
 * @param plugins	plugins structure
 * @param fi		file info iterator (or NULL)
 * @param path		file object path
 * @param file_mode	file object mode
 * @param op		file operation + associated flags
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallFsmFilePre(rpmPlugins plugins, rpmfi fi, const char* path,
                                mode_t file_mode, rpmFsmOp op);

/** \ingroup rpmplugins
 * Call the fsm file post plugin hook
 * @param plugins	plugins structure
 * @param fi		file info iterator (or NULL)
 * @param path		file object path
 * @param file_mode	file object mode
 * @param op		file operation + associated flags
 * @param res		fsm result code
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallFsmFilePost(rpmPlugins plugins, rpmfi fi, const char* path,
                                mode_t file_mode, rpmFsmOp op, int res);

/** \ingroup rpmplugins
 * Call the fsm file prepare plugin hook. Called after setting
 * permissions etc, but before committing file to destination path.
 * @param plugins	plugins structure
 * @param fi		file info iterator (or NULL)
 * @param fd		file descriptor (or -1 if not available)
 * @param path		file object current path
 * @param dest		file object destination path
 * @param mode		file object mode
 * @param op		file operation + associated flags
 * @return		RPMRC_OK on success, RPMRC_FAIL otherwise
 */
RPM_GNUC_INTERNAL
rpmRC rpmpluginsCallFsmFilePrepare(rpmPlugins plugins, rpmfi fi,
                                   int fd, const char *path, const char *dest,
                                   mode_t mode, rpmFsmOp op);

#endif	/* _PLUGINS_H */
