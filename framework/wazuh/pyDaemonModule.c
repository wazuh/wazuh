/*
 * Wazuh Cluster Daemon
 * Copyright (C) 2017 Wazuh Inc.
 * October 27, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <Python.h>

static PyObject* pyDaemon() {
	int res_code = daemon(0, 0);
	return Py_BuildValue("res_code", res_code);
}

static PyMethodDef pyDaemonModule_methods[] = {
	{"pyDaemon", pyDaemon, METH_VARARGS},
	{NULL, NULL}
};

void initpyDaemonModule() {
	(void) Py_InitModule("pyDaemonModule", pyDaemonModule_methods);
}
