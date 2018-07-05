#include <Python.h>
#include "structmember.h"

#include <errno.h>
#include <time.h>
#include "auparse.h"

/*
auparse functions explicitly not exported in this binding and why:

auparse_destroy:	because this is handled by python object management
auparse_get_time:	because AuEvent provides this as an attribute
auparse_get_milli:	because AuEvent provides this as an attribute
auparse_get_serial:	because AuEvent provides this as an attribute
auparse_get_node:	because AuEvent provides this as an attribute
auparse_timestamp_compare: because AuEvent calls this via the cmp operator

*/

/*
 * Note about function return codes. If a C function returns:
 *
 * -1 and 0, then we return exception and none respectively
 * -1, 0, 1, then we return exception, false, true respectively
 *
 */

#if PY_MAJOR_VERSION > 2
#define IS_PY3K
#define MODINITERROR return NULL
#define PYNUM_FROMLONG PyLong_FromLong
#define PYSTR_CHECK PyUnicode_Check
#define PYSTR_FROMSTRING PyUnicode_FromString
#define PYSTR_ASSTRING PyUnicode_AsUTF8
#define PYFILE_ASFILE(f) fdopen(PyObject_AsFileDescriptor(f), "r")
int PyFile_Check(PyObject *f) {
    PyObject *io, *base;
    if (!(io = PyImport_ImportModule("io"))) {
        return 0;
    } else {
        if (!(base = PyObject_GetAttrString(io, "TextIOBase"))) {
            return 0;
        } else {
            return PyObject_IsInstance(f, base);
        }
    }
}
#else
#define MODINITERROR return
#define PYNUM_FROMLONG PyInt_FromLong
#define PYSTR_CHECK PyString_Check
#define PYSTR_FROMSTRING PyString_FromString
#define PYSTR_ASSTRING PyString_AsString
#define PYFILE_ASFILE(f) PyFile_AsFile(f)
#endif

static int debug = 0;
static PyObject *NoParserError = NULL;

/*===========================================================================
 *                                AuEvent
 *===========================================================================*/

typedef struct {
    PyObject_HEAD
    PyObject *sec;
    PyObject *milli;
    PyObject *serial;
    PyObject *host;
    au_event_t event;
} AuEvent;

static void
AuEvent_dealloc(AuEvent* self)
{
    Py_XDECREF(self->sec);
    Py_XDECREF(self->milli);
    Py_XDECREF(self->serial);
    Py_XDECREF(self->host);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
AuEvent_compare(PyObject *obj1, PyObject *obj2)
{
    AuEvent *au_event1 = (AuEvent *) obj1;
    AuEvent *au_event2 = (AuEvent *) obj2;

    return auparse_timestamp_compare(&au_event1->event, &au_event2->event);
}

static PyObject *
AuEvent_get_sec(AuEvent *self, void *closure)
{
    if (self->sec == NULL) {
        if ((self->sec = PYNUM_FROMLONG(self->event.sec)) == NULL) return NULL;
    }
    Py_INCREF(self->sec);
    return self->sec;
}

static PyObject *
AuEvent_get_milli(AuEvent *self, void *closure)
{
    if (self->milli == NULL) {
        if ((self->milli = PYNUM_FROMLONG(self->event.milli)) == NULL) return NULL;
    }
    Py_INCREF(self->milli);
    return self->milli;
}

static PyObject *
AuEvent_get_serial(AuEvent *self, void *closure)
{
    if (self->serial == NULL) {
        if ((self->serial = PYNUM_FROMLONG(self->event.serial)) == NULL) return NULL;
    }
    Py_INCREF(self->serial);
    return self->serial;
}

static PyObject *
AuEvent_get_host(AuEvent *self, void *closure)
{
    if (self->event.host == NULL) {
        Py_RETURN_NONE;
    } else {
	if (self->host == NULL) {
	    if ((self->host = PYSTR_FROMSTRING(self->event.host)) == NULL) return NULL;
	}
        Py_INCREF(self->host);
        return self->host;
    }
}

static PyGetSetDef AuEvent_getseters[] = {
    {"sec",    (getter)AuEvent_get_sec,    (setter)NULL, "Event seconds", NULL},
    {"milli",  (getter)AuEvent_get_milli,  (setter)NULL, "millisecond of the timestamp", NULL},
    {"serial", (getter)AuEvent_get_serial, (setter)NULL, "Serial number of the event", NULL},
    {"host",   (getter)AuEvent_get_host,   (setter)NULL, "Machine's name", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef AuEvent_members[] = {
    {NULL}  /* Sentinel */
};

static char *
fmt_event(time_t seconds, unsigned int milli, unsigned long serial, const char *host)
{
    static char buf1[200], buf2[200];
    char fmt[] = "%a %b %d %H:%M:%S.%%ld %Y serial=%%ld host=%%s";
    struct tm *tmp;

    tmp = localtime(&seconds);
    if (tmp == NULL) {
        sprintf(buf2, "localtime error");
        return buf2;
    }

    if (strftime(buf1, sizeof(buf1), fmt, tmp) == 0) {
        sprintf(buf2, "strftime returned 0");
        return buf2;
    }

    snprintf(buf2, sizeof(buf2), buf1, milli, serial, host, sizeof(buf2));
    return buf2;
}

static PyObject *
AuEvent_str(PyObject * obj)
{
    AuEvent *event = (AuEvent *) obj;
    return PYSTR_FROMSTRING(fmt_event(event->event.sec, event->event.milli, event->event.serial, event->event.host));
}


static PyMethodDef AuEvent_methods[] = {
    {NULL}  /* Sentinel */
};

PyDoc_STRVAR(AuEvent_doc,
"An internal object which encapsulates the timestamp, serial number\n\
and host information of an audit event. The object cannot be\n\
instantiated from python code, rather it is returned from the\n\
audit parsing API.");

static PyTypeObject AuEventType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "auparse.AuEvent",         /*tp_name*/
    sizeof(AuEvent),           /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)AuEvent_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    AuEvent_compare,           /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    AuEvent_str,               /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    AuEvent_doc,               /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    AuEvent_methods,           /* tp_methods */
    AuEvent_members,                        /* tp_members */
    AuEvent_getseters,         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0,               /* tp_new */
};

static PyObject *
AuEvent_new_from_struct(au_event_t const *event_ptr)
{
    AuEvent *self;

    self = (AuEvent *)AuEventType.tp_alloc(&AuEventType, 0);
    if (self != NULL) {
        self->event = *event_ptr;
    }

    return (PyObject *)self;
}

/*===========================================================================
 *                                AuParser
 *===========================================================================*/

#define PARSER_CHECK                                                               \
    if (self->au == NULL) {                                                        \
        PyErr_SetString(NoParserError, "object has no parser associated with it"); \
        return NULL;                                                               \
    }

typedef struct {
    PyObject_HEAD
    auparse_state_t *au;
} AuParser;

typedef struct {
    AuParser *py_AuParser;
    PyObject *func;
    PyObject *user_data;
} CallbackData;

void callback_data_destroy(void *user_data)
{
    CallbackData *cb = (CallbackData *)user_data;

    if (debug) printf("<< callback_data_destroy\n");
    if (cb) {
        Py_DECREF(cb->func);
        Py_XDECREF(cb->user_data);
        PyMem_Del(cb);
    }
}

static void auparse_callback(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)
{
    CallbackData *cb = (CallbackData *)user_data;
    PyObject *arglist;
    PyObject *result;

    arglist = Py_BuildValue("OiO", cb->py_AuParser, cb_event_type, cb->user_data);
    result = PyEval_CallObject(cb->func, arglist);
    Py_DECREF(arglist);
    Py_XDECREF(result);
}

static void
AuParser_dealloc(AuParser* self)
{
    if (debug) printf("<< AuParser_dealloc: self=%p au=%p\n", self, self->au);
    if (self->au != NULL) {
        auparse_destroy(self->au);
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
AuParser_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AuParser *self;

    self = (AuParser *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->au = NULL;
    }
    return (PyObject *)self;
}

/********************************
 * auparse_init
 ********************************/
static int
AuParser_init(AuParser *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"source_type", "source", NULL};
    int source_type = -1;
    PyObject  *source=Py_None;

    if (self->au != NULL) {
        auparse_destroy(self->au);
        self->au = NULL;
    }

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|iO", kwlist, &source_type, &source)) return -1; 

    switch (source_type) {
    case AUSOURCE_LOGS: {
        if (source != Py_None) {
            PyErr_SetString(PyExc_ValueError, "source must be None or not passed as a parameter when source_type is AUSOURCE_LOGS");
            return -1;
        }
        if ((self->au = auparse_init(source_type, NULL)) == NULL) {
            PyErr_SetFromErrno(PyExc_IOError);
            return -1;
        }
    } break;
    case AUSOURCE_FILE: {
        char *filename = NULL;

        if (!PYSTR_CHECK(source)) {
            PyErr_SetString(PyExc_ValueError, "source must be a string when source_type is AUSOURCE_FILE");
            return -1;
        }
        if ((filename = PYSTR_ASSTRING(source)) == NULL) return -1;
        if ((self->au = auparse_init(source_type, filename)) == NULL) {
            PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
            return -1;
        }
    } break;
    case AUSOURCE_FILE_ARRAY: {
        int i, n;
        PyObject *item = NULL;
        char **files = NULL;

        if (PySequence_Check(source)) {
            n = PySequence_Size(source);
            if ((files = PyMem_New(char *, n+1)) == NULL) {
                PyErr_NoMemory();
                return -1;
            }
            for (i = 0; i < n; i++) {
                item = PySequence_GetItem(source, i);
                if ((files[i] = PYSTR_ASSTRING(item)) == NULL) {
                    PyErr_SetString(PyExc_ValueError, "members of source sequence must be a string when source_type is AUSOURCE_FILE_ARRAY");
                    Py_DECREF(item);
                    PyMem_Del(files);
                    return -1;
                } else {
                    Py_DECREF(item);
                }
            }
            files[i] = NULL;
        } else {
            PyErr_SetString(PyExc_ValueError, "source must be a sequence when source_type is AUSOURCE_FILE_ARRAY");
            return -1;
        }
        
        if ((self->au = auparse_init(source_type, files)) == NULL) {
            PyErr_SetFromErrno(PyExc_IOError);
            PyMem_Del(files);
            return -1;
        }
        PyMem_Del(files);
    } break;
    case AUSOURCE_BUFFER: {
        char *buf;
        if ((buf = PYSTR_ASSTRING(source)) == NULL) return -1;
        if ((self->au = auparse_init(source_type, buf)) == NULL) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return -1;
        }
    } break;
    case AUSOURCE_BUFFER_ARRAY: {
        int i, n;
        PyObject *item = NULL;
        char **buffers = NULL;

        if (PySequence_Check(source)) {
            n = PySequence_Size(source);
            if ((buffers = PyMem_New(char *, n+1)) == NULL) {
                PyErr_NoMemory();
                return -1;
            }
            for (i = 0; i < n; i++) {
                item = PySequence_GetItem(source, i);
                if ((buffers[i] = PYSTR_ASSTRING(item)) == NULL) {
                    PyErr_SetString(PyExc_ValueError, "members of source sequence must be a string when source_type is AUSOURCE_BUFFER_ARRAY");
                    Py_DECREF(item);
                    PyMem_Del(buffers);
                    return -1;
                } else {
                    Py_DECREF(item);
                }
            }
            buffers[i] = NULL;
        } else {
            PyErr_SetString(PyExc_ValueError, "source must be a sequence when source_type is AUSOURCE_FILE_ARRAY");
            return -1;
        }
        
        if ((self->au = auparse_init(source_type, buffers)) == NULL) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            PyMem_Del(buffers);
            return -1;
        }
        PyMem_Del(buffers);
    } break;
    case AUSOURCE_DESCRIPTOR: {
        long fd;
        fd = PyObject_AsFileDescriptor(source);
        if (fd < 0) {
            PyErr_SetString(PyExc_ValueError, "source must be resolvable to a file descriptor when source_type is AUSOURCE_DESCRIPTOR");
            return -1;
        }
        if ((self->au = auparse_init(source_type, (const void *)fd)) == NULL) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return -1;
        }
    } break;
    case AUSOURCE_FILE_POINTER: {
        FILE* fp;

        if (!PyFile_Check(source)) {
            PyErr_SetString(PyExc_ValueError, "source must be a file object when source_type is AUSOURCE_FILE_POINTER");
            return -1;
        }
	if ((fp = PYFILE_ASFILE(source)) == NULL) {
            PyErr_SetString(PyExc_TypeError, "source must be open file when source_type is AUSOURCE_FILE_POINTER");
            return -1;
	}
#if PY_MAJOR_VERSION < 3
	int fd = fileno(fp);
	fp = fdopen(fd, "r");
#endif
        if ((self->au = auparse_init(source_type, fp)) == NULL) {
            //char *filename = PYSTR_ASSTRING(PyFile_Name(source));
            char *filename = "TODO";
            PyErr_SetFromErrnoWithFilename(PyExc_IOError, filename);
            return -1;
        }
    } break;
    case AUSOURCE_FEED: {
        if (source != Py_None) {
            PyErr_SetString(PyExc_ValueError, "source must be None when source_type is AUSOURCE_FEED");
            return -1;
        }
        if ((self->au = auparse_init(source_type, NULL)) == NULL) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return -1;
        }
    } break;
    default: {
        PyErr_SetString(PyExc_ValueError, "Invalid source type");
        return -1;
    } break;
    }

    if (debug) printf(">> AuParser_init: self=%p au=%p\n", self, self->au);
    return 0;
}

/********************************
 * auparse_feed
 ********************************/
PyDoc_STRVAR(feed_doc,
"feed(data) supplies new data for the parser to consume.\n\
\n\
AuParser() must have been called with a source type of AUSOURCE_FEED.\n\
The parser consumes as much data as it can invoking a user supplied\n\
callback specified with add_callback() with a cb_event_type of\n\
AUPARSE_CB_EVENT_READY each time the parser recognizes a complete event\n\
in the data stream. Data not fully parsed will persist and be prepended\n\
to the next feed data. After all data has been feed to the parser flush_feed()\n\
should be called to signal the end of input data and flush any pending\n\
parse data through the parsing system.\n\
\n\
Returns None.\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_feed(AuParser *self, PyObject *args)
{
    char *data;
    int data_len;
    int result;

    if (!PyArg_ParseTuple(args, "s#:feed", &data, &data_len)) return NULL;
    PARSER_CHECK;
    result = auparse_feed(self->au, data, data_len);
    if (result ==  0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_flush_feed
 ********************************/
PyDoc_STRVAR(flush_feed_doc,
"flush_feed() flush any unconsumed feed data through parser\n\
\n\
flush_feed() should be called to signal the end of feed input data\n\
and flush any pending parse data through the parsing system.\n\
\n\
Returns None.\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_flush_feed(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_flush_feed(self->au);
    if (result ==  0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_feed_has_data
 ********************************/
PyDoc_STRVAR(feed_has_data_doc,
"feed_has_data() determines if there are any records that\n\
 are accumulating but not yet ready to emit.\n\
\n\
Returns True if data left and false otherwise.\n\
");
static PyObject *
AuParser_feed_has_data(AuParser *self)
{
    PARSER_CHECK;
    if (auparse_feed_has_data(self->au) == 0)
        Py_RETURN_FALSE;
    Py_RETURN_TRUE;
}

/********************************
 * auparse_feed_age_events
 ********************************/
PyDoc_STRVAR(feed_age_events_doc,
"feed_age_events() age events by the clock\n\
\n\
feed_age_events() should be called to timeout events by the clock.\n\
Any newly complete events will be sent to the callback function.\n\
\n\
Returns None.\n\
");
static PyObject *
AuParser_feed_age_events(AuParser *self)
{
    PARSER_CHECK;
    auparse_feed_age_events(self->au);
    Py_RETURN_NONE;
}

/********************************
 * auparse_add_callback
 ********************************/
PyDoc_STRVAR(add_callback_doc,
"add_callback(callback, user_data) add a callback handler for notifications.\n\
\n\
auparse_add_callback adds a callback function to the parse state which\n\
is invoked to notify the application of parsing events.\n\
\n\
The signature of the callback is:\n\
\n\
callback(au, cb_event_type,user_data)\n\
\n\
When the callback is invoked it is passed:\n\
au: the AuParser object\n\
cb_event_type: enumerated value indicating the reason why the callback was invoked\n\
user_data: user supplied private data\n\
\n\
The cb_event_type argument indicates why the callback was invoked.\n\
It's possible values are:\n\
\n\
AUPARSE_CB_EVENT_READY\n\
A complete event has been parsed and is ready to be examined.\n\
This is logically equivalent to the parse state immediately following\n\
auparse_next_event()\n\
\n\
Returns None.\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_add_callback(AuParser *self, PyObject *args)
{
    PyObject *func;
    PyObject *user_data;

    if (!PyArg_ParseTuple(args, "O|O:add_callback", &func, &user_data)) return NULL;
    if (!PyFunction_Check(func)) {
        PyErr_SetString(PyExc_ValueError, "callback must be a function");
        return NULL;
    }
    PARSER_CHECK;

    {
        CallbackData *cb;

        cb = PyMem_New(CallbackData, 1);
        if (cb == NULL)
            return PyErr_NoMemory();
        cb->py_AuParser = self;
        cb->func = func;
        cb->user_data = user_data;
        Py_INCREF(cb->func);
        Py_XINCREF(cb->user_data);
        auparse_add_callback(self->au, auparse_callback, cb, callback_data_destroy);
}

    Py_RETURN_NONE;
}

/********************************
 * auparse_set_escape_mode
 ********************************/
PyDoc_STRVAR(set_escape_mode_doc,
"set_escape_mode(mode) Set audit parser escaping\n\
\n\
This function sets the character escaping applied to value fields in the audit record.\n\
Returns None.\n\
");
static PyObject *
AuParser_set_escape_mode(AuParser *self, PyObject *args)
{
    int mode;

    if (!PyArg_ParseTuple(args, "i", &mode)) return NULL;
    auparse_set_escape_mode(self->au, mode);

    Py_RETURN_NONE;
}

/********************************
 * auparse_reset
 ********************************/
PyDoc_STRVAR(reset_doc,
"reset() Reset audit parser instance\n\
\n\
reset resets all internal cursors to the beginning.\n\
It closes files and descriptors.\n\
\n\
Returns None.\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_reset(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_reset(self->au);
    if (result ==  0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_add_expression
 ********************************/
PyDoc_STRVAR(search_add_expression_doc,
"search_add_expression(expression, how) Build up search expression\n\
\n\
\n\
ausearch_add_item adds an expression to the current audit search\n\
expression.  The search conditions can then be used to scan logs,\n\
files, or buffers for something of interest.  The expression parameter\n\
contains an expression, as specified in ausearch-expression(5).\n\
\n\
The how parameter determines how this search expression will affect the\n\
existing search expression, if one is already defined.  The possible\n\
values are:\n\
\n\
AUSEARCH_RULE_CLEAR:\n\
Clear the current search expression, if any, and use only this search\n\
expression.\n\
\n\
AUSEARCH_RULE_OR:\n\
\n\
If a search expression E is already configured, replace it by\n\
(E || this_search_expression).\n\
\n\
AUSEARCH_RULE_AND:\n\
If a search expression E is already configured, replace it by\n\
(E && this_search_expression).\n\
\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_search_add_expression(AuParser *self, PyObject *args)
{
    const char *expression;
    char *error;
    int how;
    int result;

    if (!PyArg_ParseTuple(args, "si", &expression, &how)) return NULL;
    PARSER_CHECK;

    result = ausearch_add_expression(self->au, expression, &error, how);
    if (result == 0) Py_RETURN_NONE;
    if (error == NULL)
	PyErr_SetFromErrno(PyExc_EnvironmentError);
    else {
	PyErr_SetString(PyExc_EnvironmentError, error);
	free(error);
    }
    return NULL;
}

/********************************
 * ausearch_add_item
 ********************************/
PyDoc_STRVAR(search_add_item_doc,
"search_add_item(field, op, value, how) Build up search rule\n\
\n\
\n\
search_add_item() adds one search condition to the current audit search\n\
expression. The search conditions can then be used to scan logs, files, or\n\
buffers for something of interest. The field value is the field name\n\
that the value will be checked for. The op variable describes what\n\
kind of check is to be done. Legal op values are:\n\
\n\
'exists':\n\
Just check that a field name exists\n\
\n\
'=':\n\
locate the field name and check that the value associated with it\n\
is equal to the value given in this rule.\n\
\n\
'!=':\n\
locate the field name and check that the value associated with\n\
it is NOT equal to the value given in this rule.\n\
\n\
The value parameter is compared to the uninterpreted field value.\n\
\n\
The how parameter determines how this search expression will affect the\n\
existing search expression, if one is already defined.  The possible\n\
values are:\n\
\n\
AUSEARCH_RULE_CLEAR:\n\
Clear the current search expression, if any, and use only this search\n\
expression.\n\
\n\
AUSEARCH_RULE_OR:\n\
\n\
If a search expression E is already configured, replace it by\n\
(E || this_search_expression).\n\
\n\
AUSEARCH_RULE_AND:\n\
If a search expression E is already configured, replace it by\n\
(E && this_search_expression).\n\
\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");

static PyObject *
AuParser_search_add_item(AuParser *self, PyObject *args)
{
    const char *field;
    const char *op;
    const char *value;
    int how;
    int result;

    if (!PyArg_ParseTuple(args, "sssi", &field, &op, &value, &how)) return NULL;
    PARSER_CHECK;

    result = ausearch_add_item(self->au, field, op, value, how);
    if (result == 0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_add_interpreted_item
 ********************************/
PyDoc_STRVAR(search_add_interpreted_item_doc,
"search_add_interpreted_item(field, op, value, how) Build up search rule\n\
\n\
\n\
search_add_interpreted_item() adds one search condition to the current audit\n\
search expression. The search conditions can then be used to scan logs,\n\
files, or buffers for something of interest. The field value is the field\n\
name that the value will be checked for. The op variable describes what\n\
kind of check is to be done. Legal op values are:\n\
\n\
'exists':\n\
Just check that a field name exists\n\
\n\
'=':\n\
locate the field name and check that the value associated with it\n\
is equal to the value given in this rule.\n\
\n\
'!=':\n\
locate the field name and check that the value associated with\n\
it is NOT equal to the value given in this rule.\n\
\n\
The value parameter is compared to the interpreted field value (the value\n\
that would be returned by AuParser.interpret_field).\n\
\n\
The how parameter determines how this search expression will affect the\n\
existing search expression, if one is already defined.  The possible\n\
values are:\n\
\n\
AUSEARCH_RULE_CLEAR:\n\
Clear the current search expression, if any, and use only this search\n\
expression.\n\
\n\
AUSEARCH_RULE_OR:\n\
\n\
If a search expression E is already configured, replace it by\n\
(E || this_search_expression).\n\
\n\
AUSEARCH_RULE_AND:\n\
If a search expression E is already configured, replace it by\n\
(E && this_search_expression).\n\
\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");

static PyObject *
AuParser_search_add_interpreted_item(AuParser *self, PyObject *args)
{
    const char *field;
    const char *op;
    const char *value;
    int how;
    int result;

    if (!PyArg_ParseTuple(args, "sssi", &field, &op, &value, &how)) return NULL;
    PARSER_CHECK;

    result = ausearch_add_interpreted_item(self->au, field, op, value, how);
    if (result == 0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_add_timestamp_item
 ********************************/
PyDoc_STRVAR(search_add_timestamp_item_doc,
"search_add_timestamp_item(op, sec, milli, how) Build up search rule\n\
\n\
\n\
search_add_timestamp_item adds an event time condition to the current audit\n\
search expression. The search conditions can then be used to scan logs,\n\
files, or buffers for something of interest. The op parameter specifies the\n\
desired comparison. Legal op values are \"<\", \"<=\", \">=\", \">\" and\n\
\"=\". The left operand of the comparison operator is the timestamp of the\n\
examined event, the right operand is specified by the sec and milli\n\
parameters.\n\
\n\
The how parameter determines how this search expression will affect the\n\
existing search expression, if one is already defined.  The possible\n\
values are:\n\
\n\
AUSEARCH_RULE_CLEAR:\n\
Clear the current search expression, if any, and use only this search\n\
expression.\n\
\n\
AUSEARCH_RULE_OR:\n\
\n\
If a search expression E is already configured, replace it by\n\
(E || this_search_expression).\n\
\n\
AUSEARCH_RULE_AND:\n\
If a search expression E is already configured, replace it by\n\
(E && this_search_expression).\n\
\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");

static PyObject *
AuParser_search_add_timestamp_item(AuParser *self, PyObject *args)
{
    const char *op;
    PY_LONG_LONG sec;
    int milli;
    int how;
    int result;

    /* There's no completely portable way to handle time_t values from Python;
       note that time_t might even be a floating-point type!  PY_LONG_LONG
       is at least enough not to worry about year 2038.

       milli is int because Python's 'I' format does no overflow checking.
       Negative milli values will wrap to values > 1000 and
       ausearch_add_timestamp_item will reject them. */
    if (!PyArg_ParseTuple(args, "sLii", &op, &sec, &milli, &how))
	    return NULL;
    PARSER_CHECK;

    result = ausearch_add_timestamp_item(self->au, op, sec, (unsigned)milli,
					 how);
    if (result == 0)
	    Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_add_timestamp_item_ex
 ********************************/
PyDoc_STRVAR(search_add_timestamp_item_ex_doc,
"search_add_timestamp_item_ex(op, sec, milli, serial, how) Build up search rule\n\
search_add_timestamp_item_ex adds an event time condition to the current audit\n\
search expression. Its similar to search_add_timestamp_item except it adds\n\
the event serial number.\n\
");

static PyObject *
AuParser_search_add_timestamp_item_ex(AuParser *self, PyObject *args)
{
    const char *op;
    PY_LONG_LONG sec;
    int milli;
    int serial;
    int how;
    int result;

    /* There's no completely portable way to handle time_t values from Python;
       note that time_t might even be a floating-point type!  PY_LONG_LONG
       is at least enough not to worry about year 2038.

       milli is int because Python's 'I' format does no overflow checking.
       Negative milli values will wrap to values > 1000 and
       ausearch_add_timestamp_item will reject them. */
    if (!PyArg_ParseTuple(args, "sLiiii", &op, &sec, &milli, &serial, &how))
	    return NULL;
    PARSER_CHECK;

    result = ausearch_add_timestamp_item_ex(self->au, op, sec, (unsigned)milli,
					 (unsigned)serial, how);
    if (result == 0)
	    Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_add_regex
 ********************************/
PyDoc_STRVAR(search_add_regex_doc,
"search_add_regex(regexp) Add a regular expression to the search criteria.\n\
\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_search_add_regex(AuParser *self, PyObject *args)
{
    const char* regexp;
    int result;

    if (!PyArg_ParseTuple(args, "s", &regexp)) return NULL;
    PARSER_CHECK;
    result = ausearch_add_regex(self->au, regexp);
    if (result == 0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * ausearch_set_stop
 ********************************/
PyDoc_STRVAR(search_set_stop_doc,
"search_set_stop(where) Set where cursor is positioned on search match.\n\
\n\
search_set_stop() determines where the internal cursor will stop when\n\
a search condition is met. The possible values are:\n\
\n\
AUSEARCH_STOP_EVENT:\n\
This one repositions the cursors to the first field of the first\n\
record of the event containing the items searched for.\n\
\n\
AUSEARCH_STOP_RECORD:\n\
This one repositions the cursors to the first field of the record\n\
containing the items searched for.\n\
\n\
AUSEARCH_STOP_FIELD:\n\
This one simply stops on the current field when the evaluation of the\n\
rules becomes true.\n\
\n\
No Return value, raises exception (ValueError) on error.\n\
");
static PyObject *
AuParser_search_set_stop(AuParser *self, PyObject *args)
{
    int where;
    int result;

    if (!PyArg_ParseTuple(args, "i", &where)) return NULL;
    PARSER_CHECK;
    result = ausearch_set_stop(self->au, where);
    if (result == 0) Py_RETURN_NONE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * ausearch_clear
 ********************************/
PyDoc_STRVAR(search_clear_doc,
"search_clear() Clear search parameters.\n\
\n\
ausearch_clear clears any search parameters stored in the parser\n\
instance and frees memory associated with it.\n\
\n\
No Return value.\n\
");
static PyObject *
AuParser_search_clear(AuParser *self)
{
    PARSER_CHECK;
    ausearch_clear(self->au);
    Py_RETURN_NONE;
}

/********************************
 * ausearch_next_event
 ********************************/
PyDoc_STRVAR(search_next_event_doc,
"search_next_event() Find the next event that meets search criteria.\n\
\n\
search_next_event() will scan the input source and evaluate whether\n\
any record in an event contains the data being searched\n\
for. Evaluation is done at the record level.\n\
\n\
Returns True if a match was found\n\
Returns False if a match was not found.\n\
\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_search_next_event(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = ausearch_next_event(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_next_event
 ********************************/
PyDoc_STRVAR(parse_next_event_doc,
"parse_next_event() Advance the parser to the next event.\n\
\n\
parse_next_event() will position the cursors at the first field of the first\n\
record of the next event in a file or buffer. It does not skip events\n\
or honor any search criteria that may be stored.\n\
\n\
Returns True if parser advances to next event.\n\
Returns False if there are no more events to parse\n\
\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_parse_next_event(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_next_event(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}



/********************************
 * aup_normalize
 ********************************/
PyDoc_STRVAR(aup_normalize_doc,
"aup_normalize(opt) Normalize the audit event for uniform access to fields.\n\
\n\
aup_normalize() takes an argument to decide if it should also gather subject\n\
and object attributes. The possible values are:\n\
\n\
NORM_OPT_ALL:\n\
This means include subject and object attributes\n\
\n\
NORM_OPT_NO_ATTRS:\n\
This means do not gather subject and object attributes\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize(AuParser *self, PyObject *args)
{
    int opt;
    int result;

    if (!PyArg_ParseTuple(args, "i", &opt)) return NULL;
    PARSER_CHECK;
    result = auparse_normalize(self->au, opt);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}


/********************************
 * aup_normalize_get_event_kind
 ********************************/
PyDoc_STRVAR(aup_normalize_get_event_kind_doc,
"aup_normalize_get_event_kind() This returns a string that indicates what\n\
kind of event this is.\n\
\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_aup_normalize_get_event_kind(AuParser *self)
{
    const char *kind = NULL;

    PARSER_CHECK;
    kind = auparse_normalize_get_event_kind(self->au);
    if (kind == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'event_kind' has no value");
        return NULL;
    }
    return Py_BuildValue("s", kind);
}

/********************************
 * aup_normalize_session
 ********************************/
PyDoc_STRVAR(aup_normalize_session_doc,
"aup_normalize_session() This function positions the internal cursor on\n\
the session's field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_session(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_session(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_subject_primary
 ********************************/
PyDoc_STRVAR(aup_normalize_subject_primary_doc,
"aup_normalize_subject_primary() This function positions the internal\n\
cursor on the subject's field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_subject_primary(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_subject_primary(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_subject_secondary
 ********************************/
PyDoc_STRVAR(aup_normalize_subject_secondary_doc,
"aup_normalize_subject_secondary() This function positions the internal\n\
cursor on the subject's secondary field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_subject_secondary(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_subject_secondary(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_subject_first_attribute
 ********************************/
PyDoc_STRVAR(aup_normalize_subject_first_attribute_doc,
"aup_normalize_subject_first_attribute() This function positions the internal\n\
cursor on the subject's first attribute field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_subject_first_attribute(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_subject_first_attribute(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_subject_next_attribute
 ********************************/
PyDoc_STRVAR(aup_normalize_subject_next_attribute_doc,
"aup_normalize_subject_next_attribute() This function positions the internal\n\
cursor on the next subject's attribute field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_subject_next_attribute(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_subject_next_attribute(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_subject_kind
 ********************************/
PyDoc_STRVAR(aup_normalize_subject_kind_doc,
"aup_normalize_subject_kind() This returns a string that indicates the\n\
kind of account the subject is.\n\
\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_aup_normalize_subject_kind(AuParser *self)
{
    const char *kind = NULL;

    PARSER_CHECK;
    kind = auparse_normalize_subject_kind(self->au);
    if (kind == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'subject_kind' has no value");
        return NULL;
    }
    return Py_BuildValue("s", kind);
}

/********************************
 * aup_normalize_get_action
 ********************************/
PyDoc_STRVAR(aup_normalize_get_action_doc,
"aup_normalize_get_action() This returns a string that indicates the\n\
subject's action.\n\
\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_aup_normalize_get_action(AuParser *self)
{
    const char *action = NULL;

    PARSER_CHECK;
    action = auparse_normalize_get_action(self->au);
    if (action == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'action' has no value");
        return NULL;
    }
    return Py_BuildValue("s", action);
}

/********************************
 * aup_normalize_object_primary
 ********************************/
PyDoc_STRVAR(aup_normalize_object_primary_doc,
"aup_normalize_object_primary() This function positions the internal\n\
cursor on the object's field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_object_primary(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_object_primary(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_object_secondary
 ********************************/
PyDoc_STRVAR(aup_normalize_object_secondary_doc,
"aup_normalize_object_secondary() This function positions the internal\n\
cursor on the object's secondary field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_object_secondary(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_object_secondary(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_object_first_attribute
 ********************************/
PyDoc_STRVAR(aup_normalize_object_first_attribute_doc,
"aup_normalize_object_first_attribute() This function positions the internal\n\
cursor on the object's first attribute field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_object_first_attribute(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_object_first_attribute(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_object_next_attribute
 ********************************/
PyDoc_STRVAR(aup_normalize_object_next_attribute_doc,
"aup_normalize_object_next_attribute() This function positions the internal\n\
cursor on the next object's attribute field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_object_next_attribute(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_object_next_attribute(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_object_kind
 ********************************/
PyDoc_STRVAR(aup_normalize_object_kind_doc,
"aup_normalize_object_kind() This returns a string that indicates the\n\
kind of thing the object is.\n\
\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_aup_normalize_object_kind(AuParser *self)
{
    const char *kind = NULL;

    PARSER_CHECK;
    kind = auparse_normalize_object_kind(self->au);
    if (kind == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'object_kind' has no value");
        return NULL;
    }
    return Py_BuildValue("s", kind);
}

/********************************
 * aup_normalize_get_results
 ********************************/
PyDoc_STRVAR(aup_normalize_get_results_doc,
"aup_normalize_subject_primary() This function positions the internal\n\
cursor on the results field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_get_results(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_get_results(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}

/********************************
 * aup_normalize_how
 ********************************/
PyDoc_STRVAR(aup_normalize_how_doc,
"aup_normalize_how() This returns a string that indicates the\n\
how the object is being accessed. This is usually a program.\n\
\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_aup_normalize_how(AuParser *self)
{
    const char *how = NULL;

    PARSER_CHECK;
    how = auparse_normalize_how(self->au);
    if (how == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'how' has no value");
        return NULL;
    }
    return Py_BuildValue("s", how);
}

/********************************
 * aup_normalize_key
 ********************************/
PyDoc_STRVAR(aup_normalize_key_doc,
"aup_normalize_key() This function positions the internal\n\
cursor on the key field of the event.\n\
\n\
Returns True on success\n\
Returns False if uninitialized\n\
\n\
Raises exception (ValueError) on error\n\
");
static PyObject *
AuParser_aup_normalize_key(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_normalize_key(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_ValueError);
    return NULL;
}


/********************************
 * auparse_get_timestamp
 ********************************/
PyDoc_STRVAR(get_timestamp_doc,
"get_timestamp() Return current event's timestamp.\n\
\n\
Returns the current event's timestamp info as an AuEvent object.\n\
No Return value, raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_get_timestamp(AuParser *self)
{
    const au_event_t *event_ptr;
    PyObject *py_event;

    PARSER_CHECK;
    event_ptr = auparse_get_timestamp(self->au);

    if (event_ptr == NULL) {
        if (errno) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return NULL;
        } else {
            Py_RETURN_NONE;
        }
    }
    py_event = AuEvent_new_from_struct(event_ptr);
    return py_event;
}

/********************************
 * auparse_get_num_records
 *
 ********************************/
PyDoc_STRVAR(get_num_records_doc,
"get_num_records() Get the number of records.\n\
\n\
Returns the number of records in the current event.\n\
Raises exception (RuntimeError) on error.\n\
");
static PyObject *
AuParser_get_num_records(AuParser *self)
{
    int num_records;

    PARSER_CHECK;
    num_records = auparse_get_num_records(self->au);
    if (num_records == 0) {
        PyErr_SetString(PyExc_RuntimeError, "No records");
        return NULL;
    }
    return Py_BuildValue("i", num_records);
}

/********************************
 * auparse_first_record
 ********************************/
PyDoc_STRVAR(first_record_doc,
"first_record() Reposition record cursor.\n\
\n\
first_record() repositions the internal cursors of the parsing library\n\
to point to the first record in the current event.\n\
\n\
Return True for success, False if there is no event data.\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_first_record(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_first_record(self->au);
    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_next_record
 ********************************/
PyDoc_STRVAR(next_record_doc,
"next_record() Advance record cursor.\n\
\n\
next_record() will move the internal library cursors to point to the\n\
next record of the current event.\n\
\n\
Returns True on success, False if no more records in current event\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_next_record(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_next_record(self->au);

    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_goto_record_num
 ********************************/
PyDoc_STRVAR(goto_record_num_doc,
"goto_record_num() Move record cursor to specific position.\n\
\n\
goto_record_num() will move the internal library cursors to point\n\
to a specific physical record number. Records within the same event are\n\
numbered  starting  from  0. This is generally not needed but there are\n\
some cases where one may want precise control  over  the  exact  record\n\
being looked at.\n\
\n\
Returns True on success, False if no more records in current event\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_goto_record_num(AuParser *self, PyObject *args)
{
    int result;
    unsigned int num;

    if (!PyArg_ParseTuple(args, "i", &num)) return NULL;
    PARSER_CHECK;
    result = auparse_goto_record_num(self->au, num);

    if (result >  0) Py_RETURN_TRUE;
    if (result == 0) Py_RETURN_FALSE;
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

/********************************
 * auparse_get_type
 ********************************/
PyDoc_STRVAR(get_type_doc,
"get_type() Get record’s type.\n\
\n\
get_type() will return the integer value for the current record of the\n\
current event.\n\
\n\
Returns record type.\n\
Raises exception (LookupError) on error.\n\
");
static PyObject *
AuParser_get_type(AuParser *self)
{
    int value;

    PARSER_CHECK;
    value = auparse_get_type(self->au);

    if (value == 0) {
	PyErr_SetString(PyExc_LookupError, "Not found");
        return NULL;
    }
    return Py_BuildValue("i", value);
}

/********************************
 * auparse_get_type_name
 ********************************/
PyDoc_STRVAR(get_type_name_doc,
"get_type_name() Get current record’s type name.\n\
\n\
get_type_name() allows access to the current record type name in the\n\
current event.\n\
\n\
Raises exception (LookupError) on error.\n\
");
static PyObject *
AuParser_get_type_name(AuParser *self)
{
    const char *name = NULL;

    PARSER_CHECK;
    name = auparse_get_type_name(self->au);
    if (name == NULL) {
	PyErr_SetString(PyExc_LookupError, "Not found");
	return NULL;
    }
    return Py_BuildValue("s", name);
}

/********************************
 * auparse_get_line_number
 ********************************/
PyDoc_STRVAR(get_line_number_doc,
"auparse_get_line_number() get line number where record was found\n\
\n\
get_line_number will return the source input line number for\n\
the current record of the current event. Line numbers start at 1.  If\n\
the source input type is AUSOURCE_FILE_ARRAY the line numbering will\n\
reset back to 1 each time a new life in the file array is opened.\n\
Raises exception (RuntimeError) on error.\n\
");
static PyObject *
AuParser_get_line_number(AuParser *self)
{
    unsigned int value;

    PARSER_CHECK;
    value = auparse_get_line_number(self->au);
    if (value == 0) {
        PyErr_SetString(PyExc_RuntimeError, "No line number");
        return NULL;
    }
    return Py_BuildValue("I", value);
}

/********************************
 * auparse_get_filename
 ********************************/
PyDoc_STRVAR(get_filename_doc,
"auparse_get_filename() get the filename where record was found\n\
get_filename() will return the name of the source file where the\n\
record was found if the source type is AUSOURCE_FILE or\n\
AUSOURCE_FILE_ARRAY. For other source types the return value will be\n\
None.\n\
");
static PyObject *
AuParser_get_filename(AuParser *self)
{
    const char *value;

    PARSER_CHECK;
    value = auparse_get_filename(self->au);

    if (value == NULL) Py_RETURN_NONE;
    return Py_BuildValue("s", value);
}

/********************************
 * auparse_first_field
 ********************************/
PyDoc_STRVAR(first_field_doc,
"first_field() Reposition field cursor.\n\
\n\
Returns True on success, False if there is no event data\n\
");
static PyObject *
AuParser_first_field(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_first_field(self->au);

    if (result == 0) Py_RETURN_FALSE;
    Py_RETURN_TRUE;
}

/********************************
 * auparse_next_field
 ********************************/
PyDoc_STRVAR(next_field_doc,
"next_field() Advance the field cursor.\n\
\n\
next_field() moves the library’s internal cursor to point to the next\n\
field in the current record of the current event.\n\
\n\
Returns True on success, False if there is no more fields exist\n\
");
static PyObject *
AuParser_next_field(AuParser *self)
{
    int result;

    PARSER_CHECK;
    result = auparse_next_field(self->au);

    if (result == 0) Py_RETURN_FALSE;
    Py_RETURN_TRUE;
}

/********************************
 * auparse_get_num_fields
 ********************************/
PyDoc_STRVAR(get_num_fields_doc,
"get_num_fields() Get the number of fields.\n\
\n\
Returns the number of fields in the current event.\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_get_num_fields(AuParser *self)
{
    int num_fields;

    PARSER_CHECK;
    num_fields = auparse_get_num_fields(self->au);
    if (num_fields == 0) {
        PyErr_SetFromErrno(PyExc_EnvironmentError);
        return NULL;
    }
    return Py_BuildValue("i", num_fields);
}

/********************************
 * auparse_get_record_text
 ********************************/
PyDoc_STRVAR(get_record_text_doc,
"get_record_text() Return unparsed record data\n\
\n\
get_record_text() returns the full unparsed record.\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_get_record_text(AuParser *self)
{
    const char *text;

    PARSER_CHECK;
    text = auparse_get_record_text(self->au);

    if (text == NULL) {
        PyErr_SetFromErrno(PyExc_EnvironmentError);
        return NULL;
    }
    return Py_BuildValue("s", text);
}

/********************************
 * auparse_find_field
 ********************************/
PyDoc_STRVAR(find_field_doc,
"find_field(name) Search for field name.\n\
\n\
find_field() will scan all records in an event to find the first\n\
occurrence of the field name passed to it. Searching begins from the\n\
cursor’s current position. The field name is stored for subsequent\n\
searching.\n\
\n\
Returns value associated with field or None if not found.\n\
");
static PyObject *
AuParser_find_field(AuParser *self, PyObject *args)
{
    char *name = NULL;
    const char *value;

    if (!PyArg_ParseTuple(args, "s:find_field", &name)) return NULL;
    PARSER_CHECK;
    if ((value =auparse_find_field(self->au, name)) == NULL) {
        if (errno) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return NULL;
        } else {
            Py_RETURN_NONE;
        }
    }
    return Py_BuildValue("s", value);
}

const char *auparse_find_field_next(auparse_state_t *au);
/********************************
 * auparse_find_field_next
 ********************************/
PyDoc_STRVAR(find_field_next_doc,
"find_field_next() Get next occurrence of field name\n\
\n\
find_field_next() returns the value associated next occurrence of field name.\n\
Returns value associated with field or None if there is no next field.\n\
Raises exception (EnvironmentError) on error.\n\
");
static PyObject *
AuParser_find_field_next(AuParser *self)
{
    const char *value;

    PARSER_CHECK;
    if ((value = auparse_find_field_next(self->au)) == NULL) {
        if (errno) {
            PyErr_SetFromErrno(PyExc_EnvironmentError);
            return NULL;
        } else {
            Py_RETURN_NONE;
        }
    }
    return Py_BuildValue("s", value);
}

/********************************
 * auparse_get_field_name
 ********************************/
PyDoc_STRVAR(get_field_name_doc,
"get_field_name() Get current field’s name.\n\
\n\
get_field_name() allows access to the current field name of the\n\
current record in the current event.\n\
\n\
Returns None if the field value is unavailable.\n\
Returns String.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_get_field_name(AuParser *self)
{
    const char *name = NULL;

    PARSER_CHECK;
    name = auparse_get_field_name(self->au);
    if (name == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'field name' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", name);
}

/********************************
 * auparse_get_field_str
 ********************************/
PyDoc_STRVAR(get_field_str_doc,
"get_field_str() get current field’s value\n\
\n\
get_field_str() allows access to the value in the current field of the\n\
current record in the current event.\n\
\n\
Returns String.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_get_field_str(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_get_field_str(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'field str' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

/********************************
 * auparse_get_field_type
 ********************************/
PyDoc_STRVAR(get_field_type_doc,
"get_field_type() Get current field’s data type value.\n\
\n\
get_field_type() returns a value from the auparse_type_t enum that\n\
describes the kind of data in the current field of the current record\n\
in the current event.\n\
\n\
Returns AUPARSE_TYPE_UNCLASSIFIED if the field’s data type has no\n\
known description or is an integer. Otherwise it returns another enum.\n\
Fields with the type AUPARSE_TYPE_ESCAPED must be interpreted to access\n\
their value since those field’s raw value is encoded.\n\
");
static PyObject *
AuParser_get_field_type(AuParser *self)
{
    int value;

    PARSER_CHECK;
    value = auparse_get_field_type(self->au);
    return Py_BuildValue("i", value);
}

/********************************
 * auparse_get_field_int
 ********************************/
PyDoc_STRVAR(get_field_int_doc,
"get_field_int() Get current field’s value as an integer.\n\
\n\
get_field_int() allows access to the value as an int of the current\n\
field of the current record in the current event.\n\
\n\
Returns field's numeric value.\n\
Raises exception (EnvironmentError) on error\n\
");
static PyObject *
AuParser_get_field_int(AuParser *self)
{
    int value;

    PARSER_CHECK;
    value = auparse_get_field_int(self->au);
    if (errno == 0) return Py_BuildValue("i", value);
    PyErr_SetFromErrno(PyExc_EnvironmentError);
    return NULL;
}

PyDoc_STRVAR(interpret_field_doc,
"interpret_field() Return an interpretation of the current field as a string that has the chosen character escaping applied.\n\
\n\
If the field cannot be interpreted the field is returned unmodified.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_interpret_field(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_interpret_field(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'interpretation' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

PyDoc_STRVAR(interpret_realpath_doc,
"interpret_realpath() Return an interpretation of the current field as a realpath string that has the chosen character escaping applied.\n\
\n\
If the field cannot be interpreted the field is returned unmodified.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_interpret_realpath(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_interpret_realpath(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'interpretation' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

PyDoc_STRVAR(interpret_sock_family_doc,
"interpret_sock_family() Return an interpretation of the current field's socket family. Only supported on sockaddr field types.\n\
\n\
If the field cannot be interpreted the field is returned unmodified.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_interpret_sock_family(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_interpret_sock_family(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'interpretation' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

PyDoc_STRVAR(interpret_sock_port_doc,
"interpret_sock_address() Return an interpretation of the current field's socket port. Only supported on sockaddr field types.\n\
\n\
If the field cannot be interpreted the field is returned unmodified.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_interpret_sock_port(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_interpret_sock_port(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'interpretation' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

PyDoc_STRVAR(interpret_sock_address_doc,
"interpret_sock_address() Return an interpretation of the current field's socket address. Only supported on sockaddr field types.\n\
\n\
If the field cannot be interpreted the field is returned unmodified.\n\
Raises exception (RuntimeError) on error\n\
");
static PyObject *
AuParser_interpret_sock_address(AuParser *self)
{
    const char *value = NULL;

    PARSER_CHECK;
    value = auparse_interpret_sock_address(self->au);
    if (value == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "'interpretation' is NULL");
        return NULL;
    }
    return Py_BuildValue("s", value);
}

static
PyGetSetDef AuParser_getseters[] = {
    {NULL}  /* Sentinel */
};

static
PyMemberDef AuParser_members[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef AuParser_methods[] = {
    {"feed",              (PyCFunction)AuParser_feed,              METH_VARARGS, feed_doc},
    {"flush_feed",        (PyCFunction)AuParser_flush_feed,        METH_NOARGS,  flush_feed_doc},
    {"feed_has_data",     (PyCFunction)AuParser_feed_has_data,     METH_NOARGS,  feed_has_data_doc},
    {"feed_age_events",   (PyCFunction)AuParser_feed_age_events,   METH_NOARGS,  feed_age_events_doc},
    {"add_callback",      (PyCFunction)AuParser_add_callback,      METH_VARARGS, add_callback_doc},
    {"set_escape_mode",   (PyCFunction)AuParser_set_escape_mode,   METH_VARARGS, set_escape_mode_doc},
    {"reset",             (PyCFunction)AuParser_reset,             METH_NOARGS,  reset_doc},
    {"search_add_expression", (PyCFunction)AuParser_search_add_expression, METH_VARARGS, search_add_expression_doc},
    {"search_add_item",   (PyCFunction)AuParser_search_add_item,   METH_VARARGS, search_add_item_doc},
    {"search_add_interpreted_item", (PyCFunction)AuParser_search_add_interpreted_item, METH_VARARGS, search_add_interpreted_item_doc},
    {"search_add_timestamp_item", (PyCFunction)AuParser_search_add_timestamp_item, METH_VARARGS, search_add_timestamp_item_doc},
    {"search_add_timestamp_item_ex", (PyCFunction)AuParser_search_add_timestamp_item_ex, METH_VARARGS, search_add_timestamp_item_ex_doc},
    {"search_add_regex",  (PyCFunction)AuParser_search_add_regex,  METH_VARARGS, search_add_regex_doc},
    {"search_set_stop",   (PyCFunction)AuParser_search_set_stop,   METH_VARARGS, search_set_stop_doc},
    {"search_clear",      (PyCFunction)AuParser_search_clear,      METH_NOARGS,  search_clear_doc},
    {"search_next_event", (PyCFunction)AuParser_search_next_event, METH_NOARGS,  search_next_event_doc},
    {"parse_next_event",  (PyCFunction)AuParser_parse_next_event,  METH_NOARGS,  parse_next_event_doc},
    {"aup_normalize",     (PyCFunction)AuParser_aup_normalize,     METH_VARARGS, aup_normalize_doc},
    {"aup_normalize_get_event_kind",  (PyCFunction)AuParser_aup_normalize_get_event_kind, METH_NOARGS, aup_normalize_get_event_kind_doc},
    {"aup_normalize_session",  (PyCFunction)AuParser_aup_normalize_session, METH_NOARGS, aup_normalize_session_doc},
    {"aup_normalize_subject_primary",  (PyCFunction)AuParser_aup_normalize_subject_primary, METH_NOARGS, aup_normalize_subject_primary_doc},
    {"aup_normalize_subject_secondary",  (PyCFunction)AuParser_aup_normalize_subject_secondary, METH_NOARGS, aup_normalize_subject_secondary_doc},
    {"aup_normalize_subject_first_attribute",  (PyCFunction)AuParser_aup_normalize_subject_first_attribute, METH_NOARGS, aup_normalize_subject_first_attribute_doc},
    {"aup_normalize_subject_next_attribute",  (PyCFunction)AuParser_aup_normalize_subject_next_attribute, METH_NOARGS, aup_normalize_subject_next_attribute_doc},
    {"aup_normalize_subject_kind",  (PyCFunction)AuParser_aup_normalize_subject_kind, METH_NOARGS, aup_normalize_subject_kind_doc},
    {"aup_normalize_get_action",  (PyCFunction)AuParser_aup_normalize_get_action, METH_NOARGS, aup_normalize_get_action_doc},
    {"aup_normalize_object_primary",  (PyCFunction)AuParser_aup_normalize_object_primary, METH_NOARGS, aup_normalize_object_primary_doc},
    {"aup_normalize_object_secondary",  (PyCFunction)AuParser_aup_normalize_object_secondary, METH_NOARGS, aup_normalize_object_secondary_doc},
    {"aup_normalize_object_first_attribute",  (PyCFunction)AuParser_aup_normalize_object_first_attribute, METH_NOARGS, aup_normalize_object_first_attribute_doc},
    {"aup_normalize_object_next_attribute",  (PyCFunction)AuParser_aup_normalize_object_next_attribute, METH_NOARGS, aup_normalize_object_next_attribute_doc},
    {"aup_normalize_object_kind",  (PyCFunction)AuParser_aup_normalize_object_kind, METH_NOARGS, aup_normalize_object_kind_doc},
    {"aup_normalize_get_results",  (PyCFunction)AuParser_aup_normalize_get_results, METH_NOARGS, aup_normalize_get_results_doc},
    {"aup_normalize_how", (PyCFunction)AuParser_aup_normalize_how, METH_NOARGS, aup_normalize_how_doc},
    {"aup_normalize_key", (PyCFunction)AuParser_aup_normalize_key, METH_NOARGS, aup_normalize_key_doc},
    {"get_timestamp",     (PyCFunction)AuParser_get_timestamp,     METH_NOARGS,  get_timestamp_doc},
    {"get_num_records",   (PyCFunction)AuParser_get_num_records,   METH_NOARGS,  get_num_records_doc},
    {"first_record",      (PyCFunction)AuParser_first_record,      METH_NOARGS,  first_record_doc},
    {"next_record",       (PyCFunction)AuParser_next_record,       METH_NOARGS,  next_record_doc},
    {"goto_record_num",   (PyCFunction)AuParser_goto_record_num,   METH_VARARGS,  goto_record_num_doc},
    {"get_type",          (PyCFunction)AuParser_get_type,          METH_NOARGS,  get_type_doc},
    {"get_type_name",     (PyCFunction)AuParser_get_type_name,     METH_NOARGS,  get_type_name_doc},
    {"get_line_number",   (PyCFunction)AuParser_get_line_number,   METH_NOARGS,  get_line_number_doc},
    {"get_filename",      (PyCFunction)AuParser_get_filename,      METH_NOARGS,  get_filename_doc},
    {"first_field",       (PyCFunction)AuParser_first_field,       METH_NOARGS,  first_field_doc},
    {"next_field",        (PyCFunction)AuParser_next_field,        METH_NOARGS,  next_field_doc},
    {"get_num_fields",    (PyCFunction)AuParser_get_num_fields,    METH_NOARGS,  get_num_fields_doc},
    {"get_record_text",   (PyCFunction)AuParser_get_record_text,   METH_NOARGS,  get_record_text_doc},
    {"find_field_next",   (PyCFunction)AuParser_find_field_next,   METH_NOARGS,  find_field_next_doc},
    {"find_field",        (PyCFunction)AuParser_find_field,        METH_VARARGS, find_field_doc},
    {"get_field_name",    (PyCFunction)AuParser_get_field_name,    METH_NOARGS,  get_field_name_doc},
    {"get_field_str",     (PyCFunction)AuParser_get_field_str,     METH_NOARGS,  get_field_str_doc},
    {"get_field_type",    (PyCFunction)AuParser_get_field_type,    METH_NOARGS,  get_field_type_doc},
    {"get_field_int",     (PyCFunction)AuParser_get_field_int,     METH_NOARGS,  get_field_int_doc},
    {"interpret_field",   (PyCFunction)AuParser_interpret_field,   METH_NOARGS,  interpret_field_doc},
    {"interpret_realpath",   (PyCFunction)AuParser_interpret_realpath, METH_NOARGS,  interpret_realpath_doc},
    {"interpret_sock_family",   (PyCFunction)AuParser_interpret_sock_family, METH_NOARGS,  interpret_sock_family_doc},
    {"interpret_sock_port",   (PyCFunction)AuParser_interpret_sock_port, METH_NOARGS,  interpret_sock_port_doc},
    {"interpret_sock_address",   (PyCFunction)AuParser_interpret_sock_address, METH_NOARGS,  interpret_sock_address_doc},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyDoc_STRVAR(AuParser_doc,
"AuParser(source_type, source)\n\
\n\
Construct a new audit parser object and bind it to input data.\n\
source_type: one of the AUSOURCE_* constants.\n\
source:      the input data, dependent on the source_type as follows:\n\
\n\
AUSOURCE_LOGS:         None (system log files will be parsed)\n\
AUSOURCE_FILE:         string containing file path name\n\
AUSOURCE_FILE_ARRAY:   list or tuple of strings each containing a file path name\n\
AUSOURCE_BUFFER:       string containing audit data to parse\n\
AUSOURCE_BUFFER_ARRAY: list or tuple of strings each containing audit data to parse\n\
AUSOURCE_DESCRIPTOR:   integer file descriptor (e.g. fileno)\n\
AUSOURCE_FILE_POINTER: file object (e.g. types.FileType)\n\
AUSOURCE_FEED:         None (data supplied via feed()\n\
");

static PyTypeObject AuParserType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "auparse.AuParser",         /*tp_name*/
    sizeof(AuParser),           /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)AuParser_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    AuParser_doc,              /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    AuParser_methods,           /* tp_methods */
    AuParser_members,                        /* tp_members */
    AuParser_getseters,         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)AuParser_init,  /* tp_init */
    0,                         /* tp_alloc */
    AuParser_new,              /* tp_new */
};



/*===========================================================================
 *                                Module
 *===========================================================================*/

#ifndef IS_PY3K
PyDoc_STRVAR(auparse_doc,
"Parsing library for audit messages.\n\
\n\
The module defines the following exceptions:\n\
\n\
NoParser: Raised if the underlying C code parser is not bound to the AuParser object.\n\
");
#endif

static PyMethodDef module_methods[] = {
    {NULL}  /* Sentinel */
};

#ifdef IS_PY3K
static struct PyModuleDef auparse_def = {
    PyModuleDef_HEAD_INIT,
    "auparse",
    NULL,
    -1,
    module_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_auparse(void)
#else
PyMODINIT_FUNC
initauparse(void) 
#endif
{
    PyObject* m;

    if (PyType_Ready(&AuEventType) < 0) MODINITERROR;
    if (PyType_Ready(&AuParserType) < 0) MODINITERROR;

#ifdef IS_PY3K
    m = PyModule_Create(&auparse_def);
#else
    m = Py_InitModule3("auparse", module_methods, auparse_doc);
#endif

    if (m == NULL)
      MODINITERROR;

    Py_INCREF(&AuParserType);
    PyModule_AddObject(m, "AuParser", (PyObject *)&AuParserType);

    Py_INCREF(&AuEventType);
    PyModule_AddObject(m, "AuEvent", (PyObject *)&AuEventType);

    /* exceptions */
    NoParserError = PyErr_NewException("auparse.NoParser", NULL, NULL);
    Py_INCREF(NoParserError);
    PyModule_AddObject(m, "NoParser", NoParserError);

    /* ausource_t */
    PyModule_AddIntConstant(m, "AUSOURCE_LOGS",          AUSOURCE_LOGS);
    PyModule_AddIntConstant(m, "AUSOURCE_FILE",          AUSOURCE_FILE);
    PyModule_AddIntConstant(m, "AUSOURCE_FILE_ARRAY",    AUSOURCE_FILE_ARRAY);
    PyModule_AddIntConstant(m, "AUSOURCE_BUFFER",        AUSOURCE_BUFFER);
    PyModule_AddIntConstant(m, "AUSOURCE_BUFFER_ARRAY",  AUSOURCE_BUFFER_ARRAY);
    PyModule_AddIntConstant(m, "AUSOURCE_DESCRIPTOR",    AUSOURCE_DESCRIPTOR);
    PyModule_AddIntConstant(m, "AUSOURCE_FILE_POINTER",  AUSOURCE_FILE_POINTER);
    PyModule_AddIntConstant(m, "AUSOURCE_FEED",          AUSOURCE_FEED);

    /* ausearch_op_t */
    PyModule_AddIntConstant(m, "AUSEARCH_UNSET",         AUSEARCH_UNSET);
    PyModule_AddIntConstant(m, "AUSEARCH_EXISTS",        AUSEARCH_EXISTS);
    PyModule_AddIntConstant(m, "AUSEARCH_EQUAL",         AUSEARCH_EQUAL);
    PyModule_AddIntConstant(m, "AUSEARCH_NOT_EQUAL",     AUSEARCH_NOT_EQUAL);
    PyModule_AddIntConstant(m, "AUSEARCH_TIME_LT",       AUSEARCH_TIME_LT);
    PyModule_AddIntConstant(m, "AUSEARCH_TIME_LE",       AUSEARCH_TIME_LE);
    PyModule_AddIntConstant(m, "AUSEARCH_TIME_GE",       AUSEARCH_TIME_GE);
    PyModule_AddIntConstant(m, "AUSEARCH_TIME_GT",       AUSEARCH_TIME_GT);
    PyModule_AddIntConstant(m, "AUSEARCH_TIME_EQ",       AUSEARCH_TIME_EQ);
    PyModule_AddIntConstant(m, "AUSEARCH_INTERPRETED",   0x40000000);

    /* austop_t */
    PyModule_AddIntConstant(m, "AUSEARCH_STOP_EVENT",    AUSEARCH_STOP_EVENT);
    PyModule_AddIntConstant(m, "AUSEARCH_STOP_RECORD",   AUSEARCH_STOP_RECORD);
    PyModule_AddIntConstant(m, "AUSEARCH_STOP_FIELD",    AUSEARCH_STOP_FIELD);

    /* normalize_option_t */
    PyModule_AddIntConstant(m, "NORM_OPT_ALL", NORM_OPT_ALL);
    PyModule_AddIntConstant(m, "NORM_OPT_NO_ATTRS", NORM_OPT_NO_ATTRS);

    /* ausearch_rule_t */
    PyModule_AddIntConstant(m, "AUSEARCH_RULE_CLEAR",    AUSEARCH_RULE_CLEAR);
    PyModule_AddIntConstant(m, "AUSEARCH_RULE_OR",       AUSEARCH_RULE_OR);
    PyModule_AddIntConstant(m, "AUSEARCH_RULE_AND",      AUSEARCH_RULE_AND);
    PyModule_AddIntConstant(m, "AUSEARCH_RULE_REGEX",    AUSEARCH_RULE_REGEX);

    /* auparse_cb_event_t */
    PyModule_AddIntConstant(m, "AUPARSE_CB_EVENT_READY", AUPARSE_CB_EVENT_READY);
    /* auparse_type_t */
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_UNCLASSIFIED", AUPARSE_TYPE_UNCLASSIFIED);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_UID",     AUPARSE_TYPE_UID);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_GID",     AUPARSE_TYPE_GID);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SYSCALL", AUPARSE_TYPE_SYSCALL);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ARCH",    AUPARSE_TYPE_ARCH);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_EXIT",    AUPARSE_TYPE_EXIT);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ESCAPED", AUPARSE_TYPE_ESCAPED);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_PERM",    AUPARSE_TYPE_PERM);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_MODE",    AUPARSE_TYPE_MODE);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SOCKADDR", AUPARSE_TYPE_SOCKADDR);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_FLAGS",   AUPARSE_TYPE_FLAGS);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_PROMISC", AUPARSE_TYPE_PROMISC);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_CAPABILITY", AUPARSE_TYPE_CAPABILITY);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SUCCESS", AUPARSE_TYPE_SUCCESS);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_A0",      AUPARSE_TYPE_A0);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_A1",      AUPARSE_TYPE_A1);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_A2",      AUPARSE_TYPE_A2);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SIGNAL",  AUPARSE_TYPE_SIGNAL);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_LIST",    AUPARSE_TYPE_LIST);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_TTY_DATA", AUPARSE_TYPE_TTY_DATA);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SESSION", AUPARSE_TYPE_SESSION);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_CAP_BITMAP", AUPARSE_TYPE_CAP_BITMAP);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_NFPROTO", AUPARSE_TYPE_NFPROTO);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ICMPTYPE", AUPARSE_TYPE_ICMPTYPE);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_PROTOCOL", AUPARSE_TYPE_PROTOCOL);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ADDR", AUPARSE_TYPE_ADDR);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_PERSONALITY", AUPARSE_TYPE_PERSONALITY);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_SECCOMP", AUPARSE_TYPE_SECCOMP);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_OFLAG", AUPARSE_TYPE_OFLAG);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_MMAP", AUPARSE_TYPE_MMAP);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_MODE_SHORT", AUPARSE_TYPE_MODE_SHORT);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_MAC_LABEL", AUPARSE_TYPE_MAC_LABEL);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_PROCTITLE", AUPARSE_TYPE_PROCTITLE);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_HOOK", AUPARSE_TYPE_HOOK);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_NETACTION", AUPARSE_TYPE_NETACTION);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_IOCTL_REQ", AUPARSE_TYPE_IOCTL_REQ);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ESCAPED_KEY", AUPARSE_TYPE_ESCAPED_KEY);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_ESCAPED_FILE", AUPARSE_TYPE_ESCAPED_FILE);
    PyModule_AddIntConstant(m, "AUPARSE_TYPE_FANOTIFY", AUPARSE_TYPE_FANOTIFY);

    /* Escape types */
    PyModule_AddIntConstant(m, "AUPARSE_ESC_RAW", AUPARSE_ESC_RAW);
    PyModule_AddIntConstant(m, "AUPARSE_ESC_TTY", AUPARSE_ESC_TTY);
    PyModule_AddIntConstant(m, "AUPARSE_ESC_SHELL", AUPARSE_ESC_SHELL);
    PyModule_AddIntConstant(m, "AUPARSE_ESC_SHELL_QUOTE", AUPARSE_ESC_SHELL_QUOTE);

#ifdef IS_PY3K
    return m;
#endif
}
