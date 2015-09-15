#ifndef WORKER_H_
#define WORKER_H_

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

using namespace node;
using namespace v8;

class Worker {
  public:
    Worker();
    virtual ~Worker();

    // libuv's request struct.
    uv_work_t request;
    // Callback
    v8::Persistent<v8::Function> callback;
    // Parameters
    void *parameters;
    // Results
    void *return_value;
    // Did we raise an error
    bool error;
    // The error message
    char *error_message;
    // Error code if not message
    int error_code;
    // Any return code
    int return_code;
    // Method we are going to fire
    void (*execute)(Worker *worker);
    Handle<Value> (*mapper)(Worker *worker);
};

#endif  // WORKER_H_
