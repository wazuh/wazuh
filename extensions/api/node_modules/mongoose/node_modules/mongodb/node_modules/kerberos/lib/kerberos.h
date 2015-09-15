#ifndef KERBEROS_H
#define KERBEROS_H

#include <node.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#include <node_object_wrap.h>
#include <v8.h>

extern "C" {
  #include "kerberosgss.h"
}

using namespace v8;
using namespace node;

class Kerberos : public ObjectWrap {

public:
  Kerberos();
  ~Kerberos() {};

  // Constructor used for creating new Kerberos objects from C++
  static Persistent<FunctionTemplate> constructor_template;

  // Initialize function for the object
  static void Initialize(Handle<Object> target);

  // Method available
  static Handle<Value> AuthGSSClientInit(const Arguments &args);
  static Handle<Value> AuthGSSClientStep(const Arguments &args);
  static Handle<Value> AuthGSSClientUnwrap(const Arguments &args);
  static Handle<Value> AuthGSSClientWrap(const Arguments &args);
  static Handle<Value> AuthGSSClientClean(const Arguments &args);

private:
  static Handle<Value> New(const Arguments &args);  

  // Handles the uv calls
  static void Process(uv_work_t* work_req);
  // Called after work is done
  static void After(uv_work_t* work_req);
};

#endif