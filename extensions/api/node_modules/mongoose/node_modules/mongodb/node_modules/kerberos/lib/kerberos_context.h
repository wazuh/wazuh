#ifndef KERBEROS_CONTEXT_H
#define KERBEROS_CONTEXT_H

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

class KerberosContext : public ObjectWrap {

public:
  KerberosContext();
  ~KerberosContext();

  static inline bool HasInstance(Handle<Value> val) {
    if (!val->IsObject()) return false;
    Local<Object> obj = val->ToObject();
    return constructor_template->HasInstance(obj);
  };

  // Constructor used for creating new Kerberos objects from C++
  static Persistent<FunctionTemplate> constructor_template;

  // Initialize function for the object
  static void Initialize(Handle<Object> target);

  // Public constructor
  static KerberosContext* New();

  // Handle to the kerberos context
  gss_client_state *state;

private:
  static Handle<Value> New(const Arguments &args);  

  static Handle<Value> ResponseGetter(Local<String> property, const AccessorInfo& info);  
};
#endif