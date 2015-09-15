#ifndef SECURITY_CONTEXT_H
#define SECURITY_CONTEXT_H

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#define SECURITY_WIN32 1

#include <sspi.h>
#include <tchar.h>
#include "security_credentials.h"
#include "../worker.h"

extern "C" {
  #include "../kerberos_sspi.h"
  #include "../base64.h"
}

using namespace v8;
using namespace node;

class SecurityContext : public ObjectWrap {  
  public:    
    SecurityContext();
    ~SecurityContext();    

    // Security info package
    PSecPkgInfo m_PkgInfo;
    // Do we have a context
    bool hasContext;
    // Reference to security credentials
    SecurityCredentials *security_credentials;
    // Security context
    CtxtHandle m_Context;
    // Attributes
    DWORD CtxtAttr;
    // Expiry time for ticket
    TimeStamp Expiration;
    // Payload
    char *payload;

    // Has instance check
    static inline bool HasInstance(Handle<Value> val) {
      if (!val->IsObject()) return false;
      Local<Object> obj = val->ToObject();
      return constructor_template->HasInstance(obj);
    };

    // Functions available from V8
    static void Initialize(Handle<Object> target);    

    static Handle<Value> InitializeContext(const Arguments &args);
    static Handle<Value> InitializeContextSync(const Arguments &args);
    
    static Handle<Value> InitalizeStep(const Arguments &args);
    static Handle<Value> InitalizeStepSync(const Arguments &args);

    static Handle<Value> DecryptMessage(const Arguments &args);
    static Handle<Value> DecryptMessageSync(const Arguments &args);

    static Handle<Value> QueryContextAttributesSync(const Arguments &args);
    static Handle<Value> QueryContextAttributes(const Arguments &args);

    static Handle<Value> EncryptMessageSync(const Arguments &args);
    static Handle<Value> EncryptMessage(const Arguments &args);

    // Payload getter
    static Handle<Value> PayloadGetter(Local<String> property, const AccessorInfo& info);
    // hasContext getter
    static Handle<Value> HasContextGetter(Local<String> property, const AccessorInfo& info);

    // Constructor used for creating new Long objects from C++
    static Persistent<FunctionTemplate> constructor_template;
    
  private:
    // Create a new instance
    static Handle<Value> New(const Arguments &args);
    // // Handles the uv calls
    // static void Process(uv_work_t* work_req);
    // // Called after work is done
    // static void After(uv_work_t* work_req);
};

#endif
