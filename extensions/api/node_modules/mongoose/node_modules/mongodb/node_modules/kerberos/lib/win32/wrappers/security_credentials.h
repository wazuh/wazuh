#ifndef SECURITY_CREDENTIALS_H
#define SECURITY_CREDENTIALS_H

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#define SECURITY_WIN32 1

#include <windows.h>
#include <sspi.h>
#include <tchar.h>
#include "../worker.h"
#include <uv.h>

extern "C" {
  #include "../kerberos_sspi.h"
}

// SEC_WINNT_AUTH_IDENTITY makes it unusually hard
// to compile for both Unicode and ansi, so I use this macro:
#ifdef _UNICODE
#define USTR(str) (str)
#else
#define USTR(str) ((unsigned char*)(str))
#endif

using namespace v8;
using namespace node;

class SecurityCredentials : public ObjectWrap {  
  public:    
    SecurityCredentials();
    ~SecurityCredentials();    

    // Pointer to context object
    SEC_WINNT_AUTH_IDENTITY m_Identity;
    // credentials
    CredHandle m_Credentials;    
    // Expiry time for ticket
    TimeStamp Expiration;

    // Has instance check
    static inline bool HasInstance(Handle<Value> val) {
      if (!val->IsObject()) return false;
      Local<Object> obj = val->ToObject();
      return constructor_template->HasInstance(obj);
    };

    // Functions available from V8
    static void Initialize(Handle<Object> target);    
    static Handle<Value> AquireSync(const Arguments &args);
    static Handle<Value> Aquire(const Arguments &args);

    // Constructor used for creating new Long objects from C++
    static Persistent<FunctionTemplate> constructor_template;
    
  private:
    // Create a new instance
    static Handle<Value> New(const Arguments &args);
    // Handles the uv calls
    static void Process(uv_work_t* work_req);
    // Called after work is done
    static void After(uv_work_t* work_req);
};

#endif