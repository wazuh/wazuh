#ifndef KERBEROS_H
#define KERBEROS_H

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

extern "C" {
  #include "kerberos_sspi.h"
  #include "base64.h"
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
  static Handle<Value> AcquireAlternateCredentials(const Arguments &args);
  static Handle<Value> PrepareOutboundPackage(const Arguments &args);
  static Handle<Value> DecryptMessage(const Arguments &args);
  static Handle<Value> EncryptMessage(const Arguments &args);
  static Handle<Value> QueryContextAttributes(const Arguments &args);

private:
  static Handle<Value> New(const Arguments &args);  

  // Pointer to context object
  SEC_WINNT_AUTH_IDENTITY m_Identity;
  // credentials
  CredHandle m_Credentials;
  // Expiry time for ticket
  TimeStamp Expiration;
  // package info
  SecPkgInfo m_PkgInfo;
  // context
  CtxtHandle m_Context;
  // Do we have a context
  bool m_HaveContext;
  // Attributes
  DWORD CtxtAttr;

  // Handles the uv calls
  static void Process(uv_work_t* work_req);
  // Called after work is done
  static void After(uv_work_t* work_req);
};

#endif