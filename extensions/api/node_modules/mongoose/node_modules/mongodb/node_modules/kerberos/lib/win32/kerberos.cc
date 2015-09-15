#include "kerberos.h"
#include <stdlib.h>
#include <tchar.h>
#include "base64.h"
#include "wrappers/security_buffer.h"
#include "wrappers/security_buffer_descriptor.h"
#include "wrappers/security_context.h"
#include "wrappers/security_credentials.h"

Persistent<FunctionTemplate> Kerberos::constructor_template;

// VException object (causes throw in calling code)
static Handle<Value> VException(const char *msg) {
  HandleScope scope;
  return ThrowException(Exception::Error(String::New(msg)));
}

Kerberos::Kerberos() : ObjectWrap() {
}

void Kerberos::Initialize(v8::Handle<v8::Object> target) {
  // Grab the scope of the call from Node
  HandleScope scope;
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(Kerberos::New);
  constructor_template = Persistent<FunctionTemplate>::New(t);
  constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
  constructor_template->SetClassName(String::NewSymbol("Kerberos"));
  // Set the symbol
  target->ForceSet(String::NewSymbol("Kerberos"), constructor_template->GetFunction());
}

Handle<Value> Kerberos::New(const Arguments &args) {
  // Load the security.dll library
  load_library();
  // Create a Kerberos instance
  Kerberos *kerberos = new Kerberos();
  // Return the kerberos object
  kerberos->Wrap(args.This());
  return args.This();
}

// Exporting function
extern "C" void init(Handle<Object> target) {
  HandleScope scope;
  Kerberos::Initialize(target);
  SecurityContext::Initialize(target);
  SecurityBuffer::Initialize(target);
  SecurityBufferDescriptor::Initialize(target);
  SecurityCredentials::Initialize(target);
}

NODE_MODULE(kerberos, init);
