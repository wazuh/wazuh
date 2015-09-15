#include "kerberos_context.h"

Persistent<FunctionTemplate> KerberosContext::constructor_template;

KerberosContext::KerberosContext() : ObjectWrap() {
}

KerberosContext::~KerberosContext() {
}

KerberosContext* KerberosContext::New() {
  HandleScope scope;
  
  Local<Object> obj = constructor_template->GetFunction()->NewInstance();
  KerberosContext *kerberos_context = ObjectWrap::Unwrap<KerberosContext>(obj);  
  
  return kerberos_context;
}

Handle<Value> KerberosContext::New(const Arguments &args) {
  HandleScope scope;    
  // Create code object
  KerberosContext *kerberos_context = new KerberosContext();
  // Wrap it
  kerberos_context->Wrap(args.This());
  // Return the object
  return args.This();    
}

static Persistent<String> response_symbol;

void KerberosContext::Initialize(Handle<Object> target) {
  // Grab the scope of the call from Node
  HandleScope scope;
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  constructor_template = Persistent<FunctionTemplate>::New(t);
  constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
  constructor_template->SetClassName(String::NewSymbol("KerberosContext"));

  // Property symbols
  response_symbol = NODE_PSYMBOL("response");
    
  // Getter for the response
  constructor_template->InstanceTemplate()->SetAccessor(response_symbol, ResponseGetter);

  // Set up the Symbol for the Class on the Module
  target->Set(String::NewSymbol("KerberosContext"), constructor_template->GetFunction());
}

//
// Response Setter / Getter
Handle<Value> KerberosContext::ResponseGetter(Local<String> property, const AccessorInfo& info) {
  HandleScope scope;
  gss_client_state *state;

  // Unpack the object
  KerberosContext *context = ObjectWrap::Unwrap<KerberosContext>(info.Holder());
  // Let's grab the response
  state = context->state;
  // No state no response
  if(state == NULL || state->response == NULL) return scope.Close(Null());
  // Return the response
  return scope.Close(String::New(state->response));
}









