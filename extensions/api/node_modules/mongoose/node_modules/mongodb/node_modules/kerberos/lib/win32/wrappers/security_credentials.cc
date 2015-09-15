#include <node.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <v8.h>
#include <node_buffer.h>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>

#include "security_credentials.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#endif

static LPSTR DisplaySECError(DWORD ErrCode);

static Handle<Value> VException(const char *msg) {
  HandleScope scope;
  return ThrowException(Exception::Error(String::New(msg)));
};

static Handle<Value> VExceptionErrNo(const char *msg, const int errorNumber) {
  HandleScope scope;

  Local<Value> err = Exception::Error(String::New(msg));
  Local<Object> obj = err->ToObject();
  obj->Set(NODE_PSYMBOL("code"), Int32::New(errorNumber));
  return ThrowException(err);
};

Persistent<FunctionTemplate> SecurityCredentials::constructor_template;

SecurityCredentials::SecurityCredentials() : ObjectWrap() {
}

SecurityCredentials::~SecurityCredentials() {
}

Handle<Value> SecurityCredentials::New(const Arguments &args) {
  HandleScope scope;  

  // Create security credentials instance
  SecurityCredentials *security_credentials = new SecurityCredentials();
  // Wrap it
  security_credentials->Wrap(args.This());
  // Return the object
  return args.This();
}

Handle<Value> SecurityCredentials::AquireSync(const Arguments &args) {
  HandleScope scope;  
  char *package_str = NULL, *username_str = NULL, *password_str = NULL, *domain_str = NULL;
  // Status of operation
  SECURITY_STATUS status;

  // Unpack the variables
  if(args.Length() != 2 && args.Length() != 3 && args.Length() != 4)
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string]]");

  if(!args[0]->IsString())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string]]");

  if(!args[1]->IsString())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string]]");

  if(args.Length() == 3 && !args[2]->IsString())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string]]");

  if(args.Length() == 4 && (!args[3]->IsString() && !args[3]->IsUndefined() && !args[3]->IsNull()))
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string]]");

  // Unpack the package
  Local<String> package = args[0]->ToString();
  package_str = (char *)calloc(package->Utf8Length() + 1, sizeof(char));
  package->WriteUtf8(package_str);

  // Unpack the user name
  Local<String> username = args[1]->ToString();
  username_str = (char *)calloc(username->Utf8Length() + 1, sizeof(char));
  username->WriteUtf8(username_str);

  // If we have a password
  if(args.Length() == 3 || args.Length() == 4) {
    Local<String> password = args[2]->ToString();
    password_str = (char *)calloc(password->Utf8Length() + 1, sizeof(char));
    password->WriteUtf8(password_str);    
  }

  // If we have a domain
  if(args.Length() == 4 && args[3]->IsString()) {
    Local<String> domain = args[3]->ToString();
    domain_str = (char *)calloc(domain->Utf8Length() + 1, sizeof(char));
    domain->WriteUtf8(domain_str);    
  }

  // Create Security instance
  Local<Object> security_credentials_value = constructor_template->GetFunction()->NewInstance();

  // Unwrap the credentials
  SecurityCredentials *security_credentials = ObjectWrap::Unwrap<SecurityCredentials>(security_credentials_value);

  // If we have domain string
  if(domain_str != NULL) {
    security_credentials->m_Identity.Domain = USTR(_tcsdup(domain_str));
    security_credentials->m_Identity.DomainLength = (unsigned long)_tcslen(domain_str);
  } else {
    security_credentials->m_Identity.Domain = NULL;
    security_credentials->m_Identity.DomainLength = 0;
  }

  // Set up the user
  security_credentials->m_Identity.User = USTR(_tcsdup(username_str));
  security_credentials->m_Identity.UserLength = (unsigned long)_tcslen(username_str);

  // If we have a password string
  if(password_str != NULL) {
    // Set up the password
    security_credentials->m_Identity.Password = USTR(_tcsdup(password_str));
    security_credentials->m_Identity.PasswordLength = (unsigned long)_tcslen(password_str);    
  }

  #ifdef _UNICODE
    security_credentials->m_Identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  #else
    security_credentials->m_Identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
  #endif

  // Attempt to acquire credentials
  status = _sspi_AcquireCredentialsHandle(
    NULL,
    package_str,
    SECPKG_CRED_OUTBOUND,
    NULL, 
    password_str != NULL ? &security_credentials->m_Identity : NULL,
    NULL, NULL,
    &security_credentials->m_Credentials,
    &security_credentials->Expiration
  );

  // We have an error
  if(status != SEC_E_OK) {
    LPSTR err_message = DisplaySECError(status);

    if(err_message != NULL) {
      return VExceptionErrNo(err_message, status);
    } else {
      return VExceptionErrNo("Unknown error", status);
    }
  }

  // Make object persistent
  Persistent<Object> persistent = Persistent<Object>::New(security_credentials_value);
  // Return the object
  return scope.Close(persistent);
}

// Call structs
typedef struct SecurityCredentialCall {
  char *package_str;
  char *username_str;
  char *password_str;
  char *domain_str;
  SecurityCredentials *credentials;
} SecurityCredentialCall;

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// authGSSClientInit
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static void _authSSPIAquire(Worker *worker) {
  // Status of operation
  SECURITY_STATUS status;

  // Unpack data
  SecurityCredentialCall *call = (SecurityCredentialCall *)worker->parameters;  

  // Unwrap the credentials
  SecurityCredentials *security_credentials = (SecurityCredentials *)call->credentials;

  // If we have domain string
  if(call->domain_str != NULL) {
    security_credentials->m_Identity.Domain = USTR(_tcsdup(call->domain_str));
    security_credentials->m_Identity.DomainLength = (unsigned long)_tcslen(call->domain_str);
  } else {
    security_credentials->m_Identity.Domain = NULL;
    security_credentials->m_Identity.DomainLength = 0;
  }

  // Set up the user
  security_credentials->m_Identity.User = USTR(_tcsdup(call->username_str));
  security_credentials->m_Identity.UserLength = (unsigned long)_tcslen(call->username_str);

  // If we have a password string
  if(call->password_str != NULL) {
    // Set up the password
    security_credentials->m_Identity.Password = USTR(_tcsdup(call->password_str));
    security_credentials->m_Identity.PasswordLength = (unsigned long)_tcslen(call->password_str);    
  }

  #ifdef _UNICODE
    security_credentials->m_Identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  #else
    security_credentials->m_Identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
  #endif

  // Attempt to acquire credentials
  status = _sspi_AcquireCredentialsHandle(
    NULL,
    call->package_str,
    SECPKG_CRED_OUTBOUND,
    NULL, 
    call->password_str != NULL ? &security_credentials->m_Identity : NULL,
    NULL, NULL,
    &security_credentials->m_Credentials,
    &security_credentials->Expiration
  );

  // We have an error
  if(status != SEC_E_OK) {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  } else {
    worker->return_code = status;
    worker->return_value = security_credentials;
  }

  // Free up parameter structure
  if(call->package_str != NULL) free(call->package_str);
  if(call->domain_str != NULL) free(call->domain_str);
  if(call->password_str != NULL) free(call->password_str);
  if(call->username_str != NULL) free(call->username_str);
  free(call);
}

static Handle<Value> _map_authSSPIAquire(Worker *worker) {
  HandleScope scope;

  // Unpack the credentials
  SecurityCredentials *security_credentials = (SecurityCredentials *)worker->return_value;
  // Make object persistent
  Persistent<Object> persistent = Persistent<Object>::New(security_credentials->handle_);
  // Return the object
  return scope.Close(persistent);
}

Handle<Value> SecurityCredentials::Aquire(const Arguments &args) {
  HandleScope scope;  
  char *package_str = NULL, *username_str = NULL, *password_str = NULL, *domain_str = NULL;
  // Unpack the variables
  if(args.Length() != 2 && args.Length() != 3 && args.Length() != 4 && args.Length() != 5)
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  if(!args[0]->IsString())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  if(!args[1]->IsString())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  if(args.Length() == 3 && (!args[2]->IsString() && !args[2]->IsFunction()))
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  if(args.Length() == 4 && (!args[3]->IsString() && !args[3]->IsUndefined() && !args[3]->IsNull()) && !args[3]->IsFunction())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  if(args.Length() == 5 && !args[4]->IsFunction())
    return VException("Aquire must be called with either [package:string, username:string, [password:string, domain:string], callback:function]");

  Local<Function> callback;

  // Figure out which parameter is the callback
  if(args.Length() == 5) {
    callback = Local<Function>::Cast(args[4]);
  } else if(args.Length() == 4) {
    callback = Local<Function>::Cast(args[3]);
  } else if(args.Length() == 3) {
    callback = Local<Function>::Cast(args[2]);
  }

  // Unpack the package
  Local<String> package = args[0]->ToString();
  package_str = (char *)calloc(package->Utf8Length() + 1, sizeof(char));
  package->WriteUtf8(package_str);

  // Unpack the user name
  Local<String> username = args[1]->ToString();
  username_str = (char *)calloc(username->Utf8Length() + 1, sizeof(char));
  username->WriteUtf8(username_str);

  // If we have a password
  if(args.Length() == 3 || args.Length() == 4 || args.Length() == 5) {
    Local<String> password = args[2]->ToString();
    password_str = (char *)calloc(password->Utf8Length() + 1, sizeof(char));
    password->WriteUtf8(password_str);    
  }

  // If we have a domain
  if((args.Length() == 4 || args.Length() == 5) && args[3]->IsString()) {
    Local<String> domain = args[3]->ToString();
    domain_str = (char *)calloc(domain->Utf8Length() + 1, sizeof(char));
    domain->WriteUtf8(domain_str);    
  }

  // Create reference object
  Local<Object> security_credentials_value = constructor_template->GetFunction()->NewInstance();
  // Unwrap object
  SecurityCredentials *security_credentials = ObjectWrap::Unwrap<SecurityCredentials>(security_credentials_value);

  // Allocate call structure
  SecurityCredentialCall *call = (SecurityCredentialCall *)calloc(1, sizeof(SecurityCredentialCall));
  call->domain_str = domain_str;
  call->package_str = package_str;
  call->password_str = password_str;
  call->username_str = username_str;
  call->credentials = security_credentials;

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _authSSPIAquire;
  worker->mapper = _map_authSSPIAquire;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, SecurityCredentials::Process, (uv_after_work_cb)SecurityCredentials::After);

  // Return the undefined value
  return scope.Close(Undefined());
}

void SecurityCredentials::Initialize(Handle<Object> target) {
  // Grab the scope of the call from Node
  HandleScope scope;
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  constructor_template = Persistent<FunctionTemplate>::New(t);
  constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
  constructor_template->SetClassName(String::NewSymbol("SecurityCredentials"));

  // Class methods
  NODE_SET_METHOD(constructor_template, "aquireSync", AquireSync);
  NODE_SET_METHOD(constructor_template, "aquire", Aquire);

  // Set the class on the target module
  target->Set(String::NewSymbol("SecurityCredentials"), constructor_template->GetFunction());  

  // Attempt to load the security.dll library
  load_library();
}

static LPSTR DisplaySECError(DWORD ErrCode) {
  LPSTR pszName = NULL; // WinError.h

  switch(ErrCode) {
    case SEC_E_BUFFER_TOO_SMALL:
      pszName = "SEC_E_BUFFER_TOO_SMALL - The message buffer is too small. Used with the Digest SSP.";
      break;

    case SEC_E_CRYPTO_SYSTEM_INVALID:
      pszName = "SEC_E_CRYPTO_SYSTEM_INVALID - The cipher chosen for the security context is not supported. Used with the Digest SSP."; 
      break;
    case SEC_E_INCOMPLETE_MESSAGE:
      pszName = "SEC_E_INCOMPLETE_MESSAGE - The data in the input buffer is incomplete. The application needs to read more data from the server and call DecryptMessage (General) again."; 
      break;

    case SEC_E_INVALID_HANDLE:
      pszName = "SEC_E_INVALID_HANDLE - A context handle that is not valid was specified in the phContext parameter. Used with the Digest and Schannel SSPs."; 
      break;

    case SEC_E_INVALID_TOKEN:
      pszName = "SEC_E_INVALID_TOKEN - The buffers are of the wrong type or no buffer of type SECBUFFER_DATA was found. Used with the Schannel SSP."; 
      break;
        
    case SEC_E_MESSAGE_ALTERED:
      pszName = "SEC_E_MESSAGE_ALTERED - The message has been altered. Used with the Digest and Schannel SSPs."; 
      break;
        
    case SEC_E_OUT_OF_SEQUENCE:
      pszName = "SEC_E_OUT_OF_SEQUENCE - The message was not received in the correct sequence."; 
      break;
        
    case SEC_E_QOP_NOT_SUPPORTED:
      pszName = "SEC_E_QOP_NOT_SUPPORTED - Neither confidentiality nor integrity are supported by the security context. Used with the Digest SSP."; 
      break;
        
    case SEC_I_CONTEXT_EXPIRED:
      pszName = "SEC_I_CONTEXT_EXPIRED - The message sender has finished using the connection and has initiated a shutdown."; 
      break;
        
    case SEC_I_RENEGOTIATE:
      pszName = "SEC_I_RENEGOTIATE - The remote party requires a new handshake sequence or the application has just initiated a shutdown."; 
      break;
        
    case SEC_E_ENCRYPT_FAILURE:
      pszName = "SEC_E_ENCRYPT_FAILURE - The specified data could not be encrypted."; 
      break;
        
    case SEC_E_DECRYPT_FAILURE:
      pszName = "SEC_E_DECRYPT_FAILURE - The specified data could not be decrypted."; 
      break;
    case -1:
      pszName = "Failed to load security.dll library"; 
      break;

  }

  return pszName;
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// UV Lib callbacks
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
void SecurityCredentials::Process(uv_work_t* work_req) {
  // Grab the worker
  Worker *worker = static_cast<Worker*>(work_req->data);
  // Execute the worker code
  worker->execute(worker);
}

void SecurityCredentials::After(uv_work_t* work_req) {
  // Grab the scope of the call from Node
  v8::HandleScope scope;

  // Get the worker reference
  Worker *worker = static_cast<Worker*>(work_req->data);

  // If we have an error
  if(worker->error) {
    v8::Local<v8::Value> err = v8::Exception::Error(v8::String::New(worker->error_message));
    Local<Object> obj = err->ToObject();
    obj->Set(NODE_PSYMBOL("code"), Int32::New(worker->error_code));
    v8::Local<v8::Value> args[2] = { err, v8::Local<v8::Value>::New(v8::Null()) };
    // Execute the error
    v8::TryCatch try_catch;
    // Call the callback
    worker->callback->Call(v8::Context::GetCurrent()->Global(), ARRAY_SIZE(args), args);
    // If we have an exception handle it as a fatalexception
    if (try_catch.HasCaught()) {
      node::FatalException(try_catch);
    }
  } else {
    // // Map the data
    v8::Handle<v8::Value> result = worker->mapper(worker);
    // Set up the callback with a null first
    v8::Handle<v8::Value> args[2] = { v8::Local<v8::Value>::New(v8::Null()), result};
    // Wrap the callback function call in a TryCatch so that we can call
    // node's FatalException afterwards. This makes it possible to catch
    // the exception from JavaScript land using the
    // process.on('uncaughtException') event.
    v8::TryCatch try_catch;
    // Call the callback
    worker->callback->Call(v8::Context::GetCurrent()->Global(), ARRAY_SIZE(args), args);
    // If we have an exception handle it as a fatalexception
    if (try_catch.HasCaught()) {
      node::FatalException(try_catch);
    }
  }

  // Clean up the memory
  worker->callback.Dispose();
  delete worker;
}

