#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>

#include "security_context.h"
#include "security_buffer_descriptor.h"

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

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// UV Lib callbacks
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static void Process(uv_work_t* work_req) {
  // Grab the worker
  Worker *worker = static_cast<Worker*>(work_req->data);
  // Execute the worker code
  worker->execute(worker);
}

static void After(uv_work_t* work_req) {
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
  free(worker->parameters);
  delete worker;
}

Persistent<FunctionTemplate> SecurityContext::constructor_template;

SecurityContext::SecurityContext() : ObjectWrap() {
}

SecurityContext::~SecurityContext() {
  if(this->hasContext) {
    _sspi_DeleteSecurityContext(&this->m_Context);
  }
}

Handle<Value> SecurityContext::New(const Arguments &args) {
  HandleScope scope;    

  PSecurityFunctionTable pSecurityInterface = NULL;
  DWORD dwNumOfPkgs;
  SECURITY_STATUS status;

  // Create code object
  SecurityContext *security_obj = new SecurityContext();
  // Get security table interface
  pSecurityInterface = _ssip_InitSecurityInterface();
  // Call the security interface
  status = (*pSecurityInterface->EnumerateSecurityPackages)(
                                                    &dwNumOfPkgs, 
                                                    &security_obj->m_PkgInfo);
  if(status != SEC_E_OK) {
    printf(TEXT("Failed in retrieving security packages, Error: %x"), GetLastError());
    return VException("Failed in retrieving security packages");
  }

  // Wrap it
  security_obj->Wrap(args.This());
  // Return the object
  return args.This();    
}

Handle<Value> SecurityContext::InitializeContextSync(const Arguments &args) {
  HandleScope scope;  
  char *service_principal_name_str = NULL, *input_str = NULL, *decoded_input_str = NULL;
  BYTE *out_bound_data_str = NULL;
  int decoded_input_str_length = NULL;
  // Store reference to security credentials
  SecurityCredentials *security_credentials = NULL;
  // Status of operation
  SECURITY_STATUS status;

  // We need 3 parameters
  if(args.Length() != 3)
    return VException("Initialize must be called with either [credential:SecurityCredential, servicePrincipalName:string, input:string]");

  // First parameter must be an instance of SecurityCredentials
  if(!SecurityCredentials::HasInstance(args[0]))
    return VException("First parameter for Initialize must be an instance of SecurityCredentials");

  // Second parameter must be a string
  if(!args[1]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Third parameter must be a base64 encoded string
  if(!args[2]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Let's unpack the values
  Local<String> service_principal_name = args[1]->ToString();
  service_principal_name_str = (char *)calloc(service_principal_name->Utf8Length() + 1, sizeof(char));
  service_principal_name->WriteUtf8(service_principal_name_str);

  // Unpack the user name
  Local<String> input = args[2]->ToString();

  if(input->Utf8Length() > 0) {
    input_str = (char *)calloc(input->Utf8Length() + 1, sizeof(char));
    input->WriteUtf8(input_str);

    // Now let's get the base64 decoded string
    decoded_input_str = (char *)base64_decode(input_str, &decoded_input_str_length);
  }

  // Unpack the Security credentials
  security_credentials = ObjectWrap::Unwrap<SecurityCredentials>(args[0]->ToObject());

  // Create Security context instance
  Local<Object> security_context_value = constructor_template->GetFunction()->NewInstance();
  // Unwrap the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(security_context_value);
  // Add a reference to the security_credentials
  security_context->security_credentials = security_credentials;

  // Structures used for c calls
  SecBufferDesc ibd, obd;
  SecBuffer ib, ob;

  // 
  // Prepare data structure for returned data from SSPI
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = security_context->m_PkgInfo->cbMaxToken;
  // Allocate space for return data
  out_bound_data_str = new BYTE[ob.cbBuffer + sizeof(DWORD)];
  ob.pvBuffer = out_bound_data_str;
  // prepare buffer description
  obd.cBuffers  = 1;
  obd.ulVersion = SECBUFFER_VERSION;
  obd.pBuffers  = &ob;

  //
  // Prepare the data we are passing to the SSPI method
  if(input->Utf8Length() > 0) {
    ib.BufferType = SECBUFFER_TOKEN;
    ib.cbBuffer   = decoded_input_str_length;
    ib.pvBuffer   = decoded_input_str;
    // prepare buffer description
    ibd.cBuffers  = 1;
    ibd.ulVersion = SECBUFFER_VERSION;
    ibd.pBuffers  = &ib;    
  }

  // Perform initialization step
  status = _sspi_initializeSecurityContext(
      &security_credentials->m_Credentials
    , NULL
    , const_cast<TCHAR*>(service_principal_name_str)
    , 0x02  // MUTUAL
    , 0
    , 0     // Network
    , input->Utf8Length() > 0 ? &ibd : NULL
    , 0
    , &security_context->m_Context
    , &obd
    , &security_context->CtxtAttr
    , &security_context->Expiration
  );

  // If we have a ok or continue let's prepare the result
  if(status == SEC_E_OK 
    || status == SEC_I_COMPLETE_NEEDED
    || status == SEC_I_CONTINUE_NEEDED
    || status == SEC_I_COMPLETE_AND_CONTINUE
  ) {
    security_context->hasContext = true;
    security_context->payload = base64_encode((const unsigned char *)ob.pvBuffer, ob.cbBuffer);
  } else {
    LPSTR err_message = DisplaySECError(status);

    if(err_message != NULL) {
      return VExceptionErrNo(err_message, status);
    } else {
      return VExceptionErrNo("Unknown error", status);
    }
  }

  // Return security context
  return scope.Close(security_context_value);
}

//
//  Async InitializeContext
//
typedef struct SecurityContextStaticInitializeCall {
  char *service_principal_name_str;
  char *decoded_input_str;
  int decoded_input_str_length;
  SecurityContext *context;
} SecurityContextStaticInitializeCall;

static void _initializeContext(Worker *worker) {
  // Status of operation
  SECURITY_STATUS status;
  BYTE *out_bound_data_str = NULL;
  SecurityContextStaticInitializeCall *call = (SecurityContextStaticInitializeCall *)worker->parameters;

  // Structures used for c calls
  SecBufferDesc ibd, obd;
  SecBuffer ib, ob;

  // 
  // Prepare data structure for returned data from SSPI
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = call->context->m_PkgInfo->cbMaxToken;
  // Allocate space for return data
  out_bound_data_str = new BYTE[ob.cbBuffer + sizeof(DWORD)];
  ob.pvBuffer = out_bound_data_str;
  // prepare buffer description
  obd.cBuffers  = 1;
  obd.ulVersion = SECBUFFER_VERSION;
  obd.pBuffers  = &ob;

  //
  // Prepare the data we are passing to the SSPI method
  if(call->decoded_input_str_length > 0) {
    ib.BufferType = SECBUFFER_TOKEN;
    ib.cbBuffer   = call->decoded_input_str_length;
    ib.pvBuffer   = call->decoded_input_str;
    // prepare buffer description
    ibd.cBuffers  = 1;
    ibd.ulVersion = SECBUFFER_VERSION;
    ibd.pBuffers  = &ib;    
  }

  // Perform initialization step
  status = _sspi_initializeSecurityContext(
      &call->context->security_credentials->m_Credentials
    , NULL
    , const_cast<TCHAR*>(call->service_principal_name_str)
    , 0x02  // MUTUAL
    , 0
    , 0     // Network
    , call->decoded_input_str_length > 0 ? &ibd : NULL
    , 0
    , &call->context->m_Context
    , &obd
    , &call->context->CtxtAttr
    , &call->context->Expiration
  );

  // If we have a ok or continue let's prepare the result
  if(status == SEC_E_OK 
    || status == SEC_I_COMPLETE_NEEDED
    || status == SEC_I_CONTINUE_NEEDED
    || status == SEC_I_COMPLETE_AND_CONTINUE
  ) {
    call->context->hasContext = true;
    call->context->payload = base64_encode((const unsigned char *)ob.pvBuffer, ob.cbBuffer);

    // Set the context
    worker->return_code = status;
    worker->return_value = call->context;
  } else {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  }

  // Clean up data
  if(call->decoded_input_str != NULL) free(call->decoded_input_str);
  if(call->service_principal_name_str != NULL) free(call->service_principal_name_str);
}

static Handle<Value> _map_initializeContext(Worker *worker) {
  HandleScope scope;

  // Unwrap the security context
  SecurityContext *context = (SecurityContext *)worker->return_value;
  // Return the value
  return scope.Close(context->handle_);
}

Handle<Value> SecurityContext::InitializeContext(const Arguments &args) {
  HandleScope scope;  
  char *service_principal_name_str = NULL, *input_str = NULL, *decoded_input_str = NULL;
  int decoded_input_str_length = NULL;
  // Store reference to security credentials
  SecurityCredentials *security_credentials = NULL;

  // We need 3 parameters
  if(args.Length() != 4)
    return VException("Initialize must be called with [credential:SecurityCredential, servicePrincipalName:string, input:string, callback:function]");

  // First parameter must be an instance of SecurityCredentials
  if(!SecurityCredentials::HasInstance(args[0]))
    return VException("First parameter for Initialize must be an instance of SecurityCredentials");

  // Second parameter must be a string
  if(!args[1]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Third parameter must be a base64 encoded string
  if(!args[2]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Third parameter must be a callback
  if(!args[3]->IsFunction())
    return VException("Third parameter for Initialize must be a callback function");

  // Let's unpack the values
  Local<String> service_principal_name = args[1]->ToString();
  service_principal_name_str = (char *)calloc(service_principal_name->Utf8Length() + 1, sizeof(char));
  service_principal_name->WriteUtf8(service_principal_name_str);

  // Unpack the user name
  Local<String> input = args[2]->ToString();

  if(input->Utf8Length() > 0) {
    input_str = (char *)calloc(input->Utf8Length() + 1, sizeof(char));
    input->WriteUtf8(input_str);

    // Now let's get the base64 decoded string
    decoded_input_str = (char *)base64_decode(input_str, &decoded_input_str_length);
    // Free original allocation
    free(input_str);
  }

  // Unpack the Security credentials
  security_credentials = ObjectWrap::Unwrap<SecurityCredentials>(args[0]->ToObject());
  // Create Security context instance
  Local<Object> security_context_value = constructor_template->GetFunction()->NewInstance();
  // Unwrap the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(security_context_value);
  // Add a reference to the security_credentials
  security_context->security_credentials = security_credentials;

  // Build the call function
  SecurityContextStaticInitializeCall *call = (SecurityContextStaticInitializeCall *)calloc(1, sizeof(SecurityContextStaticInitializeCall));
  call->context = security_context;
  call->decoded_input_str = decoded_input_str;
  call->decoded_input_str_length = decoded_input_str_length;
  call->service_principal_name_str = service_principal_name_str;

  // Callback
  Local<Function> callback = Local<Function>::Cast(args[3]);

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _initializeContext;
  worker->mapper = _map_initializeContext;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, Process, (uv_after_work_cb)After);

  // Return no value
  return scope.Close(Undefined());  
}

Handle<Value> SecurityContext::PayloadGetter(Local<String> property, const AccessorInfo& info) {
  HandleScope scope;
  // Unpack the context object
  SecurityContext *context = ObjectWrap::Unwrap<SecurityContext>(info.Holder());
  // Return the low bits
  return scope.Close(String::New(context->payload));
}

Handle<Value> SecurityContext::HasContextGetter(Local<String> property, const AccessorInfo& info) {
  HandleScope scope;
  // Unpack the context object
  SecurityContext *context = ObjectWrap::Unwrap<SecurityContext>(info.Holder());
  // Return the low bits
  return scope.Close(Boolean::New(context->hasContext));  
}

//
//  Async InitializeContextStep
//
typedef struct SecurityContextStepStaticInitializeCall {
  char *service_principal_name_str;
  char *decoded_input_str;
  int decoded_input_str_length;
  SecurityContext *context;
} SecurityContextStepStaticInitializeCall;

static void _initializeContextStep(Worker *worker) {
  // Outbound data array
  BYTE *out_bound_data_str = NULL;
  // Status of operation
  SECURITY_STATUS status;
  // Unpack data
  SecurityContextStepStaticInitializeCall *call = (SecurityContextStepStaticInitializeCall *)worker->parameters;
  SecurityContext *context = call->context;
  // Structures used for c calls
  SecBufferDesc ibd, obd;
  SecBuffer ib, ob;

  // 
  // Prepare data structure for returned data from SSPI
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = context->m_PkgInfo->cbMaxToken;
  // Allocate space for return data
  out_bound_data_str = new BYTE[ob.cbBuffer + sizeof(DWORD)];
  ob.pvBuffer = out_bound_data_str;
  // prepare buffer description
  obd.cBuffers  = 1;
  obd.ulVersion = SECBUFFER_VERSION;
  obd.pBuffers  = &ob;

  //
  // Prepare the data we are passing to the SSPI method
  if(call->decoded_input_str_length > 0) {
    ib.BufferType = SECBUFFER_TOKEN;
    ib.cbBuffer   = call->decoded_input_str_length;
    ib.pvBuffer   = call->decoded_input_str;
    // prepare buffer description
    ibd.cBuffers  = 1;
    ibd.ulVersion = SECBUFFER_VERSION;
    ibd.pBuffers  = &ib;    
  }

  // Perform initialization step
  status = _sspi_initializeSecurityContext(
      &context->security_credentials->m_Credentials
    , context->hasContext == true ? &context->m_Context : NULL
    , const_cast<TCHAR*>(call->service_principal_name_str)
    , 0x02  // MUTUAL
    , 0
    , 0     // Network
    , call->decoded_input_str_length ? &ibd : NULL
    , 0
    , &context->m_Context
    , &obd
    , &context->CtxtAttr
    , &context->Expiration
  );

  // If we have a ok or continue let's prepare the result
  if(status == SEC_E_OK 
    || status == SEC_I_COMPLETE_NEEDED
    || status == SEC_I_CONTINUE_NEEDED
    || status == SEC_I_COMPLETE_AND_CONTINUE
  ) {
    // Set the new payload
    if(context->payload != NULL) free(context->payload);
    context->payload = base64_encode((const unsigned char *)ob.pvBuffer, ob.cbBuffer);
    worker->return_code = status;
    worker->return_value = context;
  } else {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  }

  // Clean up data
  if(call->decoded_input_str != NULL) free(call->decoded_input_str);
  if(call->service_principal_name_str != NULL) free(call->service_principal_name_str);
}

static Handle<Value> _map_initializeContextStep(Worker *worker) {
  HandleScope scope;
  // Unwrap the security context
  SecurityContext *context = (SecurityContext *)worker->return_value;
  // Return the value
  return scope.Close(context->handle_);
}

Handle<Value> SecurityContext::InitalizeStep(const Arguments &args) {
  HandleScope scope;

  char *service_principal_name_str = NULL, *input_str = NULL, *decoded_input_str = NULL;
  int decoded_input_str_length = NULL;

  // We need 3 parameters
  if(args.Length() != 3)
    return VException("Initialize must be called with [servicePrincipalName:string, input:string, callback:function]");

  // Second parameter must be a string
  if(!args[0]->IsString())
    return VException("First parameter for Initialize must be a string");

  // Third parameter must be a base64 encoded string
  if(!args[1]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Third parameter must be a base64 encoded string
  if(!args[2]->IsFunction())
    return VException("Third parameter for Initialize must be a callback function");

  // Let's unpack the values
  Local<String> service_principal_name = args[0]->ToString();
  service_principal_name_str = (char *)calloc(service_principal_name->Utf8Length() + 1, sizeof(char));
  service_principal_name->WriteUtf8(service_principal_name_str);

  // Unpack the user name
  Local<String> input = args[1]->ToString();

  if(input->Utf8Length() > 0) {
    input_str = (char *)calloc(input->Utf8Length() + 1, sizeof(char));
    input->WriteUtf8(input_str);
    // Now let's get the base64 decoded string
    decoded_input_str = (char *)base64_decode(input_str, &decoded_input_str_length);
    // Free input string
    free(input_str);
  }

  // Unwrap the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());

  // Create call structure
  SecurityContextStepStaticInitializeCall *call = (SecurityContextStepStaticInitializeCall *)calloc(1, sizeof(SecurityContextStepStaticInitializeCall));
  call->context = security_context;
  call->decoded_input_str = decoded_input_str;
  call->decoded_input_str_length = decoded_input_str_length;
  call->service_principal_name_str = service_principal_name_str;

  // Callback
  Local<Function> callback = Local<Function>::Cast(args[2]);

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _initializeContextStep;
  worker->mapper = _map_initializeContextStep;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, Process, (uv_after_work_cb)After);

  // Return undefined
  return scope.Close(Undefined());  
}

Handle<Value> SecurityContext::InitalizeStepSync(const Arguments &args) {
  HandleScope scope;

  char *service_principal_name_str = NULL, *input_str = NULL, *decoded_input_str = NULL;
  BYTE *out_bound_data_str = NULL;
  int decoded_input_str_length = NULL;
  // Status of operation
  SECURITY_STATUS status;

  // We need 3 parameters
  if(args.Length() != 2)
    return VException("Initialize must be called with [servicePrincipalName:string, input:string]");

  // Second parameter must be a string
  if(!args[0]->IsString())
    return VException("First parameter for Initialize must be a string");

  // Third parameter must be a base64 encoded string
  if(!args[1]->IsString())
    return VException("Second parameter for Initialize must be a string");

  // Let's unpack the values
  Local<String> service_principal_name = args[0]->ToString();
  service_principal_name_str = (char *)calloc(service_principal_name->Utf8Length() + 1, sizeof(char));
  service_principal_name->WriteUtf8(service_principal_name_str);

  // Unpack the user name
  Local<String> input = args[1]->ToString();

  if(input->Utf8Length() > 0) {
    input_str = (char *)calloc(input->Utf8Length() + 1, sizeof(char));
    input->WriteUtf8(input_str);
    // Now let's get the base64 decoded string
    decoded_input_str = (char *)base64_decode(input_str, &decoded_input_str_length);
  }

  // Unpack the long object
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());  
  SecurityCredentials *security_credentials = security_context->security_credentials;

  // Structures used for c calls
  SecBufferDesc ibd, obd;
  SecBuffer ib, ob;

  // 
  // Prepare data structure for returned data from SSPI
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = security_context->m_PkgInfo->cbMaxToken;
  // Allocate space for return data
  out_bound_data_str = new BYTE[ob.cbBuffer + sizeof(DWORD)];
  ob.pvBuffer = out_bound_data_str;
  // prepare buffer description
  obd.cBuffers  = 1;
  obd.ulVersion = SECBUFFER_VERSION;
  obd.pBuffers  = &ob;

  //
  // Prepare the data we are passing to the SSPI method
  if(input->Utf8Length() > 0) {
    ib.BufferType = SECBUFFER_TOKEN;
    ib.cbBuffer   = decoded_input_str_length;
    ib.pvBuffer   = decoded_input_str;
    // prepare buffer description
    ibd.cBuffers  = 1;
    ibd.ulVersion = SECBUFFER_VERSION;
    ibd.pBuffers  = &ib;    
  }

  // Perform initialization step
  status = _sspi_initializeSecurityContext(
      &security_credentials->m_Credentials
    , security_context->hasContext == true ? &security_context->m_Context : NULL
    , const_cast<TCHAR*>(service_principal_name_str)
    , 0x02  // MUTUAL
    , 0
    , 0     // Network
    , input->Utf8Length() > 0 ? &ibd : NULL
    , 0
    , &security_context->m_Context
    , &obd
    , &security_context->CtxtAttr
    , &security_context->Expiration
  );

  // If we have a ok or continue let's prepare the result
  if(status == SEC_E_OK 
    || status == SEC_I_COMPLETE_NEEDED
    || status == SEC_I_CONTINUE_NEEDED
    || status == SEC_I_COMPLETE_AND_CONTINUE
  ) {
    // Set the new payload
    if(security_context->payload != NULL) free(security_context->payload);
    security_context->payload = base64_encode((const unsigned char *)ob.pvBuffer, ob.cbBuffer);
  } else {
    LPSTR err_message = DisplaySECError(status);

    if(err_message != NULL) {
      return VExceptionErrNo(err_message, status);
    } else {
      return VExceptionErrNo("Unknown error", status);
    }
  }

  return scope.Close(Null());
}

//
//  Async EncryptMessage
//
typedef struct SecurityContextEncryptMessageCall {
  SecurityContext *context;
  SecurityBufferDescriptor *descriptor;
  unsigned long flags;
} SecurityContextEncryptMessageCall;

static void _encryptMessage(Worker *worker) {
  SECURITY_STATUS status;
  // Unpack call
  SecurityContextEncryptMessageCall *call = (SecurityContextEncryptMessageCall *)worker->parameters;
  // Unpack the security context
  SecurityContext *context = call->context;
  SecurityBufferDescriptor *descriptor = call->descriptor;

  // Let's execute encryption
  status = _sspi_EncryptMessage(
      &context->m_Context
    , call->flags
    , &descriptor->secBufferDesc
    , 0
  );

  // We've got ok
  if(status == SEC_E_OK) {
    int bytesToAllocate = (int)descriptor->bufferSize();    
    // Free up existing payload
    if(context->payload != NULL) free(context->payload);
    // Save the payload
    context->payload = base64_encode((unsigned char *)descriptor->toBuffer(), bytesToAllocate);
    // Set result
    worker->return_code = status;
    worker->return_value = context;
  } else {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  }
}

static Handle<Value> _map_encryptMessage(Worker *worker) {
  HandleScope scope;
  // Unwrap the security context
  SecurityContext *context = (SecurityContext *)worker->return_value;
  // Return the value
  return scope.Close(context->handle_);
}

Handle<Value> SecurityContext::EncryptMessage(const Arguments &args) {
  HandleScope scope;

  if(args.Length() != 3)
    return VException("EncryptMessage takes an instance of SecurityBufferDescriptor, an integer flag and a callback function");  
  if(!SecurityBufferDescriptor::HasInstance(args[0]))
    return VException("EncryptMessage takes an instance of SecurityBufferDescriptor, an integer flag and a callback function");  
  if(!args[1]->IsUint32())
    return VException("EncryptMessage takes an instance of SecurityBufferDescriptor, an integer flag and a callback function");  
  if(!args[2]->IsFunction())
    return VException("EncryptMessage takes an instance of SecurityBufferDescriptor, an integer flag and a callback function");  

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());

  // Unpack the descriptor
  SecurityBufferDescriptor *descriptor = ObjectWrap::Unwrap<SecurityBufferDescriptor>(args[0]->ToObject());

  // Create call structure
  SecurityContextEncryptMessageCall *call = (SecurityContextEncryptMessageCall *)calloc(1, sizeof(SecurityContextEncryptMessageCall));
  call->context = security_context;
  call->descriptor = descriptor;
  call->flags = (unsigned long)args[1]->ToInteger()->Value();

  // Callback
  Local<Function> callback = Local<Function>::Cast(args[2]);

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _encryptMessage;
  worker->mapper = _map_encryptMessage;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, Process, (uv_after_work_cb)After);

  // Return undefined
  return scope.Close(Undefined());  
}

Handle<Value> SecurityContext::EncryptMessageSync(const Arguments &args) {
  HandleScope scope;
  SECURITY_STATUS status;

  if(args.Length() != 2)
    return VException("EncryptMessageSync takes an instance of SecurityBufferDescriptor and an integer flag");  
  if(!SecurityBufferDescriptor::HasInstance(args[0]))
    return VException("EncryptMessageSync takes an instance of SecurityBufferDescriptor and an integer flag");  
  if(!args[1]->IsUint32())
    return VException("EncryptMessageSync takes an instance of SecurityBufferDescriptor and an integer flag");  

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());

  // Unpack the descriptor
  SecurityBufferDescriptor *descriptor = ObjectWrap::Unwrap<SecurityBufferDescriptor>(args[0]->ToObject());

  // Let's execute encryption
  status = _sspi_EncryptMessage(
      &security_context->m_Context
    , (unsigned long)args[1]->ToInteger()->Value()
    , &descriptor->secBufferDesc
    , 0
  );

  // We've got ok
  if(status == SEC_E_OK) {
    int bytesToAllocate = (int)descriptor->bufferSize();    
    // Free up existing payload
    if(security_context->payload != NULL) free(security_context->payload);
    // Save the payload
    security_context->payload = base64_encode((unsigned char *)descriptor->toBuffer(), bytesToAllocate);
  } else {
    LPSTR err_message = DisplaySECError(status);

    if(err_message != NULL) {
      return VExceptionErrNo(err_message, status);
    } else {
      return VExceptionErrNo("Unknown error", status);
    }
  }

  return scope.Close(Null());
}

//
//  Async DecryptMessage
//
typedef struct SecurityContextDecryptMessageCall {
  SecurityContext *context;
  SecurityBufferDescriptor *descriptor;
} SecurityContextDecryptMessageCall;

static void _decryptMessage(Worker *worker) {
  unsigned long quality = 0;
  SECURITY_STATUS status;
  
  // Unpack parameters
  SecurityContextDecryptMessageCall *call = (SecurityContextDecryptMessageCall *)worker->parameters;
  SecurityContext *context = call->context;
  SecurityBufferDescriptor *descriptor = call->descriptor;

  // Let's execute encryption
  status = _sspi_DecryptMessage(
      &context->m_Context
    , &descriptor->secBufferDesc
    , 0
    , (unsigned long)&quality
  );

  // We've got ok
  if(status == SEC_E_OK) {
    int bytesToAllocate = (int)descriptor->bufferSize();    
    // Free up existing payload
    if(context->payload != NULL) free(context->payload);
    // Save the payload
    context->payload = base64_encode((unsigned char *)descriptor->toBuffer(), bytesToAllocate);
    // Set return values
    worker->return_code = status;
    worker->return_value = context;
  } else {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  }
}

static Handle<Value> _map_decryptMessage(Worker *worker) {
  HandleScope scope;
  // Unwrap the security context
  SecurityContext *context = (SecurityContext *)worker->return_value;
  // Return the value
  return scope.Close(context->handle_);
}

Handle<Value> SecurityContext::DecryptMessage(const Arguments &args) {
  HandleScope scope;

  if(args.Length() != 2)
    return VException("DecryptMessage takes an instance of SecurityBufferDescriptor and a callback function");
  if(!SecurityBufferDescriptor::HasInstance(args[0]))
    return VException("DecryptMessage takes an instance of SecurityBufferDescriptor and a callback function");
  if(!args[1]->IsFunction())
    return VException("DecryptMessage takes an instance of SecurityBufferDescriptor and a callback function");

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());
  // Unpack the descriptor
  SecurityBufferDescriptor *descriptor = ObjectWrap::Unwrap<SecurityBufferDescriptor>(args[0]->ToObject());
  // Create call structure
  SecurityContextDecryptMessageCall *call = (SecurityContextDecryptMessageCall *)calloc(1, sizeof(SecurityContextDecryptMessageCall));
  call->context = security_context;
  call->descriptor = descriptor;

  // Callback
  Local<Function> callback = Local<Function>::Cast(args[1]);

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _decryptMessage;
  worker->mapper = _map_decryptMessage;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, Process, (uv_after_work_cb)After);

  // Return undefined
  return scope.Close(Undefined());  
}

Handle<Value> SecurityContext::DecryptMessageSync(const Arguments &args) {
  HandleScope scope;
  unsigned long quality = 0;
  SECURITY_STATUS status;

  if(args.Length() != 1)
    return VException("DecryptMessageSync takes an instance of SecurityBufferDescriptor");
  if(!SecurityBufferDescriptor::HasInstance(args[0]))
    return VException("DecryptMessageSync takes an instance of SecurityBufferDescriptor");

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());

  // Unpack the descriptor
  SecurityBufferDescriptor *descriptor = ObjectWrap::Unwrap<SecurityBufferDescriptor>(args[0]->ToObject());

  // Let's execute encryption
  status = _sspi_DecryptMessage(
      &security_context->m_Context
    , &descriptor->secBufferDesc
    , 0
    , (unsigned long)&quality
  );

  // We've got ok
  if(status == SEC_E_OK) {
    int bytesToAllocate = (int)descriptor->bufferSize();    
    // Free up existing payload
    if(security_context->payload != NULL) free(security_context->payload);
    // Save the payload
    security_context->payload = base64_encode((unsigned char *)descriptor->toBuffer(), bytesToAllocate);
  } else {
    LPSTR err_message = DisplaySECError(status);

    if(err_message != NULL) {
      return VExceptionErrNo(err_message, status);
    } else {
      return VExceptionErrNo("Unknown error", status);
    }
  }

  return scope.Close(Null());
}

//
//  Async QueryContextAttributes
//
typedef struct SecurityContextQueryContextAttributesCall {
  SecurityContext *context;
  uint32_t attribute;
} SecurityContextQueryContextAttributesCall;

static void _queryContextAttributes(Worker *worker) {
  SECURITY_STATUS status;

  // Cast to data structure
  SecurityContextQueryContextAttributesCall *call = (SecurityContextQueryContextAttributesCall *)worker->parameters;  

  // Allocate some space
  SecPkgContext_Sizes *sizes = (SecPkgContext_Sizes *)calloc(1, sizeof(SecPkgContext_Sizes));
  // Let's grab the query context attribute
  status = _sspi_QueryContextAttributes(
    &call->context->m_Context,
    call->attribute,
    sizes
  );  
  
  if(status == SEC_E_OK) {
    worker->return_code = status;
    worker->return_value = sizes;
  } else {
    worker->error = TRUE;
    worker->error_code = status;
    worker->error_message = DisplaySECError(status);
  }
}

static Handle<Value> _map_queryContextAttributes(Worker *worker) {
  HandleScope scope;

  // Cast to data structure
  SecurityContextQueryContextAttributesCall *call = (SecurityContextQueryContextAttributesCall *)worker->parameters;  
  // Unpack the attribute
  uint32_t attribute = call->attribute;

  // Convert data
  if(attribute == SECPKG_ATTR_SIZES) {
    SecPkgContext_Sizes *sizes = (SecPkgContext_Sizes *)worker->return_value;
    // Create object
    Local<Object> value = Object::New();
    value->Set(String::New("maxToken"), Integer::New(sizes->cbMaxToken));
    value->Set(String::New("maxSignature"), Integer::New(sizes->cbMaxSignature));
    value->Set(String::New("blockSize"), Integer::New(sizes->cbBlockSize));
    value->Set(String::New("securityTrailer"), Integer::New(sizes->cbSecurityTrailer));
    return scope.Close(value);
  }

  // Return the value
  return scope.Close(Null());
}

Handle<Value> SecurityContext::QueryContextAttributes(const Arguments &args) {
  HandleScope scope;

  if(args.Length() != 2)
    return VException("QueryContextAttributesSync method takes a an integer Attribute specifier and a callback function");
  if(!args[0]->IsInt32())
    return VException("QueryContextAttributes method takes a an integer Attribute specifier and a callback function");
  if(!args[1]->IsFunction())
    return VException("QueryContextAttributes method takes a an integer Attribute specifier and a callback function");

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());

  // Unpack the int value
  uint32_t attribute = args[0]->ToInt32()->Value();  

  // Check that we have a supported attribute
  if(attribute != SECPKG_ATTR_SIZES) 
    return VException("QueryContextAttributes only supports the SECPKG_ATTR_SIZES attribute");

  // Create call structure
  SecurityContextQueryContextAttributesCall *call = (SecurityContextQueryContextAttributesCall *)calloc(1, sizeof(SecurityContextQueryContextAttributesCall));
  call->attribute = attribute;
  call->context = security_context;

  // Callback
  Local<Function> callback = Local<Function>::Cast(args[1]);

  // Let's allocate some space
  Worker *worker = new Worker();
  worker->error = false;
  worker->request.data = worker;
  worker->callback = Persistent<Function>::New(callback);
  worker->parameters = call;
  worker->execute = _queryContextAttributes;
  worker->mapper = _map_queryContextAttributes;

  // Schedule the worker with lib_uv
  uv_queue_work(uv_default_loop(), &worker->request, Process, (uv_after_work_cb)After);

  // Return undefined
  return scope.Close(Undefined());  
}

Handle<Value> SecurityContext::QueryContextAttributesSync(const Arguments &args) {
  HandleScope scope;
  SECURITY_STATUS status;

  if(args.Length() != 1)
    return VException("QueryContextAttributesSync method takes a an integer Attribute specifier");
  if(!args[0]->IsInt32())
    return VException("QueryContextAttributesSync method takes a an integer Attribute specifier");

  // Unpack the security context
  SecurityContext *security_context = ObjectWrap::Unwrap<SecurityContext>(args.This());
  uint32_t attribute = args[0]->ToInt32()->Value();

  if(attribute != SECPKG_ATTR_SIZES) 
    return VException("QueryContextAttributes only supports the SECPKG_ATTR_SIZES attribute");

  // Check what attribute we are asking for
  if(attribute == SECPKG_ATTR_SIZES) {
    SecPkgContext_Sizes sizes;

    // Let's grab the query context attribute
    status = _sspi_QueryContextAttributes(
      &security_context->m_Context,
      attribute,
      &sizes
    );  
    
    if(status == SEC_E_OK) {
      Local<Object> value = Object::New();
      value->Set(String::New("maxToken"), Integer::New(sizes.cbMaxToken));
      value->Set(String::New("maxSignature"), Integer::New(sizes.cbMaxSignature));
      value->Set(String::New("blockSize"), Integer::New(sizes.cbBlockSize));
      value->Set(String::New("securityTrailer"), Integer::New(sizes.cbSecurityTrailer));
      return scope.Close(value);
    } else {
      LPSTR err_message = DisplaySECError(status);

      if(err_message != NULL) {
        return VExceptionErrNo(err_message, status);
      } else {
        return VExceptionErrNo("Unknown error", status);
      }      
    }
  }

  return scope.Close(Null());
}

void SecurityContext::Initialize(Handle<Object> target) {
  // Grab the scope of the call from Node
  HandleScope scope;
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  constructor_template = Persistent<FunctionTemplate>::New(t);
  constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
  constructor_template->SetClassName(String::NewSymbol("SecurityContext"));

  // Class methods
  NODE_SET_METHOD(constructor_template, "initializeSync", InitializeContextSync);
  NODE_SET_METHOD(constructor_template, "initialize", InitializeContext);
  
  // Set up method for the instance
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "initializeSync", InitalizeStepSync);
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "initialize", InitalizeStep);

  NODE_SET_PROTOTYPE_METHOD(constructor_template, "decryptMessageSync", DecryptMessageSync);
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "decryptMessage", DecryptMessage);

  NODE_SET_PROTOTYPE_METHOD(constructor_template, "queryContextAttributesSync", QueryContextAttributesSync);
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "queryContextAttributes", QueryContextAttributes);

  NODE_SET_PROTOTYPE_METHOD(constructor_template, "encryptMessageSync", EncryptMessageSync);
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "encryptMessage", EncryptMessage);

  // Getters for correct serialization of the object  
  constructor_template->InstanceTemplate()->SetAccessor(String::NewSymbol("payload"), PayloadGetter);
  // Getters for correct serialization of the object  
  constructor_template->InstanceTemplate()->SetAccessor(String::NewSymbol("hasContext"), HasContextGetter);

  // Set template class name
  target->Set(String::NewSymbol("SecurityContext"), constructor_template->GetFunction());  
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
      pszName = "SEC_E_INCOMPLETE_MESSAGE - The data in the input buffer is incomplete. The application needs to read more data from the server and call DecryptMessageSync (General) again."; 
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

