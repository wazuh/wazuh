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

#include "security_buffer.h"

using namespace node;

static Handle<Value> VException(const char *msg) {
  HandleScope scope;
  return ThrowException(Exception::Error(String::New(msg)));
};

Persistent<FunctionTemplate> SecurityBuffer::constructor_template;

SecurityBuffer::SecurityBuffer(uint32_t security_type, size_t size) : ObjectWrap() {
  this->size = size;
  this->data = calloc(size, sizeof(char));
  this->security_type = security_type;
  // Set up the data in the sec_buffer
  this->sec_buffer.BufferType = security_type;
  this->sec_buffer.cbBuffer = (unsigned long)size;
  this->sec_buffer.pvBuffer = this->data;  
}

SecurityBuffer::SecurityBuffer(uint32_t security_type, size_t size, void *data) : ObjectWrap() {
  this->size = size;
  this->data = data;
  this->security_type = security_type;
  // Set up the data in the sec_buffer
  this->sec_buffer.BufferType = security_type;
  this->sec_buffer.cbBuffer = (unsigned long)size;
  this->sec_buffer.pvBuffer = this->data;  
}

SecurityBuffer::~SecurityBuffer() {
  free(this->data);
}

Handle<Value> SecurityBuffer::New(const Arguments &args) {
  HandleScope scope;  
  SecurityBuffer *security_obj;

  if(args.Length() != 2)
    return VException("Two parameters needed integer buffer type and  [32 bit integer/Buffer] required");

  if(!args[0]->IsInt32())
    return VException("Two parameters needed integer buffer type and  [32 bit integer/Buffer] required");

  if(!args[1]->IsInt32() && !Buffer::HasInstance(args[1]))
    return VException("Two parameters needed integer buffer type and  [32 bit integer/Buffer] required");

  // Unpack buffer type
  uint32_t buffer_type = args[0]->ToUint32()->Value();

  // If we have an integer
  if(args[1]->IsInt32()) {
    security_obj = new SecurityBuffer(buffer_type, args[1]->ToUint32()->Value());
  } else {
    // Get the length of the Buffer
    size_t length = Buffer::Length(args[1]->ToObject());
    // Allocate space for the internal void data pointer
    void *data = calloc(length, sizeof(char));
    // Write the data to out of V8 heap space
    memcpy(data, Buffer::Data(args[1]->ToObject()), length);
    // Create new SecurityBuffer
    security_obj = new SecurityBuffer(buffer_type, length, data);
  }
  
  // Wrap it
  security_obj->Wrap(args.This());
  // Return the object
  return args.This();    
}

Handle<Value> SecurityBuffer::ToBuffer(const Arguments &args) {
  HandleScope scope; 

  // Unpack the Security Buffer object
  SecurityBuffer *security_obj = ObjectWrap::Unwrap<SecurityBuffer>(args.This());
  // Create a Buffer
  Buffer *buffer = Buffer::New((char *)security_obj->data, (size_t)security_obj->size);

  // Return the buffer
  return scope.Close(buffer->handle_);  
}

void SecurityBuffer::Initialize(Handle<Object> target) {
  // Grab the scope of the call from Node
  HandleScope scope;
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  constructor_template = Persistent<FunctionTemplate>::New(t);
  constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
  constructor_template->SetClassName(String::NewSymbol("SecurityBuffer"));

  // Set up method for the Kerberos instance
  NODE_SET_PROTOTYPE_METHOD(constructor_template, "toBuffer", ToBuffer);
 
  // Set up class
  target->Set(String::NewSymbol("SecurityBuffer"), constructor_template->GetFunction());  
}
