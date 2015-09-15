#ifndef SECURITY_BUFFER_DESCRIPTOR_H
#define SECURITY_BUFFER_DESCRIPTOR_H

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#include <windows.h>
#include <sspi.h>

using namespace v8;
using namespace node;

class SecurityBufferDescriptor : public ObjectWrap {  
  public:    
    Persistent<Array> arrayObject;
    SecBufferDesc secBufferDesc;
    
    SecurityBufferDescriptor();
    SecurityBufferDescriptor(Persistent<Array> arrayObject);
    ~SecurityBufferDescriptor();    

    // Has instance check
    static inline bool HasInstance(Handle<Value> val) {
      if (!val->IsObject()) return false;
      Local<Object> obj = val->ToObject();
      return constructor_template->HasInstance(obj);
    };

    char *toBuffer();
    size_t bufferSize();

    // Functions available from V8
    static void Initialize(Handle<Object> target);    
    static Handle<Value> ToBuffer(const Arguments &args);

    // Constructor used for creating new Long objects from C++
    static Persistent<FunctionTemplate> constructor_template;
    
  private:
    static Handle<Value> New(const Arguments &args);
};

#endif