#ifndef SECURITY_BUFFER_H
#define SECURITY_BUFFER_H

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#define SECURITY_WIN32 1

#include <windows.h>
#include <sspi.h>

using namespace v8;
using namespace node;

class SecurityBuffer : public ObjectWrap {  
  public:    
    SecurityBuffer(uint32_t security_type, size_t size);
    SecurityBuffer(uint32_t security_type, size_t size, void *data);
    ~SecurityBuffer();    

    // Internal values
    void *data;
    size_t size;
    uint32_t security_type;
    SecBuffer sec_buffer;

    // Has instance check
    static inline bool HasInstance(Handle<Value> val) {
      if (!val->IsObject()) return false;
      Local<Object> obj = val->ToObject();
      return constructor_template->HasInstance(obj);
    };

    // Functions available from V8
    static void Initialize(Handle<Object> target);    
    static Handle<Value> ToBuffer(const Arguments &args);

    // Constructor used for creating new Long objects from C++
    static Persistent<FunctionTemplate> constructor_template;
    
  private:
    static Handle<Value> New(const Arguments &args);
};

#endif