//===========================================================================

#include <stdarg.h>
#include <cstdlib>
#include <cstring>
#include <string.h>
#include <stdlib.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <v8.h>

// this and the above block must be around the v8.h header otherwise
// v8 is not happy
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include <node.h>
#include <node_version.h>
#include <node_buffer.h>

#include <cmath>
#include <iostream>
#include <limits>
#include <vector>

#ifdef __sun
	#include <alloca.h>
#endif

#include "bson.h"

using namespace v8;
using namespace node;

//===========================================================================

void DataStream::WriteObjectId(const Handle<Object>& object, const Handle<String>& key)
{
	uint16_t buffer[12];
	object->Get(key)->ToString()->Write(buffer, 0, 12);
	for(uint32_t i = 0; i < 12; ++i)
	{
		*p++ = (char) buffer[i];
	}
}

void ThrowAllocatedStringException(size_t allocationSize, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	char* string = (char*) malloc(allocationSize);
	vsprintf(string, format, args);
	va_end(args);

	throw string;
}

void DataStream::CheckKey(const Local<String>& keyName)
{
	size_t keyLength = keyName->Utf8Length();
	if(keyLength == 0) return;

	// Allocate space for the key, do not need to zero terminate as WriteUtf8 does it
	char* keyStringBuffer = (char*) alloca(keyLength + 1);
	// Write the key to the allocated buffer
	keyName->WriteUtf8(keyStringBuffer);
	// Check for the zero terminator
	char* terminator = strchr(keyStringBuffer, 0x00);

	// If the location is not at the end of the string we've got an illegal 0x00 byte somewhere
	if(terminator != &keyStringBuffer[keyLength]) {
		ThrowAllocatedStringException(64+keyLength, "key %s must not contain null bytes", keyStringBuffer);
	}

	if(keyStringBuffer[0] == '$')
	{
		ThrowAllocatedStringException(64+keyLength, "key %s must not start with '$'", keyStringBuffer);
	}

	if(strchr(keyStringBuffer, '.') != NULL)
	{
		ThrowAllocatedStringException(64+keyLength, "key %s must not contain '.'", keyStringBuffer);
	}
}

template<typename T> void BSONSerializer<T>::SerializeDocument(const Handle<Value>& value)
{
	void* documentSize = this->BeginWriteSize();
	Local<Object> object = bson->GetSerializeObject(value);

	// Get the object property names
	#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 6
    Local<Array> propertyNames = object->GetPropertyNames();
  #else
    Local<Array> propertyNames = object->GetOwnPropertyNames();
  #endif

	// Length of the property
	int propertyLength = propertyNames->Length();
	for(int i = 0;  i < propertyLength; ++i)
	{
		const Local<String>& propertyName = propertyNames->Get(i)->ToString();
		if(checkKeys) this->CheckKey(propertyName);

		const Local<Value>& propertyValue = object->Get(propertyName);

		if(serializeFunctions || !propertyValue->IsFunction())
		{
			void* typeLocation = this->BeginWriteType();
			this->WriteString(propertyName);
			SerializeValue(typeLocation, propertyValue);
		}
	}

	this->WriteByte(0);
	this->CommitSize(documentSize);
}

template<typename T> void BSONSerializer<T>::SerializeArray(const Handle<Value>& value)
{
	void* documentSize = this->BeginWriteSize();

	Local<Array> array = Local<Array>::Cast(value->ToObject());
	uint32_t arrayLength = array->Length();

	for(uint32_t i = 0;  i < arrayLength; ++i)
	{
		void* typeLocation = this->BeginWriteType();
		this->WriteUInt32String(i);
		SerializeValue(typeLocation, array->Get(i));
	}

	this->WriteByte(0);
	this->CommitSize(documentSize);
}

// This is templated so that we can use this function to both count the number of bytes, and to serialize those bytes.
// The template approach eliminates almost all of the inspection of values unless they're required (eg. string lengths)
// and ensures that there is always consistency between bytes counted and bytes written by design.
template<typename T> void BSONSerializer<T>::SerializeValue(void* typeLocation, const Handle<Value>& value)
{
	if(value->IsNumber())
	{
		double doubleValue = value->NumberValue();
		int intValue = (int) doubleValue;
		if(intValue == doubleValue)
		{
			this->CommitType(typeLocation, BSON_TYPE_INT);
			this->WriteInt32(intValue);
		}
		else
		{
			this->CommitType(typeLocation, BSON_TYPE_NUMBER);
			this->WriteDouble(doubleValue);
		}
	}
	else if(value->IsString())
	{
		this->CommitType(typeLocation, BSON_TYPE_STRING);
		this->WriteLengthPrefixedString(value->ToString());
	}
	else if(value->IsBoolean())
	{
		this->CommitType(typeLocation, BSON_TYPE_BOOLEAN);
		this->WriteBool(value);
	}
	else if(value->IsArray())
	{
		this->CommitType(typeLocation, BSON_TYPE_ARRAY);
		SerializeArray(value);
	}
	else if(value->IsDate())
	{
		this->CommitType(typeLocation, BSON_TYPE_DATE);
		this->WriteInt64(value);
	}
	else if(value->IsRegExp())
	{
		this->CommitType(typeLocation, BSON_TYPE_REGEXP);
		const Handle<RegExp>& regExp = Handle<RegExp>::Cast(value);

		this->WriteString(regExp->GetSource());

		int flags = regExp->GetFlags();
		if(flags & RegExp::kGlobal) this->WriteByte('s');
		if(flags & RegExp::kIgnoreCase) this->WriteByte('i');
		if(flags & RegExp::kMultiline) this->WriteByte('m');
		this->WriteByte(0);
	}
	else if(value->IsFunction())
	{
		this->CommitType(typeLocation, BSON_TYPE_CODE);
		this->WriteLengthPrefixedString(value->ToString());
	}
	else if(value->IsObject())
	{
		const Local<Object>& object = value->ToObject();
		if(object->Has(bson->_bsontypeString))
		{
			const Local<String>& constructorString = object->GetConstructorName();
			if(bson->longString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_LONG);
				this->WriteInt32(object, bson->_longLowString);
				this->WriteInt32(object, bson->_longHighString);
			}
			else if(bson->timestampString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_TIMESTAMP);
				this->WriteInt32(object, bson->_longLowString);
				this->WriteInt32(object, bson->_longHighString);
			}
			else if(bson->objectIDString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_OID);
				this->WriteObjectId(object, bson->_objectIDidString);
			}
			else if(bson->binaryString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_BINARY);

				uint32_t length = object->Get(bson->_binaryPositionString)->Uint32Value();
				Local<Object> bufferObj = object->Get(bson->_binaryBufferString)->ToObject();

				this->WriteInt32(length);
				this->WriteByte(object, bson->_binarySubTypeString);	// write subtype
				// If type 0x02 write the array length aswell
				if(object->Get(bson->_binarySubTypeString)->Int32Value() == 0x02) {
					this->WriteInt32(length);
				}
				// Write the actual data
				this->WriteData(Buffer::Data(bufferObj), length);
			}
			else if(bson->doubleString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_NUMBER);
				this->WriteDouble(object, bson->_doubleValueString);
			}
			else if(bson->symbolString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_SYMBOL);
				this->WriteLengthPrefixedString(object->Get(bson->_symbolValueString)->ToString());
			}
			else if(bson->codeString->StrictEquals(constructorString))
			{
				const Local<String>& function = object->Get(bson->_codeCodeString)->ToString();
				const Local<Object>& scope = object->Get(bson->_codeScopeString)->ToObject();

				// For Node < 0.6.X use the GetPropertyNames
	      #if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 6
	        uint32_t propertyNameLength = scope->GetPropertyNames()->Length();
	      #else
	        uint32_t propertyNameLength = scope->GetOwnPropertyNames()->Length();
	      #endif

				if(propertyNameLength > 0)
				{
					this->CommitType(typeLocation, BSON_TYPE_CODE_W_SCOPE);
					void* codeWidthScopeSize = this->BeginWriteSize();
					this->WriteLengthPrefixedString(function->ToString());
					SerializeDocument(scope);
					this->CommitSize(codeWidthScopeSize);
				}
				else
				{
					this->CommitType(typeLocation, BSON_TYPE_CODE);
					this->WriteLengthPrefixedString(function->ToString());
				}
			}
			else if(bson->dbrefString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_OBJECT);

				void* dbRefSize = this->BeginWriteSize();

				void* refType = this->BeginWriteType();
				this->WriteData("$ref", 5);
				SerializeValue(refType, object->Get(bson->_dbRefNamespaceString));

				void* idType = this->BeginWriteType();
				this->WriteData("$id", 4);
				SerializeValue(idType, object->Get(bson->_dbRefOidString));

				const Local<Value>& refDbValue = object->Get(bson->_dbRefDbString);
				if(!refDbValue->IsUndefined())
				{
					void* dbType = this->BeginWriteType();
					this->WriteData("$db", 4);
					SerializeValue(dbType, refDbValue);
				}

				this->WriteByte(0);
				this->CommitSize(dbRefSize);
			}
			else if(bson->minKeyString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_MIN_KEY);
			}
			else if(bson->maxKeyString->StrictEquals(constructorString))
			{
				this->CommitType(typeLocation, BSON_TYPE_MAX_KEY);
			}
		}
		else if(Buffer::HasInstance(value))
		{
			this->CommitType(typeLocation, BSON_TYPE_BINARY);

	    #if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 3
       Buffer *buffer = ObjectWrap::Unwrap<Buffer>(value->ToObject());
			 uint32_t length = object->length();
	    #else
			 uint32_t length = Buffer::Length(value->ToObject());
	    #endif

			this->WriteInt32(length);
			this->WriteByte(0);
			this->WriteData(Buffer::Data(value->ToObject()), length);
		}
		else
		{
			this->CommitType(typeLocation, BSON_TYPE_OBJECT);
			SerializeDocument(value);
		}
	}
	else if(value->IsNull() || value->IsUndefined())
	{
		this->CommitType(typeLocation, BSON_TYPE_NULL);
	}
}

// Data points to start of element list, length is length of entire document including '\0' but excluding initial size
BSONDeserializer::BSONDeserializer(BSON* aBson, char* data, size_t length)
: bson(aBson),
  pStart(data),
  p(data),
  pEnd(data + length - 1)
{
	if(*pEnd != '\0') ThrowAllocatedStringException(64, "Missing end of document marker '\\0'");
}

BSONDeserializer::BSONDeserializer(BSONDeserializer& parentSerializer, size_t length)
: bson(parentSerializer.bson),
  pStart(parentSerializer.p),
  p(parentSerializer.p),
  pEnd(parentSerializer.p + length - 1)
{
	parentSerializer.p += length;
	if(pEnd > parentSerializer.pEnd) ThrowAllocatedStringException(64, "Child document exceeds parent's bounds");
	if(*pEnd != '\0') ThrowAllocatedStringException(64, "Missing end of document marker '\\0'");
}

Local<String> BSONDeserializer::ReadCString()
{
	char* start = p;
	while(*p++) { }
	return String::New(start, (int32_t) (p-start-1) );
}

int32_t BSONDeserializer::ReadRegexOptions()
{
	int32_t options = 0;
	for(;;)
	{
		switch(*p++)
		{
		case '\0': return options;
		case 's': options |= RegExp::kGlobal; break;
		case 'i': options |= RegExp::kIgnoreCase; break;
		case 'm': options |= RegExp::kMultiline; break;
		}
	}
}

uint32_t BSONDeserializer::ReadIntegerString()
{
	uint32_t value = 0;
	while(*p)
	{
		if(*p < '0' || *p > '9') ThrowAllocatedStringException(64, "Invalid key for array");
		value = value * 10 + *p++ - '0';
	}
	++p;
	return value;
}

Local<String> BSONDeserializer::ReadString()
{
	uint32_t length = ReadUInt32();
	char* start = p;
	p += length;
	return String::New(start, length-1);
}

Local<String> BSONDeserializer::ReadObjectId()
{
	uint16_t objectId[12];
	for(size_t i = 0; i < 12; ++i)
	{
		objectId[i] = *reinterpret_cast<unsigned char*>(p++);
	}
	return String::New(objectId, 12);
}

Handle<Value> BSONDeserializer::DeserializeDocument(bool promoteLongs)
{
	uint32_t length = ReadUInt32();
	if(length < 5) ThrowAllocatedStringException(64, "Bad BSON: Document is less than 5 bytes");

	BSONDeserializer documentDeserializer(*this, length-4);
	return documentDeserializer.DeserializeDocumentInternal(promoteLongs);
}

Handle<Value> BSONDeserializer::DeserializeDocumentInternal(bool promoteLongs)
{
	Local<Object> returnObject = Object::New();

	while(HasMoreData())
	{
		BsonType type = (BsonType) ReadByte();
		const Local<String>& name = ReadCString();
		const Handle<Value>& value = DeserializeValue(type, promoteLongs);
		returnObject->ForceSet(name, value);
	}
	if(p != pEnd) ThrowAllocatedStringException(64, "Bad BSON Document: Serialize consumed unexpected number of bytes");

	// From JavaScript:
	// if(object['$id'] != null) object = new DBRef(object['$ref'], object['$id'], object['$db']);
	if(returnObject->Has(bson->_dbRefIdRefString))
	{
		Local<Value> argv[] = { returnObject->Get(bson->_dbRefRefString), returnObject->Get(bson->_dbRefIdRefString), returnObject->Get(bson->_dbRefDbRefString) };
		return bson->dbrefConstructor->NewInstance(3, argv);
	}
	else
	{
		return returnObject;
	}
}

Handle<Value> BSONDeserializer::DeserializeArray(bool promoteLongs)
{
	uint32_t length = ReadUInt32();
	if(length < 5) ThrowAllocatedStringException(64, "Bad BSON: Array Document is less than 5 bytes");

	BSONDeserializer documentDeserializer(*this, length-4);
	return documentDeserializer.DeserializeArrayInternal(promoteLongs);
}

Handle<Value> BSONDeserializer::DeserializeArrayInternal(bool promoteLongs)
{
	Local<Array> returnArray = Array::New();

	while(HasMoreData())
	{
		BsonType type = (BsonType) ReadByte();
		uint32_t index = ReadIntegerString();
		const Handle<Value>& value = DeserializeValue(type, promoteLongs);
		returnArray->Set(index, value);
	}
	if(p != pEnd) ThrowAllocatedStringException(64, "Bad BSON Array: Serialize consumed unexpected number of bytes");

	return returnArray;
}

Handle<Value> BSONDeserializer::DeserializeValue(BsonType type, bool promoteLongs)
{
	switch(type)
	{
	case BSON_TYPE_STRING:
		return ReadString();

	case BSON_TYPE_INT:
		return Integer::New(ReadInt32());

	case BSON_TYPE_NUMBER:
		return Number::New(ReadDouble());

	case BSON_TYPE_NULL:
		return Null();

	case BSON_TYPE_UNDEFINED:
		return Undefined();

	case BSON_TYPE_TIMESTAMP:
		{
			int32_t lowBits = ReadInt32();
			int32_t highBits = ReadInt32();
			Local<Value> argv[] = { Int32::New(lowBits), Int32::New(highBits) };
			return bson->timestampConstructor->NewInstance(2, argv);
		}

	case BSON_TYPE_BOOLEAN:
		return (ReadByte() != 0) ? True() : False();

	case BSON_TYPE_REGEXP:
		{
			const Local<String>& regex = ReadCString();
			int32_t options = ReadRegexOptions();
			return RegExp::New(regex, (RegExp::Flags) options);
		}

	case BSON_TYPE_CODE:
		{
			const Local<Value>& code = ReadString();
			const Local<Value>& scope = Object::New();
			Local<Value> argv[] = { code, scope };
			return bson->codeConstructor->NewInstance(2, argv);
		}

	case BSON_TYPE_CODE_W_SCOPE:
		{
			ReadUInt32();
			const Local<Value>& code = ReadString();
			const Handle<Value>& scope = DeserializeDocument(promoteLongs);
			Local<Value> argv[] = { code, scope->ToObject() };
			return bson->codeConstructor->NewInstance(2, argv);
		}

	case BSON_TYPE_OID:
		{
			Local<Value> argv[] = { ReadObjectId() };
			return bson->objectIDConstructor->NewInstance(1, argv);
		}

	case BSON_TYPE_BINARY:
		{
			uint32_t length = ReadUInt32();
			uint32_t subType = ReadByte();
			if(subType == 0x02) {
				length = ReadInt32();
			}

			Buffer* buffer = Buffer::New(p, length);
			p += length;

			Handle<Value> argv[] = { buffer->handle_, Uint32::New(subType) };
			return bson->binaryConstructor->NewInstance(2, argv);
		}

	case BSON_TYPE_LONG:
		{
			// Read 32 bit integers
			int32_t lowBits = (int32_t) ReadInt32();
			int32_t highBits = (int32_t) ReadInt32();

			// Promote long is enabled
			if(promoteLongs) {
				// If value is < 2^53 and >-2^53
				if((highBits < 0x200000 || (highBits == 0x200000 && lowBits == 0)) && highBits >= -0x200000) {
					// Adjust the pointer and read as 64 bit value
					p -= 8;
					// Read the 64 bit value
					int64_t finalValue = (int64_t) ReadInt64();
					return Number::New(finalValue);
				} 
			}

			// Decode the Long value
			Local<Value> argv[] = { Int32::New(lowBits), Int32::New(highBits) };
			return bson->longConstructor->NewInstance(2, argv);
		}

	case BSON_TYPE_DATE:
		return Date::New((double) ReadInt64());

	case BSON_TYPE_ARRAY:
		return DeserializeArray(promoteLongs);

	case BSON_TYPE_OBJECT:
		return DeserializeDocument(promoteLongs);

	case BSON_TYPE_SYMBOL:
		{
			const Local<String>& string = ReadString();
			Local<Value> argv[] = { string };
			return bson->symbolConstructor->NewInstance(1, argv);
		}

	case BSON_TYPE_MIN_KEY:
		return bson->minKeyConstructor->NewInstance();

	case BSON_TYPE_MAX_KEY:
		return bson->maxKeyConstructor->NewInstance();

	default:
		ThrowAllocatedStringException(64, "Unhandled BSON Type: %d", type);
	}

	return v8::Null();
}


static Handle<Value> VException(const char *msg)
{
	HandleScope scope;
	return ThrowException(Exception::Error(String::New(msg)));
}

Persistent<FunctionTemplate> BSON::constructor_template;

BSON::BSON() : ObjectWrap()
{
	// Setup pre-allocated comparision objects
	_bsontypeString = Persistent<String>::New(String::New("_bsontype"));
	_longLowString = Persistent<String>::New(String::New("low_"));
	_longHighString = Persistent<String>::New(String::New("high_"));
	_objectIDidString = Persistent<String>::New(String::New("id"));
	_binaryPositionString = Persistent<String>::New(String::New("position"));
	_binarySubTypeString = Persistent<String>::New(String::New("sub_type"));
	_binaryBufferString = Persistent<String>::New(String::New("buffer"));
	_doubleValueString = Persistent<String>::New(String::New("value"));
	_symbolValueString = Persistent<String>::New(String::New("value"));
	_dbRefRefString = Persistent<String>::New(String::New("$ref"));
	_dbRefIdRefString = Persistent<String>::New(String::New("$id"));
	_dbRefDbRefString = Persistent<String>::New(String::New("$db"));
	_dbRefNamespaceString = Persistent<String>::New(String::New("namespace"));
	_dbRefDbString = Persistent<String>::New(String::New("db"));
	_dbRefOidString = Persistent<String>::New(String::New("oid"));
	_codeCodeString = Persistent<String>::New(String::New("code"));
	_codeScopeString = Persistent<String>::New(String::New("scope"));
	_toBSONString = Persistent<String>::New(String::New("toBSON"));

	longString = Persistent<String>::New(String::New("Long"));
	objectIDString = Persistent<String>::New(String::New("ObjectID"));
	binaryString = Persistent<String>::New(String::New("Binary"));
	codeString = Persistent<String>::New(String::New("Code"));
	dbrefString = Persistent<String>::New(String::New("DBRef"));
	symbolString = Persistent<String>::New(String::New("Symbol"));
	doubleString = Persistent<String>::New(String::New("Double"));
	timestampString = Persistent<String>::New(String::New("Timestamp"));
	minKeyString = Persistent<String>::New(String::New("MinKey"));
	maxKeyString = Persistent<String>::New(String::New("MaxKey"));
}

void BSON::Initialize(v8::Handle<v8::Object> target)
{
	// Grab the scope of the call from Node
	HandleScope scope;
	// Define a new function template
	Local<FunctionTemplate> t = FunctionTemplate::New(New);
	constructor_template = Persistent<FunctionTemplate>::New(t);
	constructor_template->InstanceTemplate()->SetInternalFieldCount(1);
	constructor_template->SetClassName(String::NewSymbol("BSON"));

	// Instance methods
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "calculateObjectSize", CalculateObjectSize);
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "serialize", BSONSerialize);
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "serializeWithBufferAndIndex", SerializeWithBufferAndIndex);
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "deserialize", BSONDeserialize);
	NODE_SET_PROTOTYPE_METHOD(constructor_template, "deserializeStream", BSONDeserializeStream);

	target->ForceSet(String::NewSymbol("BSON"), constructor_template->GetFunction());
}

// Create a new instance of BSON and passing it the existing context
Handle<Value> BSON::New(const Arguments &args)
{
	HandleScope scope;

	// Check that we have an array
	if(args.Length() == 1 && args[0]->IsArray())
	{
		// Cast the array to a local reference
		Local<Array> array = Local<Array>::Cast(args[0]);

		if(array->Length() > 0)
		{
			// Create a bson object instance and return it
			BSON *bson = new BSON();

			uint32_t foundClassesMask = 0;

			// Iterate over all entries to save the instantiate funtions
			for(uint32_t i = 0; i < array->Length(); i++) {
				// Let's get a reference to the function
				Local<Function> func = Local<Function>::Cast(array->Get(i));
				Local<String> functionName = func->GetName()->ToString();

				// Save the functions making them persistant handles (they don't get collected)
				if(functionName->StrictEquals(bson->longString)) {
					bson->longConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 1;
				} else if(functionName->StrictEquals(bson->objectIDString)) {
					bson->objectIDConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 2;
				} else if(functionName->StrictEquals(bson->binaryString)) {
					bson->binaryConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 4;
				} else if(functionName->StrictEquals(bson->codeString)) {
					bson->codeConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 8;
				} else if(functionName->StrictEquals(bson->dbrefString)) {
					bson->dbrefConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x10;
				} else if(functionName->StrictEquals(bson->symbolString)) {
					bson->symbolConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x20;
				} else if(functionName->StrictEquals(bson->doubleString)) {
					bson->doubleConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x40;
				} else if(functionName->StrictEquals(bson->timestampString)) {
					bson->timestampConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x80;
				} else if(functionName->StrictEquals(bson->minKeyString)) {
					bson->minKeyConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x100;
				} else if(functionName->StrictEquals(bson->maxKeyString)) {
					bson->maxKeyConstructor = Persistent<Function>::New(func);
					foundClassesMask |= 0x200;
				}
			}

			// Check if we have the right number of constructors otherwise throw an error
			if(foundClassesMask != 0x3ff) {
				delete bson;
				return VException("Missing function constructor for either [Long/ObjectID/Binary/Code/DbRef/Symbol/Double/Timestamp/MinKey/MaxKey]");
			} else {
				bson->Wrap(args.This());
				return args.This();
			}
		}
		else
		{
			return VException("No types passed in");
		}
	}
	else
	{
		return VException("Argument passed in must be an array of types");
	}
}

//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------

Handle<Value> BSON::BSONDeserialize(const Arguments &args)
{
	HandleScope scope;

	// Fail if the first argument is not a string or a buffer
	if(args.Length() > 1 && !args[0]->IsString() && !Buffer::HasInstance(args[0]))
		return VException("First Argument must be a Buffer or String.");

	// Promote longs
	bool promoteLongs = true;

	// If we have an options object
	if(args.Length() == 2 && args[1]->IsObject()) {
		Local<Object> options = args[1]->ToObject();

		if(options->Has(String::New("promoteLongs"))) {
			promoteLongs = options->Get(String::New("promoteLongs"))->ToBoolean()->Value();
		}
	}	

	// Define pointer to data
	Local<Object> obj = args[0]->ToObject();

	// Unpack the BSON parser instance
	BSON *bson = ObjectWrap::Unwrap<BSON>(args.This());

	// If we passed in a buffer, let's unpack it, otherwise let's unpack the string
	if(Buffer::HasInstance(obj))
	{
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 3
		Buffer *buffer = ObjectWrap::Unwrap<Buffer>(obj);
		char* data = buffer->data();
		size_t length = buffer->length();
#else
		char* data = Buffer::Data(obj);
		size_t length = Buffer::Length(obj);
#endif

		// Validate that we have at least 5 bytes
		if(length < 5) return VException("corrupt bson message < 5 bytes long");

		try
		{
			BSONDeserializer deserializer(bson, data, length);
			// deserializer.promoteLongs = promoteLongs;
			return deserializer.DeserializeDocument(promoteLongs);
		}
		catch(char* exception)
		{
			Handle<Value> error = VException(exception);
			free(exception);
			return error;
		}

	}
	else
	{
		// The length of the data for this encoding
		ssize_t len = DecodeBytes(args[0], BINARY);

		// Validate that we have at least 5 bytes
		if(len < 5) return VException("corrupt bson message < 5 bytes long");

		// Let's define the buffer size
		char* data = (char *)malloc(len);
		DecodeWrite(data, len, args[0], BINARY);

		try
		{
			BSONDeserializer deserializer(bson, data, len);
			// deserializer.promoteLongs = promoteLongs;
			Handle<Value> result = deserializer.DeserializeDocument(promoteLongs);
			free(data);
			return result;

		}
		catch(char* exception)
		{
			Handle<Value> error = VException(exception);
			free(exception);
			free(data);
			return error;
		}
	}
}

Local<Object> BSON::GetSerializeObject(const Handle<Value>& argValue)
{
	Local<Object> object = argValue->ToObject();
	if(object->Has(_toBSONString))
	{
		const Local<Value>& toBSON = object->Get(_toBSONString);
		if(!toBSON->IsFunction()) ThrowAllocatedStringException(64, "toBSON is not a function");

		Local<Value> result = Local<Function>::Cast(toBSON)->Call(object, 0, NULL);
		if(!result->IsObject()) ThrowAllocatedStringException(64, "toBSON function did not return an object");
		return result->ToObject();
	}
	else
	{
		return object;
	}
}

Handle<Value> BSON::BSONSerialize(const Arguments &args)
{
	HandleScope scope;

	if(args.Length() == 1 && !args[0]->IsObject()) return VException("One, two or tree arguments required - [object] or [object, boolean] or [object, boolean, boolean]");
	if(args.Length() == 2 && !args[0]->IsObject() && !args[1]->IsBoolean()) return VException("One, two or tree arguments required - [object] or [object, boolean] or [object, boolean, boolean]");
	if(args.Length() == 3 && !args[0]->IsObject() && !args[1]->IsBoolean() && !args[2]->IsBoolean()) return VException("One, two or tree arguments required - [object] or [object, boolean] or [object, boolean, boolean]");
	if(args.Length() == 4 && !args[0]->IsObject() && !args[1]->IsBoolean() && !args[2]->IsBoolean() && !args[3]->IsBoolean()) return VException("One, two or tree arguments required - [object] or [object, boolean] or [object, boolean, boolean] or [object, boolean, boolean, boolean]");
	if(args.Length() > 4) return VException("One, two, tree or four arguments required - [object] or [object, boolean] or [object, boolean, boolean] or [object, boolean, boolean, boolean]");

	// Check if we have an array as the object
	if(args[0]->IsArray()) return VException("Only javascript objects supported");

	// Unpack the BSON parser instance
	BSON *bson = ObjectWrap::Unwrap<BSON>(args.This());

	// Calculate the total size of the document in binary form to ensure we only allocate memory once
	// With serialize function
	bool serializeFunctions = (args.Length() >= 4) && args[3]->BooleanValue();

	char *serialized_object = NULL;
	size_t object_size;
	try
	{
		Local<Object> object = bson->GetSerializeObject(args[0]);

		BSONSerializer<CountStream> counter(bson, false, serializeFunctions);
		counter.SerializeDocument(object);
		object_size = counter.GetSerializeSize();

		// Allocate the memory needed for the serialization
		serialized_object = (char *)malloc(object_size);

		// Check if we have a boolean value
		bool checkKeys = args.Length() >= 3 && args[1]->IsBoolean() && args[1]->BooleanValue();
		BSONSerializer<DataStream> data(bson, checkKeys, serializeFunctions, serialized_object);
		data.SerializeDocument(object);
	}
	catch(char *err_msg)
	{
		free(serialized_object);
		Handle<Value> error = VException(err_msg);
		free(err_msg);
		return error;
	}

	// If we have 3 arguments
	if(args.Length() == 3 || args.Length() == 4)
	{
		Buffer *buffer = Buffer::New(serialized_object, object_size);
		free(serialized_object);
		return scope.Close(buffer->handle_);
	}
	else
	{
		Local<Value> bin_value = Encode(serialized_object, object_size, BINARY)->ToString();
		free(serialized_object);
		return bin_value;
	}
}

Handle<Value> BSON::CalculateObjectSize(const Arguments &args)
{
	HandleScope scope;
	// Ensure we have a valid object
	if(args.Length() == 1 && !args[0]->IsObject()) return VException("One argument required - [object]");
	if(args.Length() == 2 && !args[0]->IsObject() && !args[1]->IsBoolean())  return VException("Two arguments required - [object, boolean]");
	if(args.Length() > 3) return VException("One or two arguments required - [object] or [object, boolean]");

	// Unpack the BSON parser instance
	BSON *bson = ObjectWrap::Unwrap<BSON>(args.This());
	bool serializeFunctions = (args.Length() >= 2) && args[1]->BooleanValue();
	BSONSerializer<CountStream> countSerializer(bson, false, serializeFunctions);
	countSerializer.SerializeDocument(args[0]);

	// Return the object size
	return scope.Close(Uint32::New((uint32_t) countSerializer.GetSerializeSize()));
}

Handle<Value> BSON::SerializeWithBufferAndIndex(const Arguments &args)
{
	HandleScope scope;

	//BSON.serializeWithBufferAndIndex = function serializeWithBufferAndIndex(object, ->, buffer, index) {
	// Ensure we have the correct values
	if(args.Length() > 5) return VException("Four or five parameters required [object, boolean, Buffer, int] or [object, boolean, Buffer, int, boolean]");
	if(args.Length() == 4 && !args[0]->IsObject() && !args[1]->IsBoolean() && !Buffer::HasInstance(args[2]) && !args[3]->IsUint32()) return VException("Four parameters required [object, boolean, Buffer, int]");
	if(args.Length() == 5 && !args[0]->IsObject() && !args[1]->IsBoolean() && !Buffer::HasInstance(args[2]) && !args[3]->IsUint32() && !args[4]->IsBoolean()) return VException("Four parameters required [object, boolean, Buffer, int, boolean]");

	uint32_t index;
	size_t object_size;

	try
	{
		BSON *bson = ObjectWrap::Unwrap<BSON>(args.This());

		Local<Object> obj = args[2]->ToObject();
		char* data = Buffer::Data(obj);
		size_t length = Buffer::Length(obj);

		index = args[3]->Uint32Value();
		bool checkKeys = args.Length() >= 4 && args[1]->IsBoolean() && args[1]->BooleanValue();
		bool serializeFunctions = (args.Length() == 5) && args[4]->BooleanValue();

		BSONSerializer<DataStream> dataSerializer(bson, checkKeys, serializeFunctions, data+index);
		dataSerializer.SerializeDocument(bson->GetSerializeObject(args[0]));
		object_size = dataSerializer.GetSerializeSize();

		if(object_size + index > length) return VException("Serious error - overflowed buffer!!");
	}
	catch(char *exception)
	{
		Handle<Value> error = VException(exception);
		free(exception);
		return error;
	}

	return scope.Close(Uint32::New((uint32_t) (index + object_size - 1)));
}

Handle<Value> BSON::BSONDeserializeStream(const Arguments &args)
{
	HandleScope scope;

	// At least 3 arguments required
	if(args.Length() < 5) return VException("Arguments required (Buffer(data), Number(index in data), Number(number of documents to deserialize), Array(results), Number(index in the array), Object(optional))");

	// If the number of argumets equals 3
	if(args.Length() >= 5)
	{
		if(!Buffer::HasInstance(args[0])) return VException("First argument must be Buffer instance");
		if(!args[1]->IsUint32()) return VException("Second argument must be a positive index number");
		if(!args[2]->IsUint32()) return VException("Third argument must be a positive number of documents to deserialize");
		if(!args[3]->IsArray()) return VException("Fourth argument must be an array the size of documents to deserialize");
		if(!args[4]->IsUint32()) return VException("Sixth argument must be a positive index number");
	}

	// If we have 4 arguments
	if(args.Length() == 6 && !args[5]->IsObject()) return VException("Fifth argument must be an object with options");

	// Define pointer to data
	Local<Object> obj = args[0]->ToObject();
	uint32_t numberOfDocuments = args[2]->Uint32Value();
	uint32_t index = args[1]->Uint32Value();
	uint32_t resultIndex = args[4]->Uint32Value();
	bool promoteLongs = true;

	// Check for the value promoteLongs in the options object
	if(args.Length() == 6) {
		Local<Object> options = args[5]->ToObject();

		// Check if we have the promoteLong variable
		if(options->Has(String::New("promoteLongs"))) {
			promoteLongs = options->Get(String::New("promoteLongs"))->ToBoolean()->Value();
		}
	}

	// Unpack the BSON parser instance
	BSON *bson = ObjectWrap::Unwrap<BSON>(args.This());

	// Unpack the buffer variable
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 3
	Buffer *buffer = ObjectWrap::Unwrap<Buffer>(obj);
	char* data = buffer->data();
	size_t length = buffer->length();
#else
	char* data = Buffer::Data(obj);
	size_t length = Buffer::Length(obj);
#endif

	// Fetch the documents
	Local<Object> documents = args[3]->ToObject();

	BSONDeserializer deserializer(bson, data+index, length-index);
	for(uint32_t i = 0; i < numberOfDocuments; i++)
	{
		try
		{
			documents->Set(i + resultIndex, deserializer.DeserializeDocument(promoteLongs));
		}
		catch (char* exception)
		{
			Handle<Value> error = VException(exception);
			free(exception);
			return error;
		}
	}

	// Return new index of parsing
	return scope.Close(Uint32::New((uint32_t) (index + deserializer.GetSerializeSize())));
}

// Exporting function
extern "C" void init(Handle<Object> target)
{
	HandleScope scope;
	BSON::Initialize(target);
}

NODE_MODULE(bson, BSON::Initialize);
