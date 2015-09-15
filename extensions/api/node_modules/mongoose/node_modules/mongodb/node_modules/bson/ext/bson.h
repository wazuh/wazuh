//===========================================================================

#ifndef BSON_H_
#define BSON_H_

//===========================================================================

#ifdef __arm__
#define USE_MISALIGNED_MEMORY_ACCESS 0
#else
#define USE_MISALIGNED_MEMORY_ACCESS 1
#endif

#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

using namespace v8;
using namespace node;

//===========================================================================

enum BsonType
{
	BSON_TYPE_NUMBER		= 1,
	BSON_TYPE_STRING		= 2,
	BSON_TYPE_OBJECT		= 3,
	BSON_TYPE_ARRAY			= 4,
	BSON_TYPE_BINARY		= 5,
	BSON_TYPE_UNDEFINED		= 6,
	BSON_TYPE_OID			= 7,
	BSON_TYPE_BOOLEAN		= 8,
	BSON_TYPE_DATE			= 9,
	BSON_TYPE_NULL			= 10,
	BSON_TYPE_REGEXP		= 11,
	BSON_TYPE_CODE			= 13,
	BSON_TYPE_SYMBOL		= 14,
	BSON_TYPE_CODE_W_SCOPE	= 15,
	BSON_TYPE_INT			= 16,
	BSON_TYPE_TIMESTAMP		= 17,
	BSON_TYPE_LONG			= 18,
	BSON_TYPE_MAX_KEY		= 0x7f,
	BSON_TYPE_MIN_KEY		= 0xff
};

//===========================================================================

template<typename T> class BSONSerializer;

class BSON : public ObjectWrap {
public:    
	BSON();
	~BSON() {}

	static void Initialize(Handle<Object> target);
	static Handle<Value> BSONDeserializeStream(const Arguments &args);

	// JS based objects
	static Handle<Value> BSONSerialize(const Arguments &args);
	static Handle<Value> BSONDeserialize(const Arguments &args);

	// Calculate size of function
	static Handle<Value> CalculateObjectSize(const Arguments &args);
	static Handle<Value> SerializeWithBufferAndIndex(const Arguments &args);

	// Constructor used for creating new BSON objects from C++
	static Persistent<FunctionTemplate> constructor_template;

private:
	static Handle<Value> New(const Arguments &args);
	static Handle<Value> deserialize(BSON *bson, char *data, uint32_t dataLength, uint32_t startIndex, bool is_array_item);

	// BSON type instantiate functions
	Persistent<Function> longConstructor;
	Persistent<Function> objectIDConstructor;
	Persistent<Function> binaryConstructor;
	Persistent<Function> codeConstructor;
	Persistent<Function> dbrefConstructor;
	Persistent<Function> symbolConstructor;
	Persistent<Function> doubleConstructor;
	Persistent<Function> timestampConstructor;
	Persistent<Function> minKeyConstructor;
	Persistent<Function> maxKeyConstructor;

	// Equality Objects
	Persistent<String> longString;
	Persistent<String> objectIDString;
	Persistent<String> binaryString;
	Persistent<String> codeString;
	Persistent<String> dbrefString;
	Persistent<String> symbolString;
	Persistent<String> doubleString;
	Persistent<String> timestampString;
	Persistent<String> minKeyString;
	Persistent<String> maxKeyString;

	// Equality speed up comparison objects
	Persistent<String> _bsontypeString;
	Persistent<String> _longLowString;
	Persistent<String> _longHighString;
	Persistent<String> _objectIDidString;
	Persistent<String> _binaryPositionString;
	Persistent<String> _binarySubTypeString;
	Persistent<String> _binaryBufferString;
	Persistent<String> _doubleValueString;
	Persistent<String> _symbolValueString;

	Persistent<String> _dbRefRefString;
	Persistent<String> _dbRefIdRefString;
	Persistent<String> _dbRefDbRefString;
	Persistent<String> _dbRefNamespaceString;
	Persistent<String> _dbRefDbString;
	Persistent<String> _dbRefOidString;

	Persistent<String> _codeCodeString;
	Persistent<String> _codeScopeString;
	Persistent<String> _toBSONString;

	Local<Object> GetSerializeObject(const Handle<Value>& object);

	template<typename T> friend class BSONSerializer;
	friend class BSONDeserializer;
};

//===========================================================================

class CountStream
{
public:
	CountStream() : count(0) { }

	void	WriteByte(int value)									{ ++count; }
	void	WriteByte(const Handle<Object>&, const Handle<String>&)	{ ++count; }
	void	WriteBool(const Handle<Value>& value)					{ ++count; }
	void	WriteInt32(int32_t value)								{ count += 4; }
	void	WriteInt32(const Handle<Value>& value)					{ count += 4; }
	void	WriteInt32(const Handle<Object>& object, const Handle<String>& key) { count += 4; }
	void	WriteInt64(int64_t value)								{ count += 8; }
	void	WriteInt64(const Handle<Value>& value)					{ count += 8; }
	void	WriteDouble(double value)								{ count += 8; }
	void	WriteDouble(const Handle<Value>& value)					{ count += 8; }
	void	WriteDouble(const Handle<Object>&, const Handle<String>&) { count += 8; }
	void	WriteUInt32String(uint32_t name)						{ char buffer[32]; count += sprintf(buffer, "%u", name) + 1; }
	void	WriteLengthPrefixedString(const Local<String>& value)	{ count += value->Utf8Length()+5; }
	void	WriteObjectId(const Handle<Object>& object, const Handle<String>& key)				{ count += 12; }
	void	WriteString(const Local<String>& value)					{ count += value->Utf8Length() + 1; }	// This returns the number of bytes exclusive of the NULL terminator
	void	WriteData(const char* data, size_t length)				{ count += length; }

	void*	BeginWriteType()										{ ++count; return NULL; }
	void	CommitType(void*, BsonType)								{ }
	void*	BeginWriteSize()										{ count += 4; return NULL; }
	void	CommitSize(void*)										{ }

	size_t GetSerializeSize() const									{ return count; }

	// Do nothing. CheckKey is implemented for DataStream
	void	CheckKey(const Local<String>&)							{ }

private:
	size_t	count;
};

class DataStream
{
public:
	DataStream(char* aDestinationBuffer) : destinationBuffer(aDestinationBuffer), p(aDestinationBuffer) { }

	void	WriteByte(int value)									{ *p++ = value; }
	void	WriteByte(const Handle<Object>& object, const Handle<String>& key)	{ *p++ = object->Get(key)->Int32Value(); }
#if USE_MISALIGNED_MEMORY_ACCESS
	void	WriteInt32(int32_t value)								{ *reinterpret_cast<int32_t*>(p) = value; p += 4; }
	void	WriteInt64(int64_t value)								{ *reinterpret_cast<int64_t*>(p) = value; p += 8; }
	void	WriteDouble(double value)								{ *reinterpret_cast<double*>(p) = value; p += 8; }
#else
	void	WriteInt32(int32_t value)								{ memcpy(p, &value, 4); p += 4; }
	void	WriteInt64(int64_t value)								{ memcpy(p, &value, 8); p += 8; }
	void	WriteDouble(double value)								{ memcpy(p, &value, 8); p += 8; }
#endif
	void	WriteBool(const Handle<Value>& value)					{ WriteByte(value->BooleanValue() ? 1 : 0); }
	void	WriteInt32(const Handle<Value>& value)					{ WriteInt32(value->Int32Value());			}
	void	WriteInt32(const Handle<Object>& object, const Handle<String>& key) { WriteInt32(object->Get(key)); }
	void	WriteInt64(const Handle<Value>& value)					{ WriteInt64(value->IntegerValue());		}
	void	WriteDouble(const Handle<Value>& value)					{ WriteDouble(value->NumberValue());		}
	void	WriteDouble(const Handle<Object>& object, const Handle<String>& key) { WriteDouble(object->Get(key)); }
	void	WriteUInt32String(uint32_t name)						{ p += sprintf(p, "%u", name) + 1;			}
	void	WriteLengthPrefixedString(const Local<String>& value)	{ WriteInt32(value->Utf8Length()+1); WriteString(value); }
	void	WriteObjectId(const Handle<Object>& object, const Handle<String>& key);
	void	WriteString(const Local<String>& value)					{ p += value->WriteUtf8(p); }		// This returns the number of bytes inclusive of the NULL terminator.
	void	WriteData(const char* data, size_t length)				{ memcpy(p, data, length); p += length; }

	void*	BeginWriteType()										{ void* returnValue = p; p++; return returnValue; }
	void	CommitType(void* beginPoint, BsonType value)			{ *reinterpret_cast<unsigned char*>(beginPoint) = value; }
	void*	BeginWriteSize()										{ void* returnValue = p; p += 4; return returnValue; }

#if USE_MISALIGNED_MEMORY_ACCESS
	void	CommitSize(void* beginPoint)							{ *reinterpret_cast<int32_t*>(beginPoint) = (int32_t) (p - (char*) beginPoint); }
#else
	void	CommitSize(void* beginPoint)							{ int32_t value = (int32_t) (p - (char*) beginPoint); memcpy(beginPoint, &value, 4); }
#endif

	size_t GetSerializeSize() const									{ return p - destinationBuffer; }

	void	CheckKey(const Local<String>& keyName);

protected:
	char *const	destinationBuffer;		// base, never changes
	char*		p;						// cursor into buffer
};

template<typename T> class BSONSerializer : public T
{
private:
	typedef T Inherited;

public:
	BSONSerializer(BSON* aBson, bool aCheckKeys, bool aSerializeFunctions) : Inherited(), checkKeys(aCheckKeys), serializeFunctions(aSerializeFunctions), bson(aBson) { }
	BSONSerializer(BSON* aBson, bool aCheckKeys, bool aSerializeFunctions, char* parentParam) : Inherited(parentParam), checkKeys(aCheckKeys), serializeFunctions(aSerializeFunctions), bson(aBson) { }

	void SerializeDocument(const Handle<Value>& value);
	void SerializeArray(const Handle<Value>& value);
	void SerializeValue(void* typeLocation, const Handle<Value>& value);

private:
	bool		checkKeys;
	bool		serializeFunctions;
	BSON*		bson;
};

//===========================================================================

class BSONDeserializer
{
public:
	BSONDeserializer(BSON* aBson, char* data, size_t length);
	BSONDeserializer(BSONDeserializer& parentSerializer, size_t length);

	Handle<Value> DeserializeDocument(bool promoteLongs);

	bool			HasMoreData() const { return p < pEnd; }
	Local<String>	ReadCString();
	uint32_t		ReadIntegerString();
	int32_t			ReadRegexOptions();
	Local<String>	ReadString();
	Local<String>	ReadObjectId();

	unsigned char	ReadByte()			{ return *reinterpret_cast<unsigned char*>(p++); }
#if USE_MISALIGNED_MEMORY_ACCESS
	int32_t			ReadInt32()			{ int32_t returnValue = *reinterpret_cast<int32_t*>(p); p += 4; return returnValue; }
	uint32_t		ReadUInt32()		{ uint32_t returnValue = *reinterpret_cast<uint32_t*>(p); p += 4; return returnValue; }
	int64_t			ReadInt64()			{ int64_t returnValue = *reinterpret_cast<int64_t*>(p); p += 8; return returnValue; }
	double			ReadDouble()		{ double returnValue = *reinterpret_cast<double*>(p); p += 8; return returnValue; }
#else
	int32_t			ReadInt32()			{ int32_t returnValue; memcpy(&returnValue, p, 4); p += 4; return returnValue; }
	uint32_t		ReadUInt32()		{ uint32_t returnValue; memcpy(&returnValue, p, 4); p += 4; return returnValue; }
	int64_t			ReadInt64()			{ int64_t returnValue; memcpy(&returnValue, p, 8); p += 8; return returnValue; }
	double			ReadDouble()		{ double returnValue; memcpy(&returnValue, p, 8); p += 8; return returnValue; }
#endif

	size_t			GetSerializeSize() const { return p - pStart; }

private:
	Handle<Value> DeserializeArray(bool promoteLongs);
	Handle<Value> DeserializeValue(BsonType type, bool promoteLongs);
	Handle<Value> DeserializeDocumentInternal(bool promoteLongs);
	Handle<Value> DeserializeArrayInternal(bool promoteLongs);

	BSON*		bson;
	char* const pStart;
	char*		p;
	char* const	pEnd;
};

//===========================================================================

#endif  // BSON_H_

//===========================================================================
