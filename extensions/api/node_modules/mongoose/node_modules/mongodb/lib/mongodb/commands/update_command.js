var BaseCommand = require('./base_command').BaseCommand,
  inherits = require('util').inherits;

/**
  Update Document Command
**/
var UpdateCommand = exports.UpdateCommand = function(db, collectionName, spec, document, options) {
  BaseCommand.call(this);

  var object = spec;
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;    
    if(object_size != object.length)  {
      var error = new Error("update spec raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  var object = document;
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;    
    if(object_size != object.length)  {
      var error = new Error("update document raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  this.collectionName = collectionName;
  this.spec = spec;
  this.document = document;
  this.db = db;
  this.serializeFunctions = false;
  this.checkKeys = typeof options.checkKeys != 'boolean' ? false : options.checkKeys;

  // Generate correct flags
  var db_upsert = 0;
  var db_multi_update = 0;
  db_upsert = options != null && options['upsert'] != null ? (options['upsert'] == true ? 1 : 0) : db_upsert;
  db_multi_update = options != null && options['multi'] != null ? (options['multi'] == true ? 1 : 0) : db_multi_update;

  // Flags
  this.flags = parseInt(db_multi_update.toString() + db_upsert.toString(), 2);
  // Let us defined on a command basis if we want functions to be serialized or not
  if(options['serializeFunctions'] != null && options['serializeFunctions']) {
    this.serializeFunctions = true;
  }
};

inherits(UpdateCommand, BaseCommand);

UpdateCommand.OP_UPDATE = 2001;

/*
struct {
    MsgHeader header;             // standard message header
    int32     ZERO;               // 0 - reserved for future use
    cstring   fullCollectionName; // "dbname.collectionname"
    int32     flags;              // bit vector. see below
    BSON      spec;               // the query to select the document
    BSON      document;           // the document data to update with or insert
}
*/
UpdateCommand.prototype.toBinary = function(bsonSettings) {
  // Validate that we are not passing 0x00 in the colletion name
  if(!!~this.collectionName.indexOf("\x00")) {
    throw new Error("namespace cannot contain a null character");
  }

  // Calculate total length of the document
  var totalLengthOfCommand = 4 + Buffer.byteLength(this.collectionName) + 1 + 4 + this.db.bson.calculateObjectSize(this.spec, false, true) +
      this.db.bson.calculateObjectSize(this.document, this.serializeFunctions, true) + (4 * 4);

  // Enforce maximum bson size
  if(!bsonSettings.disableDriverBSONSizeCheck 
    && totalLengthOfCommand > bsonSettings.maxBsonSize) 
    throw new Error("Document exceeds maximum allowed bson size of " + bsonSettings.maxBsonSize + " bytes");

  if(bsonSettings.disableDriverBSONSizeCheck 
    && totalLengthOfCommand > bsonSettings.maxMessageSizeBytes) 
    throw new Error("Command exceeds maximum message size of " + bsonSettings.maxMessageSizeBytes + " bytes");

  // Let's build the single pass buffer command
  var _index = 0;
  var _command = new Buffer(totalLengthOfCommand);
  // Write the header information to the buffer
  _command[_index + 3] = (totalLengthOfCommand >> 24) & 0xff;     
  _command[_index + 2] = (totalLengthOfCommand >> 16) & 0xff;
  _command[_index + 1] = (totalLengthOfCommand >> 8) & 0xff;
  _command[_index] = totalLengthOfCommand & 0xff;
  // Adjust index
  _index = _index + 4;
  // Write the request ID
  _command[_index + 3] = (this.requestId >> 24) & 0xff;     
  _command[_index + 2] = (this.requestId >> 16) & 0xff;
  _command[_index + 1] = (this.requestId >> 8) & 0xff;
  _command[_index] = this.requestId & 0xff;
  // Adjust index
  _index = _index + 4;
  // Write zero
  _command[_index++] = 0;
  _command[_index++] = 0;
  _command[_index++] = 0;
  _command[_index++] = 0;
  // Write the op_code for the command
  _command[_index + 3] = (UpdateCommand.OP_UPDATE >> 24) & 0xff;     
  _command[_index + 2] = (UpdateCommand.OP_UPDATE >> 16) & 0xff;
  _command[_index + 1] = (UpdateCommand.OP_UPDATE >> 8) & 0xff;
  _command[_index] = UpdateCommand.OP_UPDATE & 0xff;
  // Adjust index
  _index = _index + 4;

  // Write zero
  _command[_index++] = 0;
  _command[_index++] = 0;
  _command[_index++] = 0;
  _command[_index++] = 0;

  // Write the collection name to the command
  _index = _index + _command.write(this.collectionName, _index, 'utf8') + 1;
  _command[_index - 1] = 0;    

  // Write the update flags
  _command[_index + 3] = (this.flags >> 24) & 0xff;     
  _command[_index + 2] = (this.flags >> 16) & 0xff;
  _command[_index + 1] = (this.flags >> 8) & 0xff;
  _command[_index] = this.flags & 0xff;
  // Adjust index
  _index = _index + 4;

  // Document binary length
  var documentLength = 0
  var object = this.spec;

  // Serialize the selector
  // If we are passing a raw buffer, do minimal validation
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length) throw new Error("raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
    documentLength = object.length;
    // Copy the data into the current buffer
    object.copy(_command, _index);
  } else {
    documentLength = this.db.bson.serializeWithBufferAndIndex(object, this.checkKeys, _command, _index, false) - _index + 1;
  }

  // Write the length to the document
  _command[_index + 3] = (documentLength >> 24) & 0xff;     
  _command[_index + 2] = (documentLength >> 16) & 0xff;
  _command[_index + 1] = (documentLength >> 8) & 0xff;
  _command[_index] = documentLength & 0xff;
  // Update index in buffer
  _index = _index + documentLength;
  // Add terminating 0 for the object
  _command[_index - 1] = 0;    

  // Document binary length
  var documentLength = 0
  var object = this.document;

  // Serialize the document
  // If we are passing a raw buffer, do minimal validation
  if(Buffer.isBuffer(object)) {
    var object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length) throw new Error("raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
    documentLength = object.length;
    // Copy the data into the current buffer
    object.copy(_command, _index);
  } else {    
    documentLength = this.db.bson.serializeWithBufferAndIndex(object, false, _command, _index, this.serializeFunctions) - _index + 1;
  }

  // Write the length to the document
  _command[_index + 3] = (documentLength >> 24) & 0xff;     
  _command[_index + 2] = (documentLength >> 16) & 0xff;
  _command[_index + 1] = (documentLength >> 8) & 0xff;
  _command[_index] = documentLength & 0xff;
  // Update index in buffer
  _index = _index + documentLength;
  // Add terminating 0 for the object
  _command[_index - 1] = 0;    

  return _command;
};

// Constants
UpdateCommand.DB_UPSERT = 0;
UpdateCommand.DB_MULTI_UPDATE = 1;