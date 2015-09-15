var BaseCommand = require('./base_command').BaseCommand,
  inherits = require('util').inherits;

/**
  Insert Document Command
**/
var InsertCommand = exports.InsertCommand = function(db, collectionName, checkKeys, options) {
  BaseCommand.call(this);

  this.collectionName = collectionName;
  this.documents = [];
  this.checkKeys = checkKeys == null ? true : checkKeys;
  this.db = db;
  this.flags = 0;
  this.serializeFunctions = false;

  // Ensure valid options hash
  options = options == null ? {} : options;

  // Check if we have keepGoing set -> set flag if it's the case
  if(options['keepGoing'] != null && options['keepGoing']) {
    // This will finish inserting all non-index violating documents even if it returns an error
    this.flags = 1;
  }

  // Check if we have keepGoing set -> set flag if it's the case
  if(options['continueOnError'] != null && options['continueOnError']) {
    // This will finish inserting all non-index violating documents even if it returns an error
    this.flags = 1;
  }

  // Let us defined on a command basis if we want functions to be serialized or not
  if(options['serializeFunctions'] != null && options['serializeFunctions']) {
    this.serializeFunctions = true;
  }
};

inherits(InsertCommand, BaseCommand);

// OpCodes
InsertCommand.OP_INSERT =	2002;

InsertCommand.prototype.add = function(document) {
  if(Buffer.isBuffer(document)) {
    var object_size = document[0] | document[1] << 8 | document[2] << 16 | document[3] << 24;
    if(object_size != document.length)  {
      var error = new Error("insert raw message size does not match message header size [" + document.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  this.documents.push(document);
  return this;
};

/*
struct {
    MsgHeader header;             // standard message header
    int32     ZERO;               // 0 - reserved for future use
    cstring   fullCollectionName; // "dbname.collectionname"
    BSON[]    documents;          // one or more documents to insert into the collection
}
*/
InsertCommand.prototype.toBinary = function(bsonSettings) {
  // Validate that we are not passing 0x00 in the colletion name
  if(!!~this.collectionName.indexOf("\x00")) {
    throw new Error("namespace cannot contain a null character");
  }

  // Calculate total length of the document
  var totalLengthOfCommand = 4 + Buffer.byteLength(this.collectionName) + 1 + (4 * 4);
  // var docLength = 0
  for(var i = 0; i < this.documents.length; i++) {
    if(Buffer.isBuffer(this.documents[i])) {
      totalLengthOfCommand += this.documents[i].length;
    } else {
      // Calculate size of document
      totalLengthOfCommand += this.db.bson.calculateObjectSize(this.documents[i], this.serializeFunctions, true);
    }
  }

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
  _command[_index + 3] = (InsertCommand.OP_INSERT >> 24) & 0xff;
  _command[_index + 2] = (InsertCommand.OP_INSERT >> 16) & 0xff;
  _command[_index + 1] = (InsertCommand.OP_INSERT >> 8) & 0xff;
  _command[_index] = InsertCommand.OP_INSERT & 0xff;
  // Adjust index
  _index = _index + 4;
  // Write flags if any
  _command[_index + 3] = (this.flags >> 24) & 0xff;
  _command[_index + 2] = (this.flags >> 16) & 0xff;
  _command[_index + 1] = (this.flags >> 8) & 0xff;
  _command[_index] = this.flags & 0xff;
  // Adjust index
  _index = _index + 4;
  // Write the collection name to the command
  _index = _index + _command.write(this.collectionName, _index, 'utf8') + 1;
  _command[_index - 1] = 0;

  // Write all the bson documents to the buffer at the index offset
  for(var i = 0; i < this.documents.length; i++) {
    // Document binary length
    var documentLength = 0
    var object = this.documents[i];

    // Serialize the selector
    // If we are passing a raw buffer, do minimal validation
    if(Buffer.isBuffer(object)) {
      documentLength = object.length;
      // Copy the data into the current buffer
      object.copy(_command, _index);
    } else {
      // Serialize the document straight to the buffer
      documentLength = this.db.bson.serializeWithBufferAndIndex(object, this.checkKeys, _command, _index, this.serializeFunctions) - _index + 1;
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
  }

  return _command;
};
