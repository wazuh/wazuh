var BaseCommand = require('./base_command').BaseCommand,
  inherits = require('util').inherits;

/**
  Insert Document Command
**/
var QueryCommand = exports.QueryCommand = function(db, collectionName, queryOptions, numberToSkip, numberToReturn, query, returnFieldSelector, options) {
  BaseCommand.call(this);

  // Validate correctness off the selector
  var object = query,
    object_size;
  if(Buffer.isBuffer(object)) {
    object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length) {
      var error = new Error("query selector raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  object = returnFieldSelector;
  if(Buffer.isBuffer(object)) {
    object_size = object[0] | object[1] << 8 | object[2] << 16 | object[3] << 24;
    if(object_size != object.length) {
      var error = new Error("query fields raw message size does not match message header size [" + object.length + "] != [" + object_size + "]");
      error.name = 'MongoError';
      throw error;
    }
  }

  // Make sure we don't get a null exception
  options = options == null ? {} : options;
  // Set up options
  this.collectionName = collectionName;
  this.queryOptions = queryOptions;
  this.numberToSkip = numberToSkip;
  this.numberToReturn = numberToReturn;

  // Ensure we have no null query
  query = query == null ? {} : query;
  // Wrap query in the $query parameter so we can add read preferences for mongos
  this.query = query;
  this.returnFieldSelector = returnFieldSelector;
  this.db = db;

  // Force the slave ok flag to be set if we are not using primary read preference
  if(this.db && this.db.slaveOk) {
    this.queryOptions |= QueryCommand.OPTS_SLAVE;
  }

  // Let us defined on a command basis if we want functions to be serialized or not
  if(options['serializeFunctions'] != null && options['serializeFunctions']) {
    this.serializeFunctions = true;
  }
};

inherits(QueryCommand, BaseCommand);

QueryCommand.OP_QUERY = 2004;

/*
 * Adds the read prefrence to the current command
 */
QueryCommand.prototype.setMongosReadPreference = function(readPreference, tags) {
  // If we have readPreference set to true set to secondary prefered
  if(readPreference == true) {
    readPreference = 'secondaryPreferred';
  } else if(readPreference == 'false') {
    readPreference = 'primary';
  }

  // Force the slave ok flag to be set if we are not using primary read preference
  if(readPreference != false && readPreference != 'primary') {
    this.queryOptions |= QueryCommand.OPTS_SLAVE;
  }

  // Backward compatibility, ensure $query only set on read preference so 1.8.X works
  if((readPreference != null || tags != null) && this.query['$query'] == null) {
    this.query = {'$query': this.query};
  }

  // If we have no readPreference set and no tags, check if the slaveOk bit is set
  if(readPreference == null && tags == null) {
    // If we have a slaveOk bit set the read preference for MongoS
    if(this.queryOptions & QueryCommand.OPTS_SLAVE) {
      this.query['$readPreference'] = {mode: 'secondary'}
    } else {
      this.query['$readPreference'] = {mode: 'primary'}
    }
  }

  // Build read preference object
  if(typeof readPreference == 'object' && readPreference['_type'] == 'ReadPreference') {
    this.query['$readPreference'] = readPreference.toObject();
  } else if(readPreference != null) {
    // Add the read preference
    this.query['$readPreference'] = {mode: readPreference};

    // If we have tags let's add them
    if(tags != null) {
      this.query['$readPreference']['tags'] = tags;
    }
  }
}

/*
struct {
    MsgHeader header;                 // standard message header
    int32     opts;                   // query options.  See below for details.
    cstring   fullCollectionName;     // "dbname.collectionname"
    int32     numberToSkip;           // number of documents to skip when returning results
    int32     numberToReturn;         // number of documents to return in the first OP_REPLY
    BSON      query ;                 // query object.  See below for details.
  [ BSON      returnFieldSelector; ]  // OPTIONAL : selector indicating the fields to return.  See below for details.
}
*/
QueryCommand.prototype.toBinary = function(bsonSettings) {
  // Validate that we are not passing 0x00 in the colletion name
  if(!!~this.collectionName.indexOf("\x00")) {
    throw new Error("namespace cannot contain a null character");
  }

  // Total length of the command
  var totalLengthOfCommand = 0;
  // Calculate total length of the document
  if(Buffer.isBuffer(this.query)) {
    totalLengthOfCommand = 4 + Buffer.byteLength(this.collectionName) + 1 + 4 + 4 + this.query.length + (4 * 4);
  } else {
    totalLengthOfCommand = 4 + Buffer.byteLength(this.collectionName) + 1 + 4 + 4 + this.db.bson.calculateObjectSize(this.query, this.serializeFunctions, true) + (4 * 4);
  }

  // Calculate extra fields size
  if(this.returnFieldSelector != null && !(Buffer.isBuffer(this.returnFieldSelector)))  {
    if(Object.keys(this.returnFieldSelector).length > 0) {
      totalLengthOfCommand += this.db.bson.calculateObjectSize(this.returnFieldSelector, this.serializeFunctions, true);
    }
  } else if(Buffer.isBuffer(this.returnFieldSelector)) {
    totalLengthOfCommand += this.returnFieldSelector.length;
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
  _command[_index + 3] = (QueryCommand.OP_QUERY >> 24) & 0xff;
  _command[_index + 2] = (QueryCommand.OP_QUERY >> 16) & 0xff;
  _command[_index + 1] = (QueryCommand.OP_QUERY >> 8) & 0xff;
  _command[_index] = QueryCommand.OP_QUERY & 0xff;
  // Adjust index
  _index = _index + 4;

  // Write the query options
  _command[_index + 3] = (this.queryOptions >> 24) & 0xff;
  _command[_index + 2] = (this.queryOptions >> 16) & 0xff;
  _command[_index + 1] = (this.queryOptions >> 8) & 0xff;
  _command[_index] = this.queryOptions & 0xff;
  // Adjust index
  _index = _index + 4;

  // Write the collection name to the command
  _index = _index + _command.write(this.collectionName, _index, 'utf8') + 1;
  _command[_index - 1] = 0;

  // Write the number of documents to skip
  _command[_index + 3] = (this.numberToSkip >> 24) & 0xff;
  _command[_index + 2] = (this.numberToSkip >> 16) & 0xff;
  _command[_index + 1] = (this.numberToSkip >> 8) & 0xff;
  _command[_index] = this.numberToSkip & 0xff;
  // Adjust index
  _index = _index + 4;

  // Write the number of documents to return
  _command[_index + 3] = (this.numberToReturn >> 24) & 0xff;
  _command[_index + 2] = (this.numberToReturn >> 16) & 0xff;
  _command[_index + 1] = (this.numberToReturn >> 8) & 0xff;
  _command[_index] = this.numberToReturn & 0xff;
  // Adjust index
  _index = _index + 4;

  // Document binary length
  var documentLength = 0
  var object = this.query;

  // Serialize the selector
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

  // Push field selector if available
  if(this.returnFieldSelector != null && !(Buffer.isBuffer(this.returnFieldSelector)))  {
    if(Object.keys(this.returnFieldSelector).length > 0) {
      var documentLength = this.db.bson.serializeWithBufferAndIndex(this.returnFieldSelector, this.checkKeys, _command, _index, this.serializeFunctions) - _index + 1;
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
  } if(this.returnFieldSelector != null && Buffer.isBuffer(this.returnFieldSelector))  {
    // Document binary length
    var documentLength = 0
    var object = this.returnFieldSelector;

    // Serialize the selector
    documentLength = object.length;
    // Copy the data into the current buffer
    object.copy(_command, _index);

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

  // Return finished command
  return _command;
};

// Constants
QueryCommand.OPTS_NONE = 0;
QueryCommand.OPTS_TAILABLE_CURSOR = 2;
QueryCommand.OPTS_SLAVE = 4;
QueryCommand.OPTS_OPLOG_REPLY = 8;
QueryCommand.OPTS_NO_CURSOR_TIMEOUT = 16;
QueryCommand.OPTS_AWAIT_DATA = 32;
QueryCommand.OPTS_EXHAUST = 64;
QueryCommand.OPTS_PARTIAL = 128;