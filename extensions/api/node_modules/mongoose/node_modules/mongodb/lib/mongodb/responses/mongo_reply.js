var Long = require('bson').Long
  , timers = require('timers');

// Set processor, setImmediate if 0.10 otherwise nextTick
var processor = require('../utils').processor();

/**
  Reply message from mongo db
**/
var MongoReply = exports.MongoReply = function() {
  this.documents = [];
  this.index = 0;
};

MongoReply.prototype.parseHeader = function(binary_reply, bson) {
  // Unpack the standard header first
  this.messageLength = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  // Fetch the request id for this reply
  this.requestId = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  // Fetch the id of the request that triggered the response
  this.responseTo = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  // Skip op-code field
  this.index = this.index + 4 + 4;
  // Unpack the reply message
  this.responseFlag = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  // Unpack the cursor id (a 64 bit long integer)
  var low_bits = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  var high_bits = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  this.cursorId = new Long(low_bits, high_bits);
  // Unpack the starting from
  this.startingFrom = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
  // Unpack the number of objects returned
  this.numberReturned = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
  this.index = this.index + 4;
}

MongoReply.prototype.parseBody = function(binary_reply, bson, raw, callback) {
  raw = raw == null ? false : raw;

  try {
    // Let's unpack all the bson documents, deserialize them and store them
    for(var object_index = 0; object_index < this.numberReturned; object_index++) {
      var _options = {promoteLongs: bson.promoteLongs};
      
      // Read the size of the bson object
      var bsonObjectSize = binary_reply[this.index] | binary_reply[this.index + 1] << 8 | binary_reply[this.index + 2] << 16 | binary_reply[this.index + 3] << 24;
      
      // If we are storing the raw responses to pipe straight through
      if(raw) {
        // Deserialize the object and add to the documents array
        this.documents.push(binary_reply.slice(this.index, this.index + bsonObjectSize));
      } else {
        // Deserialize the object and add to the documents array
        this.documents.push(bson.deserialize(binary_reply.slice(this.index, this.index + bsonObjectSize), _options));
      }
      
      // Adjust binary index to point to next block of binary bson data
      this.index = this.index + bsonObjectSize;
    }
    
    // No error return
    callback(null);
  } catch(err) {
    return callback(err);
  }
}

MongoReply.prototype.is_error = function(){
  if(this.documents.length == 1) {
    return this.documents[0].ok == 1 ? false : true;
  }
  return false;
};

MongoReply.prototype.error_message = function() {
  return this.documents.length == 1 && this.documents[0].ok == 1 ? '' : this.documents[0].errmsg;
};