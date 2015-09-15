/**
 * Module dependencies.
 */
var BinaryParser = require('./binary_parser').BinaryParser;

/**
 * Machine id.
 *
 * Create a random 3-byte value (i.e. unique for this
 * process). Other drivers use a md5 of the machine id here, but
 * that would mean an asyc call to gethostname, so we don't bother.
 */
var MACHINE_ID = parseInt(Math.random() * 0xFFFFFF, 10);

// Regular expression that checks for hex value
var checkForHexRegExp = new RegExp("^[0-9a-fA-F]{24}$");

/**
* Create a new ObjectID instance
*
* @class Represents the BSON ObjectID type
* @param {String|Number} id Can be a 24 byte hex string, 12 byte binary string or a Number.
* @return {Object} instance of ObjectID.
*/
var ObjectID = function ObjectID(id, _hex) {
  if(!(this instanceof ObjectID)) return new ObjectID(id, _hex);

  this._bsontype = 'ObjectID';
  var __id = null;

  // Throw an error if it's not a valid setup
  if(id != null && 'number' != typeof id && (id.length != 12 && id.length != 24))
    throw new Error("Argument passed in must be a single String of 12 bytes or a string of 24 hex characters");

  // Generate id based on the input
  if(id == null || typeof id == 'number') {
    // convert to 12 byte binary string
    this.id = this.generate(id);
  } else if(id != null && id.length === 12) {
    // assume 12 byte string
    this.id = id;
  } else if(checkForHexRegExp.test(id)) {
    return ObjectID.createFromHexString(id);
  } else {
    throw new Error("Value passed in is not a valid 24 character hex string");
  }

  if(ObjectID.cacheHexString) this.__id = this.toHexString();
};

// Allow usage of ObjectId aswell as ObjectID
var ObjectId = ObjectID;

/**
* Return the ObjectID id as a 24 byte hex string representation
*
* @return {String} return the 24 byte hex string representation.
* @api public
*/
ObjectID.prototype.toHexString = function() {
  if(ObjectID.cacheHexString && this.__id) return this.__id;

  var hexString = ''
    , number
    , value;

  for (var index = 0, len = this.id.length; index < len; index++) {
    value = BinaryParser.toByte(this.id[index]);
    number = value <= 15
      ? '0' + value.toString(16)
      : value.toString(16);
    hexString = hexString + number;
  }

  if(ObjectID.cacheHexString) this.__id = hexString;
  return hexString;
};

/**
* Update the ObjectID index used in generating new ObjectID's on the driver
*
* @return {Number} returns next index value.
* @api private
*/
ObjectID.prototype.get_inc = function() {
  return ObjectID.index = (ObjectID.index + 1) % 0xFFFFFF;
};

/**
* Update the ObjectID index used in generating new ObjectID's on the driver
*
* @return {Number} returns next index value.
* @api private
*/
ObjectID.prototype.getInc = function() {
  return this.get_inc();
};

/**
* Generate a 12 byte id string used in ObjectID's
*
* @param {Number} [time] optional parameter allowing to pass in a second based timestamp.
* @return {String} return the 12 byte id binary string.
* @api private
*/
ObjectID.prototype.generate = function(time) {
  if ('number' == typeof time) {
    var time4Bytes = BinaryParser.encodeInt(time, 32, true, true);
    /* for time-based ObjectID the bytes following the time will be zeroed */
    var machine3Bytes = BinaryParser.encodeInt(MACHINE_ID, 24, false);
    var pid2Bytes = BinaryParser.fromShort(typeof process === 'undefined' ? Math.floor(Math.random() * 100000) : process.pid);
    var index3Bytes = BinaryParser.encodeInt(this.get_inc(), 24, false, true);
  } else {
  	var unixTime = parseInt(Date.now()/1000,10);
    var time4Bytes = BinaryParser.encodeInt(unixTime, 32, true, true);
    var machine3Bytes = BinaryParser.encodeInt(MACHINE_ID, 24, false);
    var pid2Bytes = BinaryParser.fromShort(typeof process === 'undefined' ? Math.floor(Math.random() * 100000) : process.pid);
    var index3Bytes = BinaryParser.encodeInt(this.get_inc(), 24, false, true);
  }

  return time4Bytes + machine3Bytes + pid2Bytes + index3Bytes;
};

/**
* Converts the id into a 24 byte hex string for printing
*
* @return {String} return the 24 byte hex string representation.
* @api private
*/
ObjectID.prototype.toString = function() {
  return this.toHexString();
};

/**
* Converts to a string representation of this Id.
*
* @return {String} return the 24 byte hex string representation.
* @api private
*/
ObjectID.prototype.inspect = ObjectID.prototype.toString;

/**
* Converts to its JSON representation.
*
* @return {String} return the 24 byte hex string representation.
* @api private
*/
ObjectID.prototype.toJSON = function() {
  return this.toHexString();
};

/**
* Compares the equality of this ObjectID with `otherID`.
*
* @param {Object} otherID ObjectID instance to compare against.
* @return {Bool} the result of comparing two ObjectID's
* @api public
*/
ObjectID.prototype.equals = function equals (otherID) {
  var id = (otherID instanceof ObjectID || otherID.toHexString)
    ? otherID.id
    : ObjectID.createFromHexString(otherID).id;

  return this.id === id;
}

/**
* Returns the generation date (accurate up to the second) that this ID was generated.
*
* @return {Date} the generation date
* @api public
*/
ObjectID.prototype.getTimestamp = function() {
  var timestamp = new Date();
  timestamp.setTime(Math.floor(BinaryParser.decodeInt(this.id.substring(0,4), 32, true, true)) * 1000);
  return timestamp;
}

/**
* @ignore
* @api private
*/
ObjectID.index = 0;

ObjectID.createPk = function createPk () {
  return new ObjectID();
};

/**
* Creates an ObjectID from a second based number, with the rest of the ObjectID zeroed out. Used for comparisons or sorting the ObjectID.
*
* @param {Number} time an integer number representing a number of seconds.
* @return {ObjectID} return the created ObjectID
* @api public
*/
ObjectID.createFromTime = function createFromTime (time) {
  var id = BinaryParser.encodeInt(time, 32, true, true) +
           BinaryParser.encodeInt(0, 64, true, true);
  return new ObjectID(id);
};

/**
* Creates an ObjectID from a hex string representation of an ObjectID.
*
* @param {String} hexString create a ObjectID from a passed in 24 byte hexstring.
* @return {ObjectID} return the created ObjectID
* @api public
*/
ObjectID.createFromHexString = function createFromHexString (hexString) {
  // Throw an error if it's not a valid setup
  if(typeof hexString === 'undefined' || hexString != null && hexString.length != 24)
    throw new Error("Argument passed in must be a single String of 12 bytes or a string of 24 hex characters");

  var len = hexString.length;

  if(len > 12*2) {
    throw new Error('Id cannot be longer than 12 bytes');
  }

  var result = ''
    , string
    , number;

  for (var index = 0; index < len; index += 2) {
    string = hexString.substr(index, 2);
    number = parseInt(string, 16);
    result += BinaryParser.fromByte(number);
  }

  return new ObjectID(result, hexString);
};

/**
* @ignore
*/
Object.defineProperty(ObjectID.prototype, "generationTime", {
   enumerable: true
 , get: function () {
     return Math.floor(BinaryParser.decodeInt(this.id.substring(0,4), 32, true, true));
   }
 , set: function (value) {
     var value = BinaryParser.encodeInt(value, 32, true, true);
     this.id = value + this.id.substr(4);
     // delete this.__id;
     this.toHexString();
   }
});

/**
 * Expose.
 */
exports.ObjectID = ObjectID;
exports.ObjectId = ObjectID;
