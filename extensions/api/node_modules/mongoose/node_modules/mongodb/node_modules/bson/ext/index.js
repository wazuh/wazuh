var bson = null;

// Load the precompiled win32 binary
if(process.platform == "win32" && process.arch == "x64") {
  bson = require('./win32/x64/bson');  
} else if(process.platform == "win32" && process.arch == "ia32") {
  bson = require('./win32/ia32/bson');  
} else {
  bson = require('../build/Release/bson');  
}

exports.BSON = bson.BSON;
exports.Long = require('../lib/bson/long').Long;
exports.ObjectID = require('../lib/bson/objectid').ObjectID;
exports.DBRef = require('../lib/bson/db_ref').DBRef;
exports.Code = require('../lib/bson/code').Code;
exports.Timestamp = require('../lib/bson/timestamp').Timestamp;
exports.Binary = require('../lib/bson/binary').Binary;
exports.Double = require('../lib/bson/double').Double;
exports.MaxKey = require('../lib/bson/max_key').MaxKey;
exports.MinKey = require('../lib/bson/min_key').MinKey;
exports.Symbol = require('../lib/bson/symbol').Symbol;

// Just add constants tot he Native BSON parser
exports.BSON.BSON_BINARY_SUBTYPE_DEFAULT = 0;
exports.BSON.BSON_BINARY_SUBTYPE_FUNCTION = 1;
exports.BSON.BSON_BINARY_SUBTYPE_BYTE_ARRAY = 2;
exports.BSON.BSON_BINARY_SUBTYPE_UUID = 3;
exports.BSON.BSON_BINARY_SUBTYPE_MD5 = 4;
exports.BSON.BSON_BINARY_SUBTYPE_USER_DEFINED = 128;
