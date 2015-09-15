var SecurityBufferNative = require('../../../build/Release/kerberos').SecurityBuffer;

// Add some attributes
SecurityBufferNative.VERSION  = 0;
SecurityBufferNative.EMPTY    = 0;
SecurityBufferNative.DATA     = 1;
SecurityBufferNative.TOKEN    = 2;
SecurityBufferNative.PADDING  = 9;
SecurityBufferNative.STREAM   = 10;

// Export the modified class
exports.SecurityBuffer = SecurityBufferNative;