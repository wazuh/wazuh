// Load the native SSPI classes
var kerberos = require('../build/Release/kerberos')
  , Kerberos = kerberos.Kerberos
  , SecurityBuffer = require('./win32/wrappers/security_buffer').SecurityBuffer
  , SecurityBufferDescriptor = require('./win32/wrappers/security_buffer_descriptor').SecurityBufferDescriptor
  , SecurityCredentials = require('./win32/wrappers/security_credentials').SecurityCredentials
  , SecurityContext = require('./win32/wrappers/security_context').SecurityContext;
var SSPI = function() {
}

exports.SSPI = SSPI;
exports.SecurityBuffer = SecurityBuffer;
exports.SecurityBufferDescriptor = SecurityBufferDescriptor;
exports.SecurityCredentials = SecurityCredentials;
exports.SecurityContext = SecurityContext;