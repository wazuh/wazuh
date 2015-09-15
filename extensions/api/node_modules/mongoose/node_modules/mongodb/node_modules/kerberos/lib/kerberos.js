var kerberos = require('../build/Release/kerberos')
  , KerberosNative = kerberos.Kerberos;

var Kerberos = function() {
  this._native_kerberos = new KerberosNative(); 
}

Kerberos.prototype.authGSSClientInit = function(uri, flags, callback) {
  return this._native_kerberos.authGSSClientInit(uri, flags, callback);
}

Kerberos.prototype.authGSSClientStep = function(context, challenge, callback) {
  if(typeof challenge == 'function') {
    callback = challenge;
    challenge = '';
  }

  return this._native_kerberos.authGSSClientStep(context, challenge, callback);
}

Kerberos.prototype.authGSSClientUnwrap = function(context, challenge, callback) {
  if(typeof challenge == 'function') {
    callback = challenge;
    challenge = '';
  }

  return this._native_kerberos.authGSSClientUnwrap(context, challenge, callback);
}

Kerberos.prototype.authGSSClientWrap = function(context, challenge, user_name, callback) {
  if(typeof user_name == 'function') {
    callback = user_name;
    user_name = '';
  }

  return this._native_kerberos.authGSSClientWrap(context, challenge, user_name, callback);
}

Kerberos.prototype.authGSSClientClean = function(context, callback) {
  return this._native_kerberos.authGSSClientClean(context, callback);
}

Kerberos.prototype.acquireAlternateCredentials = function(user_name, password, domain) {
  return this._native_kerberos.acquireAlternateCredentials(user_name, password, domain); 
}

Kerberos.prototype.prepareOutboundPackage = function(principal, inputdata) {
  return this._native_kerberos.prepareOutboundPackage(principal, inputdata); 
}

Kerberos.prototype.decryptMessage = function(challenge) {
  return this._native_kerberos.decryptMessage(challenge);
}

Kerberos.prototype.encryptMessage = function(challenge) {
  return this._native_kerberos.encryptMessage(challenge); 
}

Kerberos.prototype.queryContextAttribute = function(attribute) {
  if(typeof attribute != 'number' && attribute != 0x00) throw new Error("Attribute not supported");
  return this._native_kerberos.queryContextAttribute(attribute);
}

// Some useful result codes
Kerberos.AUTH_GSS_CONTINUE     = 0;
Kerberos.AUTH_GSS_COMPLETE     = 1;
     
// Some useful gss flags 
Kerberos.GSS_C_DELEG_FLAG      = 1;
Kerberos.GSS_C_MUTUAL_FLAG     = 2;
Kerberos.GSS_C_REPLAY_FLAG     = 4;
Kerberos.GSS_C_SEQUENCE_FLAG   = 8;
Kerberos.GSS_C_CONF_FLAG       = 16; 
Kerberos.GSS_C_INTEG_FLAG      = 32;
Kerberos.GSS_C_ANON_FLAG       = 64;
Kerberos.GSS_C_PROT_READY_FLAG = 128; 
Kerberos.GSS_C_TRANS_FLAG      = 256;

// Export Kerberos class
exports.Kerberos = Kerberos;

// If we have SSPI (windows)
if(kerberos.SecurityCredentials) {
  // Put all SSPI classes in it's own namespace
  exports.SSIP = {
      SecurityCredentials: require('./win32/wrappers/security_credentials').SecurityCredentials
    , SecurityContext: require('./win32/wrappers/security_context').SecurityContext
    , SecurityBuffer: require('./win32/wrappers/security_buffer').SecurityBuffer
    , SecurityBufferDescriptor: require('./win32/wrappers/security_buffer_descriptor').SecurityBufferDescriptor
  }
}
