var SecurityCredentialsNative = require('../../../build/Release/kerberos').SecurityCredentials;

// Add simple kebros helper
SecurityCredentialsNative.aquire_kerberos = function(username, password, domain, callback) {
  if(typeof password == 'function') {
    callback = password;
    password = null;
  } else if(typeof domain == 'function') {
    callback = domain;
    domain = null;
  }

  // We are going to use the async version
  if(typeof callback == 'function') {
    return SecurityCredentialsNative.aquire('Kerberos', username, password, domain, callback);
  } else {
    return SecurityCredentialsNative.aquireSync('Kerberos', username, password, domain);
  }
}

// Export the modified class
exports.SecurityCredentials = SecurityCredentialsNative;