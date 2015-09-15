var SecurityContextNative = require('../../../build/Release/kerberos').SecurityContext;
// Export the modified class
exports.SecurityContext = SecurityContextNative;