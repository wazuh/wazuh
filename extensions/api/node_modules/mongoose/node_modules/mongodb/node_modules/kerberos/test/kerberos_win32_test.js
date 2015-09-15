exports.setUp = function(callback) {
  callback();
}

exports.tearDown = function(callback) {
  callback();
}

exports['Simple initialize of Kerberos win32 object'] = function(test) {
  var KerberosNative = require('../build/Release/kerberos').Kerberos;
  // console.dir(KerberosNative)
  var kerberos = new KerberosNative();
  console.log("=========================================== 0")
  console.dir(kerberos.acquireAlternateCredentials("dev1@10GEN.ME", "a"));
  console.log("=========================================== 1")
  console.dir(kerberos.prepareOutboundPackage("mongodb/kdc.10gen.com"));
  console.log("=========================================== 2")
  test.done();
}
