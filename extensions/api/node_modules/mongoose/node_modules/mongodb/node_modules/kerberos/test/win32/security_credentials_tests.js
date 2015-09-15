exports.setUp = function(callback) {
  callback();
}

exports.tearDown = function(callback) {
  callback();
}

exports['Initialize a set of security credentials'] = function(test) {
  var SecurityCredentials = require('../../lib/sspi.js').SecurityCredentials;

  // Aquire some credentials
  try {
    var credentials = SecurityCredentials.aquire('Kerberos', 'dev1@10GEN.ME', 'a');    
  } catch(err) {    
    console.dir(err)
    test.ok(false);
  }



  // console.dir(SecurityCredentials);

  // var SecurityBufferDescriptor = require('../../lib/sspi.js').SecurityBufferDescriptor
  //   SecurityBuffer = require('../../lib/sspi.js').SecurityBuffer;

  // // Create descriptor with single Buffer
  // var securityDescriptor = new SecurityBufferDescriptor(100);
  // try {
  //   // Fail to work due to no valid Security Buffer
  //   securityDescriptor = new SecurityBufferDescriptor(["hello"]);
  //   test.ok(false);
  // } catch(err){}

  // // Should Correctly construct SecurityBuffer
  // var buffer = new SecurityBuffer(SecurityBuffer.DATA, 100);
  // securityDescriptor = new SecurityBufferDescriptor([buffer]);
  // // Should correctly return a buffer
  // var result = securityDescriptor.toBuffer();
  // test.equal(100, result.length);

  // // Should Correctly construct SecurityBuffer
  // var buffer = new SecurityBuffer(SecurityBuffer.DATA, new Buffer("hello world"));
  // securityDescriptor = new SecurityBufferDescriptor([buffer]);
  // var result = securityDescriptor.toBuffer();
  // test.equal("hello world", result.toString());

  // // Test passing in more than one Buffer
  // var buffer = new SecurityBuffer(SecurityBuffer.DATA, new Buffer("hello world"));
  // var buffer2 = new SecurityBuffer(SecurityBuffer.STREAM, new Buffer("adam and eve"));
  // securityDescriptor = new SecurityBufferDescriptor([buffer, buffer2]);
  // var result = securityDescriptor.toBuffer();
  // test.equal("hello worldadam and eve", result.toString());
  test.done();
}