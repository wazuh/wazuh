exports.setUp = function(callback) {
  callback();
}

exports.tearDown = function(callback) {
  callback();
}

exports['Initialize a security Buffer'] = function(test) {
  var SecurityBuffer = require('../../lib/sspi.js').SecurityBuffer;
  // Create empty buffer
  var securityBuffer = new SecurityBuffer(SecurityBuffer.DATA, 100);
  var buffer = securityBuffer.toBuffer();
  test.equal(100, buffer.length);

  // Access data passed in
  var allocated_buffer = new Buffer(256);
  securityBuffer = new SecurityBuffer(SecurityBuffer.DATA, allocated_buffer);
  buffer = securityBuffer.toBuffer();
  test.deepEqual(allocated_buffer, buffer);
  test.done();
}