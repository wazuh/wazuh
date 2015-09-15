
var gleak = require('gleak')();
gleak.ignore('AssertionError');
gleak.ignore('testFullSpec_param_found');
gleak.ignore('events');
gleak.ignore('Uint8Array');
gleak.ignore('Uint8ClampedArray');
gleak.ignore('TAP_Global_Harness');
gleak.ignore('setImmediate');
gleak.ignore('clearImmediate');

gleak.ignore('DTRACE_NET_SERVER_CONNECTION');
gleak.ignore('DTRACE_NET_STREAM_END');
gleak.ignore('DTRACE_NET_SOCKET_READ');
gleak.ignore('DTRACE_NET_SOCKET_WRITE');
gleak.ignore('DTRACE_HTTP_SERVER_REQUEST');
gleak.ignore('DTRACE_HTTP_SERVER_RESPONSE');
gleak.ignore('DTRACE_HTTP_CLIENT_REQUEST');
gleak.ignore('DTRACE_HTTP_CLIENT_RESPONSE');

module.exports = gleak;
