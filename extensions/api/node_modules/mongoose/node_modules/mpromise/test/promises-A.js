
/**
 * Module dependencies.
 */

var assert = require('assert')
var Promise = require('../lib/promise');
var aplus = require('promises-aplus-tests');

// tests

var adapter = {};
adapter.fulfilled = function (value) {
  var p = new Promise;
  p.fulfill(value);
  return p;
};
adapter.rejected = function (reason) {
  var p = new Promise;
  p.reject(reason);
  return p;
}
adapter.pending = function () {
  var p = new Promise;
  return {
      promise: p
    , fulfill: p.fulfill.bind(p)
    , reject: p.reject.bind(p)
  }
}

aplus(adapter, function (err) {
  assert.ifError(err);
});

