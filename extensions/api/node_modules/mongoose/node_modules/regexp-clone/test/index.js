
var assert = require('assert')
var clone = require('../');

describe('regexp-clone', function(){
  function hasEqualSource (a, b) {
    assert.ok(a !== b);
    assert.equal(a.source, b.source);
  }

  function isInsensitive (a) {
    assert.ok(a.ignoreCase);
  }

  function isGlobal (a) {
    assert.ok(a.global);
  }

  function isMultiline (a) {
    assert.ok(a.multiline);
  }

  function insensitiveFlag (a) {
    var b = clone(a);
    hasEqualSource(a, b);
    isInsensitive(a);
    isInsensitive(b);
  }

  function globalFlag (a) {
    var b = clone(a);
    hasEqualSource(a, b);
    isGlobal(a);
    isGlobal(b);
  }

  function multilineFlag (a) {
    var b = clone(a);
    hasEqualSource(a, b);
    isMultiline(a);
    isMultiline(b);
  }

  describe('literals', function(){
    it('insensitive flag', function(done){
      var a = /hello/i;
      insensitiveFlag(a);
      done();
    })
    it('global flag', function(done){
      var a = /hello/g;
      globalFlag(a);
      done();
    })
    it('multiline flag', function(done){
      var a = /hello/m;
      multilineFlag(a);
      done();
    })
    it('no flags', function(done){
      var a = /hello/;
      var b = clone(a);
      hasEqualSource(a, b);
      assert.ok(!a.insensitive);
      assert.ok(!a.global);
      assert.ok(!a.global);
      done();
    })
    it('all flags', function(done){
      var a = /hello/gim;
      insensitiveFlag(a);
      globalFlag(a);
      multilineFlag(a);
      done();
    })
  })

  describe('instances', function(){
    it('insensitive flag', function(done){
      var a = new RegExp('hello', 'i');
      insensitiveFlag(a);
      done();
    })
    it('global flag', function(done){
      var a = new RegExp('hello', 'g');
      globalFlag(a);
      done();
    })
    it('multiline flag', function(done){
      var a = new RegExp('hello', 'm');
      multilineFlag(a);
      done();
    })
    it('no flags', function(done){
      var a = new RegExp('hmm');
      var b = clone(a);
      hasEqualSource(a, b);
      assert.ok(!a.insensitive);
      assert.ok(!a.global);
      assert.ok(!a.global);
      done();
    })
    it('all flags', function(done){
      var a = new RegExp('hello', 'gim');
      insensitiveFlag(a);
      globalFlag(a);
      multilineFlag(a);
      done();
    })
  })
})

