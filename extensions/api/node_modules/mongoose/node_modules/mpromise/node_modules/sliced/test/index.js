
var sliced = require('../')
var assert = require('assert')

describe('sliced', function(){
  it('exports a function', function(){
    assert.equal('function', typeof sliced);
  })
  describe('with 1 arg', function(){
    it('returns an array of the arg', function(){
      var o = [3, "4", {}];
      var r = sliced(o);
      assert.equal(3, r.length);
      assert.equal(o[0], r[0]);
      assert.equal(o[1], r[1]);
      assert.equal(o[1], r[1]);
    })
  })
  describe('with 2 args', function(){
    it('returns an array of the arg starting at the 2nd arg', function(){
      var o = [3, "4", 5, null];
      var r = sliced(o, 2);
      assert.equal(2, r.length);
      assert.equal(o[2], r[0]);
      assert.equal(o[3], r[1]);
    })
  })
  describe('with 3 args', function(){
    it('returns an array of the arg from the 2nd to the 3rd arg', function(){
      var o = [3, "4", 5, null];
      var r = sliced(o, 1, 2);
      assert.equal(1, r.length);
      assert.equal(o[1], r[0]);
    })
  })
  describe('with negative start and no end', function(){
    it('begins at an offset from the end and includes all following elements', function(){
      var o = [3, "4", 5, null];
      var r = sliced(o, -2);
      assert.equal(2, r.length);
      assert.equal(o[2], r[0]);
      assert.equal(o[3], r[1]);

      var r = sliced(o, -12);
      assert.equal(4, r.length);
      assert.equal(o[0], r[0]);
      assert.equal(o[1], r[1]);
    })
  })
  describe('with negative start and positive end', function(){
    it('begins at an offset from the end and includes `end` elements', function(){
      var o = [3, "4", {x:1}, null];

      var r = sliced(o, -2, 1);
      assert.equal(0, r.length);

      var r = sliced(o, -2, 2);
      assert.equal(0, r.length);

      var r = sliced(o, -2, 3);
      assert.equal(1, r.length);
      assert.equal(o[2], r[0]);
    })
  })
  describe('with negative start and negative end', function(){
    it('begins at `start` offset from the end and includes all elements up to `end` offset from the end', function(){
      var o = [3, "4", {x:1}, null];
      var r = sliced(o, -3, -1);
      assert.equal(2, r.length);
      assert.equal(o[1], r[0]);
      assert.equal(o[2], r[1]);

      var r = sliced(o, -3, -3);
      assert.equal(0, r.length);

      var r = sliced(o, -3, -4);
      assert.equal(0, r.length);
    })
  })
})
