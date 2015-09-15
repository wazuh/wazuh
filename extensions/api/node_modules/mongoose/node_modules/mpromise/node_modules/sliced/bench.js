
var sliced = require('./')
var Bench = require('benchmark');
var s = new Bench.Suite;
var slice = [].slice;

s.add('Array.prototype.slice.call', function () {
  Array.prototype.slice.call(arguments);
}).add('[].slice.call', function () {
  [].slice.call(arguments);
}).add('cached slice.call', function () {
  slice.call(arguments)
}).add('sliced', function () {
  sliced(arguments)
}).on('cycle', function (evt) {
  console.log(String(evt.target));
}).on('complete', function () {
  console.log('fastest is %s', this.filter('fastest').pluck('name'));
})
.run();

var s = new Bench.Suite;
s.add('Array.prototype.slice.call(arguments, 1)', function () {
  Array.prototype.slice.call(arguments, 1);
}).add('[].slice.call(arguments, 1)', function () {
  [].slice.call(arguments, 1);
}).add('cached slice.call(arguments, 1)', function () {
  slice.call(arguments, 1)
}).add('sliced(arguments, 1)', function () {
  sliced(arguments, 1)
}).on('cycle', function (evt) {
  console.log(String(evt.target));
}).on('complete', function () {
  console.log('fastest is %s', this.filter('fastest').pluck('name'));
})
.run();

var s = new Bench.Suite;
s.add('Array.prototype.slice.call(arguments, -1)', function () {
  Array.prototype.slice.call(arguments, -1);
}).add('[].slice.call(arguments, -1)', function () {
  [].slice.call(arguments, -1);
}).add('cached slice.call(arguments, -1)', function () {
  slice.call(arguments, -1)
}).add('sliced(arguments, -1)', function () {
  sliced(arguments, -1)
}).on('cycle', function (evt) {
  console.log(String(evt.target));
}).on('complete', function () {
  console.log('fastest is %s', this.filter('fastest').pluck('name'));
})
.run();

var s = new Bench.Suite;
s.add('Array.prototype.slice.call(arguments, -2, -10)', function () {
  Array.prototype.slice.call(arguments, -2, -10);
}).add('[].slice.call(arguments, -2, -10)', function () {
  [].slice.call(arguments, -2, -10);
}).add('cached slice.call(arguments, -2, -10)', function () {
  slice.call(arguments, -2, -10)
}).add('sliced(arguments, -2, -10)', function () {
  sliced(arguments, -2, -10)
}).on('cycle', function (evt) {
  console.log(String(evt.target));
}).on('complete', function () {
  console.log('fastest is %s', this.filter('fastest').pluck('name'));
})
.run();

var s = new Bench.Suite;
s.add('Array.prototype.slice.call(arguments, -2, -1)', function () {
  Array.prototype.slice.call(arguments, -2, -1);
}).add('[].slice.call(arguments, -2, -1)', function () {
  [].slice.call(arguments, -2, -1);
}).add('cached slice.call(arguments, -2, -1)', function () {
  slice.call(arguments, -2, -1)
}).add('sliced(arguments, -2, -1)', function () {
  sliced(arguments, -2, -1)
}).on('cycle', function (evt) {
  console.log(String(evt.target));
}).on('complete', function () {
  console.log('fastest is %s', this.filter('fastest').pluck('name'));
})
.run();

/**
 * Output:
 *
 * Array.prototype.slice.call x 1,289,592 ops/sec ±2.88% (87 runs sampled)
 * [].slice.call x 1,345,451 ops/sec ±1.68% (97 runs sampled)
 * cached slice.call x 10,719,886 ops/sec ±1.04% (99 runs sampled)
 * sliced x 15,809,545 ops/sec ±1.46% (93 runs sampled)
 * fastest is sliced
 *
 */
