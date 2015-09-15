#sliced
==========

A faster alternative to `[].slice.call(arguments)`.

[![Build Status](https://secure.travis-ci.org/aheckmann/sliced.png)](http://travis-ci.org/aheckmann/sliced)

Example output from [benchmark.js](https://github.com/bestiejs/benchmark.js)

    Array.prototype.slice.call x 1,320,205 ops/sec ±2.35% (92 runs sampled)
    [].slice.call x 1,314,605 ops/sec ±1.60% (95 runs sampled)
    cached slice.call x 10,468,380 ops/sec ±1.45% (95 runs sampled)
    sliced x 16,608,237 ops/sec ±1.40% (92 runs sampled)
    fastest is sliced

    Array.prototype.slice.call(arguments, 1) x 1,383,584 ops/sec ±1.73% (97 runs sampled)
    [].slice.call(arguments, 1) x 1,494,735 ops/sec ±1.33% (95 runs sampled)
    cached slice.call(arguments, 1) x 10,085,270 ops/sec ±1.51% (97 runs sampled)
    sliced(arguments, 1) x 16,620,480 ops/sec ±1.29% (95 runs sampled)
    fastest is sliced(arguments, 1)

    Array.prototype.slice.call(arguments, -1) x 1,303,262 ops/sec ±1.62% (94 runs sampled)
    [].slice.call(arguments, -1) x 1,325,615 ops/sec ±1.36% (97 runs sampled)
    cached slice.call(arguments, -1) x 9,673,603 ops/sec ±1.70% (96 runs sampled)
    sliced(arguments, -1) x 16,384,575 ops/sec ±1.06% (91 runs sampled)
    fastest is sliced(arguments, -1)

    Array.prototype.slice.call(arguments, -2, -10) x 1,404,390 ops/sec ±1.61% (95 runs sampled)
    [].slice.call(arguments, -2, -10) x 1,514,367 ops/sec ±1.21% (96 runs sampled)
    cached slice.call(arguments, -2, -10) x 9,836,017 ops/sec ±1.21% (95 runs sampled)
    sliced(arguments, -2, -10) x 18,544,882 ops/sec ±1.30% (91 runs sampled)
    fastest is sliced(arguments, -2, -10)

    Array.prototype.slice.call(arguments, -2, -1) x 1,458,604 ops/sec ±1.41% (97 runs sampled)
    [].slice.call(arguments, -2, -1) x 1,536,547 ops/sec ±1.63% (99 runs sampled)
    cached slice.call(arguments, -2, -1) x 10,060,633 ops/sec ±1.37% (96 runs sampled)
    sliced(arguments, -2, -1) x 18,608,712 ops/sec ±1.08% (93 runs sampled)
    fastest is sliced(arguments, -2, -1)

_Benchmark  [source](https://github.com/aheckmann/sliced/blob/master/bench.js)._

##Usage

`sliced` accepts the same arguments as `Array#slice` so you can easily swap it out.

```js
function zing () {
  var slow = [].slice.call(arguments, 1, 8);
  var args = slice(arguments, 1, 8);

  var slow = Array.prototype.slice.call(arguments);
  var args = slice(arguments);
  // etc
}
```

## install

    npm install sliced


[LICENSE](https://github.com/aheckmann/sliced/blob/master/LICENSE)
