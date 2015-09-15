#mpromise
==========

A [promises/A+](https://github.com/promises-aplus/promises-spec) conformant implementation, written for [mongoose](http://mongoosejs.com).

## installation

```
$ npm install mpromise
```

## docs

An `mpromise` can be in any of three states, pending, fulfilled (success), or rejected (error). Once it is either fulfilled or rejected it's state can no longer be changed.

The exports object is the Promise constructor.

```js
var Promise = require('mpromise');
```

The constructor accepts an optional function which is executed when the promise is first resolved (either fulfilled or rejected).

```js
var promise = new Promise(fn);
```

This is the same as passing the `fn` to `onResolve` directly.

```js
var promise = new Promise;
promise.onResolve(function (err, args..) {
  ...
});
```

### Methods

####fulfill

Fulfilling a promise with values:

```js
var promise = new Promise;
promise.fulfill(args...);
```

If the promise has already been fulfilled or rejected, no action is taken.

####reject

Rejecting a promise with a reason:

```js
var promise = new Promise;
promise.reject(reason);
```

If the promise has already been fulfilled or rejected, no action is taken.

####resolve

Node.js callback style promise resolution `(err, args...)`:

```js
var promise = new Promise;
promise.resolve([reason], [arg1, arg2, ...]);
```

If the promise has already been fulfilled or rejected, no action is taken.

####onFulfill

To register a function for execution when the promise is fulfilled, pass it to `onFulfill`. When executed it will receive the arguments passed to `fulfill()`.

```js
var promise = new Promise;
promise.onFulfill(function (a, b) {
  assert.equal(3, a + b);
});
promise.fulfill(1, 2);
```

The function will only be called once when the promise is fulfilled, never when rejected.

Registering a function with `onFulfill` after the promise has already been fulfilled results in the immediate execution of the function with the original arguments used to fulfill the promise.

```js
var promise = new Promise;
promise.fulfill(" :D ");
promise.onFulfill(function (arg) {
  console.log(arg); // logs " :D "
})
```

####onReject

To register a function for execution when the promise is rejected, pass it to `onReject`. When executed it will receive the argument passed to `reject()`.

```js
var promise = new Promise;
promise.onReject(function (reason) {
  assert.equal('sad', reason);
});
promise.reject('sad');
```

The function will only be called once when the promise is rejected, never when fulfilled.

Registering a function with `onReject` after the promise has already been rejected results in the immediate execution of the function with the original argument used to reject the promise.

```js
var promise = new Promise;
promise.reject(" :( ");
promise.onReject(function (reason) {
  console.log(reason); // logs " :( "
})
```

####onResolve

Allows registration of node.js style callbacks `(err, args..)` to handle either promise resolution type (fulfill or reject).

```js
// fulfillment
var promise = new Promise;
promise.onResolve(function (err, a, b) {
  console.log(a + b); // logs 3
});
promise.fulfill(1, 2);

// rejection
var promise = new Promise;
promise.onResolve(function (err) {
  if (err) {
    console.log(err.message); // logs "failed"
  }
});
promise.reject(new Error('failed'));
```

####then

Creates a new promise and returns it. If `onFulfill` or `onReject` are passed, they are added as SUCCESS/ERROR callbacks to this promise after the nextTick.

Conforms to [promises/A+](https://github.com/promises-aplus/promises-spec) specification and passes its [tests](https://github.com/promises-aplus/promises-tests).

```js
// promise.then(onFulfill, onReject);

var p = new Promise;

p.then(function (arg) {
  return arg + 1;
}).then(function (arg) {
  throw new Error(arg + ' is an error!');
}).then(null, function (err) {
  assert.ok(err instanceof Error);
  assert.equal('2 is an error', err.message);
});
p.complete(1);
```

####end

Signifies that this promise was the last in a chain of `then()s`: if a handler passed to the call to `then` which produced this promise throws, the exception will go uncaught.

```js
var p = new Promise;
p.then(function(){ throw new Error('shucks') });
setTimeout(function () {
  p.fulfill();
  // error was caught and swallowed by the promise returned from
  // p.then(). we either have to always register handlers on
  // the returned promises or we can do the following...
}, 10);

// this time we use .end() which prevents catching thrown errors
var p = new Promise;
var p2 = p.then(function(){ throw new Error('shucks') }).end(); // <--
setTimeout(function () {
  p.fulfill(); // throws "shucks"
}, 10);
```

###Event names

If you'd like to alter this implementations event names used to signify success and failure you may do so by setting `Promise.SUCCESS` or `Promise.FAILURE` respectively.

```js
Promise.SUCCESS = 'complete';
Promise.FAILURE = 'err';
```

###Luke, use the Source
For more ideas read the [source](https://github.com/aheckmann/mpromise/blob/master/lib), [tests](https://github.com/aheckmann/mpromise/blob/master/test), or the [mongoose implementation](https://github.com/LearnBoost/mongoose/blob/3.6x/lib/promise.js).

## license

[MIT](https://github.com/aheckmann/mpromise/blob/master/LICENSE)
