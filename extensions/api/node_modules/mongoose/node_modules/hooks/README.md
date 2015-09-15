hooks
============

Add pre and post middleware hooks to your JavaScript methods.

## Installation
    npm install hooks

## Motivation
Suppose you have a JavaScript object with a `save` method.

It would be nice to be able to declare code that runs before `save` and after `save`.
For example, you might want to run validation code before every `save`,
and you might want to dispatch a job to a background job queue after `save`.

One might have an urge to hard code this all into `save`, but that turns out to
couple all these pieces of functionality (validation, save, and job creation) more
tightly than is necessary. For example, what if someone does not want to do background
job creation after the logical save? 

It is nicer to tack on functionality using what we call `pre` and `post` hooks. These
are functions that you define and that you direct to execute before or after particular
methods.

## Example
We can use `hooks` to add validation and background jobs in the following way:

    var hooks = require('hooks')
      , Document = require('./path/to/some/document/constructor');

    // Add hooks' methods: `hook`, `pre`, and `post`    
    for (var k in hooks) {
      Document[k] = hooks[k];
    }

    // Define a new method that is able to invoke pre and post middleware
    Document.hook('save', Document.prototype.save);

    // Define a middleware function to be invoked before 'save'
    Document.pre('save', function validate (next) {
      // The `this` context inside of `pre` and `post` functions
      // is the Document instance
      if (this.isValid()) next();      // next() passes control to the next middleware
                                       // or to the target method itself
      else next(new Error("Invalid")); // next(error) invokes an error callback
    });

    // Define a middleware function to be invoked after 'save'
    Document.post('save', function createJob () {
      this.sendToBackgroundQueue();
    });

If you already have defined `Document.prototype` methods for which you want pres and posts,
then you do not need to explicitly invoke `Document.hook(...)`. Invoking `Document.pre(methodName, fn)`
or `Document.post(methodName, fn)` will automatically and lazily change `Document.prototype[methodName]`
so that it plays well with `hooks`. An equivalent way to implement the previous example is:

```javascript
var hooks = require('hooks')
  , Document = require('./path/to/some/document/constructor');

// Add hooks' methods: `hook`, `pre`, and `post`    
for (var k in hooks) {
  Document[k] = hooks[k];
}

Document.prototype.save = function () {
  // ...
};

// Define a middleware function to be invoked before 'save'
Document.pre('save', function validate (next) {
  // The `this` context inside of `pre` and `post` functions
  // is the Document instance
  if (this.isValid()) next();      // next() passes control to the next middleware
                                   // or to the target method itself
  else next(new Error("Invalid")); // next(error) invokes an error callback
});

// Define a middleware function to be invoked after 'save'
Document.post('save', function createJob () {
  this.sendToBackgroundQueue();
});
```

## Pres and Posts as Middleware
We structure pres and posts as middleware to give you maximum flexibility:

1. You can define **multiple** pres (or posts) for a single method.
2. These pres (or posts) are then executed as a chain of methods.
3. Any functions in this middleware chain can choose to halt the chain's execution by `next`ing an Error from that middleware function. If this occurs, then none of the other middleware in the chain will execute, and the main method (e.g., `save`) will not execute. This is nice, for example, when we don't want a document to save if it is invalid.

## Defining multiple pres (or posts)
`pre` is chainable, so you can define multiple pres via:
    Document.pre('save', function (next, halt) {
      console.log("hello");
    }).pre('save', function (next, halt) {
      console.log("world");
    });

As soon as one pre finishes executing, the next one will be invoked, and so on.

## Error Handling
You can define a default error handler by passing a 2nd function as the 3rd argument to `hook`:
    Document.hook('set', function (path, val) {
      this[path] = val;
    }, function (err) {
      // Handler the error here
      console.error(err);
    });

Then, we can pass errors to this handler from a pre or post middleware function:
    Document.pre('set', function (next, path, val) {
      next(new Error());
    });

If you do not set up a default handler, then `hooks` makes the default handler that just throws the `Error`.

The default error handler can be over-rided on a per method invocation basis.

If the main method that you are surrounding with pre and post middleware expects its last argument to be a function
with callback signature `function (error, ...)`, then that callback becomes the error handler, over-riding the default
error handler you may have set up.
   
```javascript
Document.hook('save', function (callback) {
  // Save logic goes here
  ...
});

var doc = new Document();
doc.save( function (err, saved) {
  // We can pass err via `next` in any of our pre or post middleware functions
  if (err) console.error(err);
  
  // Rest of callback logic follows ...
});
```

## Mutating Arguments via Middleware
`pre` and `post` middleware can also accept the intended arguments for the method
they augment. This is useful if you want to mutate the arguments before passing
them along to the next middleware and eventually pass a mutated arguments list to
the main method itself.

As a simple example, let's define a method `set` that just sets a key, value pair.
If we want to namespace the key, we can do so by adding a `pre` middleware hook
that runs before `set`, alters the arguments by namespacing the `key` argument, and passes them onto `set`:

    Document.hook('set', function (key, val) {
      this[key] = val;
    });
    Document.pre('set', function (next, key, val) {
      next('namespace-' + key, val);
    });
    var doc = new Document();
    doc.set('hello', 'world');
    console.log(doc.hello); // undefined
    console.log(doc['namespace-hello']); // 'world'

As you can see above, we pass arguments via `next`.

If you are not mutating the arguments, then you can pass zero arguments
to `next`, and the next middleware function will still have access
to the arguments.

    Document.hook('set', function (key, val) {
      this[key] = val;
    });
    Document.pre('set', function (next, key, val) {
      // I have access to key and val here
      next(); // We don't need to pass anything to next
    });
    Document.pre('set', function (next, key, val) {
      // And I still have access to the original key and val here
      next();
    });

Finally, you can add arguments that downstream middleware can also see:

    // Note that in the definition of `set`, there is no 3rd argument, options
    Document.hook('set', function (key, val) {
      // But...
      var options = arguments[2]; // ...I have access to an options argument
                                  // because of pre function pre2 (defined below)
      console.log(options); // '{debug: true}'
      this[key] = val;
    });
    Document.pre('set', function pre1 (next, key, val) {
      // I only have access to key and val arguments
      console.log(arguments.length); // 3
      next(key, val, {debug: true});
    });
    Document.pre('set', function pre2 (next, key, val, options) {
      console.log(arguments.length); // 4
      console.log(options); // '{ debug: true}'
      next();
    });
    Document.pre('set', function pre3 (next, key, val, options) {
      // I still have access to key, val, AND the options argument introduced via the preceding middleware
      console.log(arguments.length); // 4
      console.log(options); // '{ debug: true}'
      next();
    });
    
    var doc = new Document()
    doc.set('hey', 'there');

## Parallel `pre` middleware

All middleware up to this point has been "serial" middleware -- i.e., middleware whose logic
is executed as a serial chain.

Some scenarios call for parallel middleware -- i.e., middleware that can wait for several
asynchronous services at once to respond.

For instance, you may only want to save a Document only after you have checked
that the Document is valid according to two different remote services.

We accomplish asynchronous middleware by adding a second kind of flow control callback
(the only flow control callback so far has been `next`), called `done`.

- `next` passes control to the next middleware in the chain
- `done` keeps track of how many parallel middleware have invoked `done` and passes
   control to the target method when ALL parallel middleware have invoked `done`. If
   you pass an `Error` to `done`, then the error is handled, and the main method that is
   wrapped by pres and posts will not get invoked.

We declare pre middleware that is parallel by passing a 3rd boolean argument to our `pre`
definition method.

We illustrate via the parallel validation example mentioned above:

    Document.hook('save', function targetFn (callback) {
      // Save logic goes here
      // ...
      // This only gets run once the two `done`s are both invoked via preOne and preTwo.
    });

                         // true marks this as parallel middleware
    Document.pre('save', true, function preOne (next, doneOne, callback) {
      remoteServiceOne.validate(this.serialize(), function (err, isValid) {
        // The code in here will probably be run after the `next` below this block
        // and could possibly be run after the console.log("Hola") in `preTwo
        if (err) return doneOne(err);
        if (isValid) doneOne();
      });
      next(); // Pass control to the next middleware
    });
    
    // We will suppose that we need 2 different remote services to validate our document
    Document.pre('save', true, function preTwo (next, doneTwo, callback) {
      remoteServiceTwo.validate(this.serialize(), function (err, isValid) {
        if (err) return doneTwo(err);
        if (isValid) doneTwo();
      });
      next();
    });
    
    // While preOne and preTwo are parallel, preThree is a serial pre middleware
    Document.pre('save', function preThree (next, callback) {
      next();
    });
    
    var doc = new Document();
    doc.save( function (err, doc) {
      // Do stuff with the saved doc here...
    });

In the above example, flow control may happen in the following way:

(1) doc.save -> (2) preOne --(next)--> (3) preTwo --(next)--> (4) preThree --(next)--> (wait for dones to invoke) -> (5) doneTwo -> (6) doneOne -> (7) targetFn

So what's happening is that:

1. You call `doc.save(...)`
2. First, your preOne middleware gets executed. It makes a remote call to the validation service and `next()`s to the preTwo middleware.
3. Now, your preTwo middleware gets executed. It makes a remote call to another validation service and `next()`s to the preThree middleware.
4. Your preThree middleware gets executed. It immediately `next()`s. But nothing else gets executing until both `doneOne` and `doneTwo` are invoked inside the callbacks handling the response from the two valiation services.
5. We will suppose that validation remoteServiceTwo returns a response to us first. In this case, we call `doneTwo` inside the callback to remoteServiceTwo.
6. Some fractions of a second later, remoteServiceOne returns a response to us. In this case, we call `doneOne` inside the callback to remoteServiceOne.
7. `hooks` implementation keeps track of how many parallel middleware has been defined per target function. It detects that both asynchronous pre middlewares (`preOne` and `preTwo`) have finally called their `done` functions (`doneOne` and `doneTwo`), so the implementation finally invokes our `targetFn` (i.e., our core `save` business logic).

## Removing Pres

You can remove a particular pre associated with a hook:

    Document.pre('set', someFn);
    Document.removePre('set', someFn);

And you can also remove all pres associated with a hook:
    Document.removePre('set'); // Removes all declared `pre`s on the hook 'set'

## Tests
To run the tests:
    make test

### Contributors
- [Brian Noguchi](https://github.com/bnoguchi)

### License
MIT License

---
### Author
Brian Noguchi
