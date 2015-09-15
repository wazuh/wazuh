/**
 * Hooks are useful if we want to add a method that automatically has `pre` and `post` hooks.
 * For example, it would be convenient to have `pre` and `post` hooks for `save`.
 * _.extend(Model, mixins.hooks);
 * Model.hook('save', function () {
 *  console.log('saving');
 * });
 * Model.pre('save', function (next, done) {
 *  console.log('about to save');
 *  next();
 * });
 * Model.post('save', function (next, done) {
 *  console.log('saved');
 *  next();
 * });
 *
 * var m = new Model();
 * m.save();
 * // about to save
 * // saving
 * // saved 
 */

// TODO Add in pre and post skipping options
module.exports = {
  /**
   *  Declares a new hook to which you can add pres and posts
   *  @param {String} name of the function
   *  @param {Function} the method
   *  @param {Function} the error handler callback
   */
  hook: function (name, fn, err) {
    if (arguments.length === 1 && typeof name === 'object') {
      for (var k in name) { // `name` is a hash of hookName->hookFn
        this.hook(k, name[k]);
      }
      return;
    }

    if (!err) err = fn;

    var proto = this.prototype || this
      , pres = proto._pres = proto._pres || {}
      , posts = proto._posts = proto._posts || {};
    pres[name] = pres[name] || [];
    posts[name] = posts[name] || [];

    function noop () {}

    proto[name] = function () {
      var self = this
        , pres = this._pres[name]
        , posts = this._posts[name]
        , numAsyncPres = 0
        , hookArgs = [].slice.call(arguments)
        , preChain = pres.map( function (pre, i) {
            var wrapper = function () {
              if (arguments[0] instanceof Error)
                return err(arguments[0]);
              if (numAsyncPres) {
                // arguments[1] === asyncComplete
                if (arguments.length)
                  hookArgs = [].slice.call(arguments, 2);
                pre.apply(self, 
                  [ preChain[i+1] || allPresInvoked, 
                    asyncComplete
                  ].concat(hookArgs)
                );
              } else {
                if (arguments.length)
                  hookArgs = [].slice.call(arguments);
                pre.apply(self,
                  [ preChain[i+1] || allPresDone ].concat(hookArgs));
              }
            }; // end wrapper = function () {...
            if (wrapper.isAsync = pre.isAsync)
              numAsyncPres++;
            return wrapper;
          }); // end posts.map(...)
      function allPresInvoked () {
        if (arguments[0] instanceof Error)
          err(arguments[0]);
      }

      function allPresDone () {
        if (arguments[0] instanceof Error)
          return err(arguments[0]);
        if (arguments.length)
          hookArgs = [].slice.call(arguments);
        fn.apply(self, hookArgs);
        var postChain = posts.map( function (post, i) {
          var wrapper = function () {
            if (arguments[0] instanceof Error)
              return err(arguments[0]);
            if (arguments.length)
              hookArgs = [].slice.call(arguments);
            post.apply(self,
              [ postChain[i+1] || noop].concat(hookArgs));
          }; // end wrapper = function () {...
          return wrapper;
        }); // end posts.map(...)
        if (postChain.length) postChain[0]();
      }

      if (numAsyncPres) {
        complete = numAsyncPres;
        function asyncComplete () {
          if (arguments[0] instanceof Error)
            return err(arguments[0]);
          --complete || allPresDone.call(this);
        }
      }
      (preChain[0] || allPresDone)();
    };

    return this;
  },

  pre: function (name, fn, isAsync) {
    var proto = this.prototype
      , pres = proto._pres = proto._pres || {};
    if (fn.isAsync = isAsync) {
      this.prototype[name].numAsyncPres++;
    }
    (pres[name] = pres[name] || []).push(fn);
    return this;
  },
  post: function (name, fn, isAsync) {
    var proto = this.prototype
      , posts = proto._posts = proto._posts || {};
    (posts[name] = posts[name] || []).push(fn);
    return this;
  }
};
