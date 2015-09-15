var timers = require('timers');

// Set processor, setImmediate if 0.10 otherwise nextTick
var processor = require('./utils').processor();

/**
 * Module dependecies.
 */
var Stream = require('stream').Stream;

/**
 * CursorStream
 *
 * Returns a stream interface for the **cursor**.
 *
 * Options
 *  - **transform** {Function} function of type function(object) { return transformed }, allows for transformation of data before emitting.
 *
 * Events
 *  - **data** {function(item) {}} the data event triggers when a document is ready.
 *  - **error** {function(err) {}} the error event triggers if an error happens.
 *  - **close** {function() {}} the end event triggers when there is no more documents available.
 *
 * @class Represents a CursorStream.
 * @param {Cursor} cursor a cursor object that the stream wraps.
 * @return {Stream}
 */
function CursorStream(cursor, options) {
  if(!(this instanceof CursorStream)) return new CursorStream(cursor);
  options = options ? options : {};

  Stream.call(this);

  this.readable = true;
  this.paused = false;
  this._cursor = cursor;
  this._destroyed = null;
  this.options = options;

  // give time to hook up events
  var self = this;
  process.nextTick(function() {
    self._init();      
  });
}

/**
 * Inherit from Stream
 * @ignore
 * @api private
 */
CursorStream.prototype.__proto__ = Stream.prototype;

/**
 * Flag stating whether or not this stream is readable.
 */
CursorStream.prototype.readable;

/**
 * Flag stating whether or not this stream is paused.
 */
CursorStream.prototype.paused;

/**
 * Initialize the cursor.
 * @ignore
 * @api private
 */
CursorStream.prototype._init = function () {
  if (this._destroyed) return;
  this._next();
}

/**
 * Pull the next document from the cursor.
 * @ignore
 * @api private
 */
CursorStream.prototype._next = function () {
  if(this.paused || this._destroyed) return;

  var self = this;
  // Get the next object
  processor(function() {
    if(self.paused || self._destroyed) return;

    self._cursor.nextObject(function (err, doc) {
      self._onNextObject(err, doc);
    });    
  });
}

/**
 * Handle each document as its returned from the cursor.
 * @ignore
 * @api private
 */
CursorStream.prototype._onNextObject = function (err, doc) {
  if(err) return this.destroy(err);

  // when doc is null we hit the end of the cursor
  if(!doc && (this._cursor.state == 1 || this._cursor.state == 2)) {
    this.emit('end')
    return this.destroy();
  } else if(doc) {
    var data = typeof this.options.transform == 'function' ? this.options.transform(doc) : doc;
    this.emit('data', data);
    this._next();
  }
}

/**
 * Pauses the stream.
 *
 * @api public
 */
CursorStream.prototype.pause = function () {
  this.paused = true;
}

/**
 * Resumes the stream.
 *
 * @api public
 */
CursorStream.prototype.resume = function () {
  var self = this;

  // Don't do anything if we are not paused
  if(!this.paused) return;
  if(!this._cursor.state == 3) return;

  process.nextTick(function() {
    self.paused = false;
    // Only trigger more fetching if the cursor is open
    self._next();
  })
}

/**
 * Destroys the stream, closing the underlying
 * cursor. No more events will be emitted.
 *
 * @api public
 */
CursorStream.prototype.destroy = function (err) {
  if (this._destroyed) return;
  this._destroyed = true;
  this.readable = false;

  this._cursor.close();

  if(err) {
    this.emit('error', err);
  }

  this.emit('close');
}

// TODO - maybe implement the raw option to pass binary?
//CursorStream.prototype.setEncoding = function () {
//}

module.exports = exports = CursorStream;
