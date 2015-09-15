
var mime = require('mime');

var slice = [].slice;

module.exports = typeofrequest;
typeofrequest.is = typeis;
typeofrequest.hasBody = hasbody;
typeofrequest.normalize = normalize;
typeofrequest.match = mimeMatch;

/**
 * Compare a `value` content-type with `types`.
 * Each `type` can be an extension like `html`,
 * a special shortcut like `multipart` or `urlencoded`,
 * or a mime type.
 *
 * If no types match, `false` is returned.
 * Otherwise, the first `type` that matches is returned.
 *
 * @param {String} value
 * @param {Array} types
 * @return String
 */

function typeis(value, types) {
  if (!value) return false;
  if (types && !Array.isArray(types)) types = slice.call(arguments, 1);

  // remove stuff like charsets
  var index = value.indexOf(';')
  value = ~index ? value.slice(0, index) : value

  // no types, return the content type
  if (!types || !types.length) return value;

  var type;
  for (var i = 0; i < types.length; i++)
    if (mimeMatch(normalize(type = types[i]), value))
      return ~type.indexOf('*') ? value : type;

  // no matches
  return false;
}

/**
 * Check if a request has a request body.
 * A request with a body __must__ either have `transfer-encoding`
 * or `content-length` headers set.
 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3
 *
 * @param {Object} request
 * @return {Boolean}
 * @api public
 */

function hasbody(req) {
  var headers = req.headers;
  if ('transfer-encoding' in headers) return true;
  var length = headers['content-length'];
  if (!length) return false;
  // no idea when this would happen, but `isNaN(null) === false`
  if (isNaN(length)) return false;
  return !!parseInt(length, 10);
}

/**
 * Check if the incoming request contains the "Content-Type"
 * header field, and it contains any of the give mime `type`s.
 * If there is no request body, `null` is returned.
 * If there is no content type, `false` is returned.
 * Otherwise, it returns the first `type` that matches.
 *
 * Examples:
 *
 *     // With Content-Type: text/html; charset=utf-8
 *     this.is('html'); // => 'html'
 *     this.is('text/html'); // => 'text/html'
 *     this.is('text/*', 'application/json'); // => 'text/html'
 *
 *     // When Content-Type is application/json
 *     this.is('json', 'urlencoded'); // => 'json'
 *     this.is('application/json'); // => 'application/json'
 *     this.is('html', 'application/*'); // => 'application/json'
 *
 *     this.is('html'); // => false
 *
 * @param {String|Array} types...
 * @return {String|false|null}
 * @api public
 */

function typeofrequest(req, types) {
  if (!hasbody(req)) return null;
  if (types && !Array.isArray(types)) types = slice.call(arguments, 1);
  return typeis(req.headers['content-type'], types);
}

/**
 * Normalize a mime type.
 * If it's a shorthand, expand it to a valid mime type.
 *
 * In general, you probably want:
 *
 *   var type = is(req, ['urlencoded', 'json', 'multipart']);
 *
 * Then use the appropriate body parsers.
 * These three are the most common request body types
 * and are thus ensured to work.
 *
 * @param {String} type
 * @api private
 */

function normalize(type) {
  switch (type) {
    case 'urlencoded': return 'application/x-www-form-urlencoded';
    case 'multipart':
      type = 'multipart/*';
      break;
  }

  return ~type.indexOf('/') ? type : mime.lookup(type);
}

/**
 * Check if `exected` mime type
 * matches `actual` mime type with
 * wildcard support.
 *
 * @param {String} expected
 * @param {String} actual
 * @return {Boolean}
 * @api private
 */

function mimeMatch(expected, actual) {
  if (expected === actual) return true;

  if (!~expected.indexOf('*')) return false;

  actual = actual.split('/');
  expected = expected.split('/');

  if ('*' === expected[0] && expected[1] === actual[1]) return true;
  if ('*' === expected[1] && expected[0] === actual[0]) return true;
  return false;
}
