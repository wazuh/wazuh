var mime = require('mime');

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

module.exports = function (req, types) {
  // no request body
  var headers = req.headers
  if (!(parseInt(headers['content-length'], 10)
    || 'transfer-encoding' in headers)) return;

  var ct = headers['content-type']
  // no content-type
  if (!ct) return false

  // paramless
  ct = ct.split(';')[0];

  // no types, return the content type
  if (!types || !types.length) return ct;

  var type;
  for (var i = 0; i < types.length; i++)
    if (mimeMatch(normalize(type = types[i]), ct))
      return ~type.indexOf('*') ? ct : type

  // no matches
  return false;
}

/**
 * Normalize a mime type.
 * If it's a shorthand, expand it to a valid mime type.
 *
 * @param {String} type
 * @api private
 */

function normalize(type) {
  switch (type) {
    case 'urlencoded': return 'application/x-www-form-urlencoded';
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
  if (expected == actual) return true;

  if (!~expected.indexOf('*')) return false;

  actual = actual.split('/');
  expected = expected.split('/');

  if ('*' == expected[0] && expected[1] == actual[1]) return true;
  if ('*' == expected[1] && expected[0] == actual[0]) return true;
}
