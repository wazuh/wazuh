var Negotiator = require('negotiator')
var mime = require('mime')

var slice = [].slice

module.exports = Accepts

function Accepts(req) {
  if (!(this instanceof Accepts))
    return new Accepts(req)

  this.headers = req.headers
  this.negotiator = Negotiator(req)
}

/**
 * Check if the given `type(s)` is acceptable, returning
 * the best match when true, otherwise `undefined`, in which
 * case you should respond with 406 "Not Acceptable".
 *
 * The `type` value may be a single mime type string
 * such as "application/json", the extension name
 * such as "json" or an array `["json", "html", "text/plain"]`. When a list
 * or array is given the _best_ match, if any is returned.
 *
 * Examples:
 *
 *     // Accept: text/html
 *     this.accepts('html');
 *     // => "html"
 *
 *     // Accept: text/*, application/json
 *     this.accepts('html');
 *     // => "html"
 *     this.accepts('text/html');
 *     // => "text/html"
 *     this.accepts('json', 'text');
 *     // => "json"
 *     this.accepts('application/json');
 *     // => "application/json"
 *
 *     // Accept: text/*, application/json
 *     this.accepts('image/png');
 *     this.accepts('png');
 *     // => undefined
 *
 *     // Accept: text/*;q=.5, application/json
 *     this.accepts(['html', 'json']);
 *     this.accepts('html', 'json');
 *     // => "json"
 *
 * @param {String|Array} type(s)...
 * @return {String|Array|Boolean}
 * @api public
 */

Accepts.prototype.type =
Accepts.prototype.types = function (types) {
  if (!Array.isArray(types)) types = slice.call(arguments);
  var n = this.negotiator;
  if (!types.length) return n.preferredMediaTypes();
  if (!this.headers.accept) return types[0];
  var mimes = types.map(extToMime);
  var accepts = n.preferredMediaTypes(mimes);
  var first = accepts[0];
  if (!first) return false;
  return types[mimes.indexOf(first)];
}

/**
 * Return accepted encodings or best fit based on `encodings`.
 *
 * Given `Accept-Encoding: gzip, deflate`
 * an array sorted by quality is returned:
 *
 *     ['gzip', 'deflate']
 *
 * @param {String|Array} encoding(s)...
 * @return {String|Array}
 * @api public
 */

Accepts.prototype.encoding =
Accepts.prototype.encodings = function (encodings) {
  if (!Array.isArray(encodings)) encodings = slice.call(arguments);
  var n = this.negotiator;
  if (!encodings.length) return n.preferredEncodings();
  return n.preferredEncodings(encodings)[0] || 'identity';
}

/**
 * Return accepted charsets or best fit based on `charsets`.
 *
 * Given `Accept-Charset: utf-8, iso-8859-1;q=0.2, utf-7;q=0.5`
 * an array sorted by quality is returned:
 *
 *     ['utf-8', 'utf-7', 'iso-8859-1']
 *
 * @param {String|Array} charset(s)...
 * @return {String|Array}
 * @api public
 */

Accepts.prototype.charset =
Accepts.prototype.charsets = function (charsets) {
  if (!Array.isArray(charsets)) charsets = [].slice.call(arguments);
  var n = this.negotiator;
  if (!charsets.length) return n.preferredCharsets();
  if (!this.headers['accept-charset']) return charsets[0];
  return n.preferredCharsets(charsets)[0] || false;
}

/**
 * Return accepted languages or best fit based on `langs`.
 *
 * Given `Accept-Language: en;q=0.8, es, pt`
 * an array sorted by quality is returned:
 *
 *     ['es', 'pt', 'en']
 *
 * @param {String|Array} lang(s)...
 * @return {Array|String}
 * @api public
 */

Accepts.prototype.lang =
Accepts.prototype.langs =
Accepts.prototype.language =
Accepts.prototype.languages = function (langs) {
  if (!Array.isArray(langs)) langs = slice.call(arguments);
  var n = this.negotiator;
  if (!langs.length) return n.preferredLanguages();
  if (!this.headers['accept-language']) return langs[0];
  return n.preferredLanguages(langs)[0] || false;
}

/**
 * Convert extnames to mime.
 *
 * @param {String} type
 * @return {String}
 * @api private
 */

function extToMime(type) {
  if (~type.indexOf('/')) return type;
  return mime.lookup(type);
}
