
var parse = require('url').parse;

/**
 * Parse the `req` url with memoization.
 *
 * @param {ServerRequest} req
 * @return {Object}
 * @api private
 */

module.exports = function parseUrl(req){
  var parsed = req._parsedUrl;
  if (parsed && parsed.href == req.url) {
    return parsed;
  } else {
    parsed = parse(req.url);

    if (parsed.auth && !parsed.protocol && ~parsed.href.indexOf('//')) {
      // This parses pathnames, and a strange pathname like //r@e should work
      parsed = parse(req.url.replace(/@/g, '%40'));
    }

    return req._parsedUrl = parsed;
  }
};
