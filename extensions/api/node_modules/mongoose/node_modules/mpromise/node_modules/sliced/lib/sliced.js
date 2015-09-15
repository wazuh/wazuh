
/**
 * An Array.prototype.slice.call(arguments) alternative
 *
 * @param {Object} args something with a length
 * @param {Number} slice
 * @param {Number} sliceEnd
 * @api public
 */

module.exports = function () {
  var args = arguments[0];
  var slice = arguments[1];
  var sliceEnd = arguments[2];

  var ret = [];
  var len = args.length;

  if (0 === len) return ret;

  var start = slice < 0
    ? Math.max(0, slice + len)
    : slice || 0;

  var end = 3 === arguments.length
    ? sliceEnd < 0
      ? sliceEnd + len
      : sliceEnd
    : len;

  while (end-- > start) {
    ret[end - start] = args[end];
  }

  return ret;
}

