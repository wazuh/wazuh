/**
 * A class representation of the BSON Double type.
 *
 * @class Represents the BSON Double type.
 * @param {Number} value the number we want to represent as a double.
 * @return {Double}
 */
function Double(value) {
  if(!(this instanceof Double)) return new Double(value);
  
  this._bsontype = 'Double';
  this.value = value;
}

/**
 * Access the number value.
 *
 * @return {Number} returns the wrapped double number.
 * @api public
 */
Double.prototype.valueOf = function() {
  return this.value;
};

/**
 * @ignore
 * @api private
 */
Double.prototype.toJSON = function() {
  return this.value;
}

exports.Double = Double;