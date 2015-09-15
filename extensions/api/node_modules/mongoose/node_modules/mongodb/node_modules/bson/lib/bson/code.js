/**
 * A class representation of the BSON Code type.
 *
 * @class Represents the BSON Code type.
 * @param {String|Function} code a string or function.
 * @param {Object} [scope] an optional scope for the function.
 * @return {Code}
 */
function Code(code, scope) {
  if(!(this instanceof Code)) return new Code(code, scope);
  
  this._bsontype = 'Code';
  this.code = code;
  this.scope = scope == null ? {} : scope;
};

/**
 * @ignore
 * @api private
 */
Code.prototype.toJSON = function() {
  return {scope:this.scope, code:this.code};
}

exports.Code = Code;