
/*!
 * Module dependencies.
 */

var SchemaType = require('../schematype')
  , CastError = SchemaType.CastError
  , errorMessages = require('../error').messages
  , utils = require('../utils')
  , Document

/**
 * EmbeddedDocument SchemaType constructor.
 *
 * @param {String} key
 * @param {Object} options
 * @inherits SchemaType
 * @api private
 */

function SchemaEmbedded (key, options, EmbeddedDoc, parentArray) {
  SchemaType.call(this, key, options, 'EmbeddedDocument');
  this.EmbeddedDoc = EmbeddedDoc;
  this.parentArray = parentArray;
};

/*!
 * Inherits from SchemaType.
 */

SchemaEmbedded.prototype.__proto__ = SchemaType.prototype;

SchemaEmbedded.prototype.cast = function (value, doc, init) {
  return new this.EmbeddedDoc(value, this.parentArray);
}

/*!
 * Module exports.
 */

module.exports = SchemaEmbedded;
