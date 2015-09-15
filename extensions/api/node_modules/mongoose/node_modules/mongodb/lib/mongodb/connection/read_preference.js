/**
 * A class representation of the Read Preference.
 *
 * Read Preferences
 *  - **ReadPreference.PRIMARY**, Read from primary only. All operations produce an error (throw an exception where applicable) if primary is unavailable. Cannot be combined with tags (This is the default.).
 *  - **ReadPreference.PRIMARY_PREFERRED**, Read from primary if available, otherwise a secondary.
 *  - **ReadPreference.SECONDARY**, Read from secondary if available, otherwise error.
 *  - **ReadPreference.SECONDARY_PREFERRED**, Read from a secondary if available, otherwise read from the primary.
 *  - **ReadPreference.NEAREST**, All modes read from among the nearest candidates, but unlike other modes, NEAREST will include both the primary and all secondaries in the random selection.
 *
 * @class Represents a Read Preference.
 * @param {String} the read preference type
 * @param {Object} tags
 * @return {ReadPreference}
 */
var ReadPreference = function(mode, tags) {
  if(!(this instanceof ReadPreference))
    return new ReadPreference(mode, tags);
  this._type = 'ReadPreference';
  this.mode = mode;
  this.tags = tags;
}

/**
 * @ignore
 */
ReadPreference.isValid = function(_mode) {
  return (_mode == ReadPreference.PRIMARY || _mode == ReadPreference.PRIMARY_PREFERRED
    || _mode == ReadPreference.SECONDARY || _mode == ReadPreference.SECONDARY_PREFERRED
    || _mode == ReadPreference.NEAREST
    || _mode == true || _mode == false);
}

/**
 * @ignore
 */
ReadPreference.prototype.isValid = function(mode) {
  var _mode = typeof mode == 'string' ? mode : this.mode;
  return ReadPreference.isValid(_mode);
}

/**
 * @ignore
 */
ReadPreference.prototype.toObject = function() {
  var object = {mode:this.mode};

  if(this.tags != null) {
    object['tags'] = this.tags;
  }

  return object;
}

/**
 * @ignore
 */
ReadPreference.PRIMARY = 'primary';
ReadPreference.PRIMARY_PREFERRED = 'primaryPreferred';
ReadPreference.SECONDARY = 'secondary';
ReadPreference.SECONDARY_PREFERRED = 'secondaryPreferred';
ReadPreference.NEAREST = 'nearest'

/**
 * @ignore
 */
exports.ReadPreference  = ReadPreference;