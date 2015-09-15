exports.setIntegerParameter = function(object, field, defaultValue) {
  if(object[field] == null) {
    object[field] = defaultValue;
  } else if(typeof object[field] !== "number" && object[field] !== parseInt(object[field], 10)) {
    throw "object field [" + field + "] must be a numeric integer value, attempted to set to [" + object[field] + "] type of [" + typeof object[field] + "]";
  }
}

exports.setBooleanParameter = function(object, field, defaultValue) {
  if(object[field] == null) {
    object[field] = defaultValue;
  } else if(typeof object[field] !== "boolean") {
    throw "object field [" + field + "] must be a boolean value, attempted to set to [" + object[field] + "] type of [" + typeof object[field] + "]";
  }
}

exports.setStringParameter = function(object, field, defaultValue) {
  if(object[field] == null) {
    object[field] = defaultValue;
  } else if(typeof object[field] !== "string") {
    throw "object field [" + field + "] must be a string value, attempted to set to [" + object[field] + "] type of [" + typeof object[field] + "]";
  }
}