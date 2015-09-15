try {
  exports.BSONPure = require('./bson');
  exports.BSONNative = require('../../ext');
} catch(err) {
  // do nothing
}

[ './binary_parser'
  , './binary'
  , './code'
  , './db_ref'
  , './double'
  , './max_key'
  , './min_key'
  , './objectid'
  , './symbol'
  , './timestamp'
  , './long'].forEach(function (path) {
  	var module = require('./' + path);
  	for (var i in module) {
  		exports[i] = module[i];
    }
});

// Exports all the classes for the NATIVE JS BSON Parser
exports.native = function() {
  var classes = {};
  // Map all the classes
  [ './binary_parser'
    , './binary'
    , './code'
    , './db_ref'
    , './double'
    , './max_key'
    , './min_key'
    , './objectid'
    , './symbol'
    , './timestamp'
    , './long'
    , '../../ext'
].forEach(function (path) {
    	var module = require('./' + path);
    	for (var i in module) {
    		classes[i] = module[i];
      }
  });
  // Return classes list
  return classes;
}

// Exports all the classes for the PURE JS BSON Parser
exports.pure = function() {
  var classes = {};
  // Map all the classes
  [ './binary_parser'
    , './binary'
    , './code'
    , './db_ref'
    , './double'
    , './max_key'
    , './min_key'
    , './objectid'
    , './symbol'
    , './timestamp'
    , './long'
    , '././bson'].forEach(function (path) {
    	var module = require('./' + path);
    	for (var i in module) {
    		classes[i] = module[i];
      }
  });
  // Return classes list
  return classes;
}
