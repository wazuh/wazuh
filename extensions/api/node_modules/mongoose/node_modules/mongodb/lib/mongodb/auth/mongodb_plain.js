var DbCommand = require('../commands/db_command').DbCommand
  , utils = require('../utils')
  , Binary = require('bson').Binary
  , format = require('util').format;

var authenticate = function(db, username, password, options, callback) {
  var numberOfConnections = 0;
  var errorObject = null;
  
  if(options['connection'] != null) {
    //if a connection was explicitly passed on options, then we have only one...
    numberOfConnections = 1;
  } else {
    // Get the amount of connections in the pool to ensure we have authenticated all comments
    numberOfConnections = db.serverConfig.allRawConnections().length;
    options['onAll'] = true;
  }

  // Create payload
  var payload = new Binary(format("\x00%s\x00%s", username, password));

  // Let's start the sasl process
  var command = {
      saslStart: 1
    , mechanism: 'PLAIN'
    , payload: payload
    , autoAuthorize: 1
  };

  // Grab all the connections
  var connections = options['connection'] != null ? [options['connection']] : db.serverConfig.allRawConnections();

  // Authenticate all connections
  for(var i = 0; i < numberOfConnections; i++) {
    var connection = connections[i];
    // Execute first sasl step
    db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, result) {
      // Count down
      numberOfConnections = numberOfConnections - 1;

      // Ensure we save any error
      if(err) {
        errorObject = err;
      } else if(result.documents[0].err != null || result.documents[0].errmsg != null){
        errorObject = utils.toError(result.documents[0]);
      }

      // Work around the case where the number of connections are 0
      if(numberOfConnections <= 0 && typeof callback == 'function') {
        var internalCallback = callback;
        callback = null;

        if(errorObject == null && result.documents[0].ok == 1) {
          // We authenticated correctly save the credentials
          db.serverConfig.auth.add('PLAIN', db.databaseName, username, password);
          // Return callback
          internalCallback(errorObject, true);
        } else {
          internalCallback(errorObject, false);
        }
      }
    });
  }
}

exports.authenticate = authenticate;