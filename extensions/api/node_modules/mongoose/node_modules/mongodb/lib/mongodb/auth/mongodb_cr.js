var DbCommand = require('../commands/db_command').DbCommand
  , utils = require('../utils');

var authenticate = function(db, username, password, authdb, options, callback) {
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

  // Execute all four
  db._executeQueryCommand(DbCommand.createGetNonceCommand(db), options, function(err, result, connection) {
    // Execute on all the connections
    if(err == null) {
      // Nonce used to make authentication request with md5 hash
      var nonce = result.documents[0].nonce;
      // Execute command
      db._executeQueryCommand(DbCommand.createAuthenticationCommand(db, username, password, nonce, authdb), {connection:connection}, function(err, result) {
        // Count down
        numberOfConnections = numberOfConnections - 1;
        // Ensure we save any error
        if(err) {
          errorObject = err;
        } else if(result 
          && Array.isArray(result.documents) 
          && result.documents.length > 0 
          && (result.documents[0].err != null || result.documents[0].errmsg != null)) {
            errorObject = utils.toError(result.documents[0]);
        }

        // Work around the case where the number of connections are 0
        if(numberOfConnections <= 0 && typeof callback == 'function') {
          var internalCallback = callback;
          callback = null;

          if(errorObject == null
              && result && Array.isArray(result.documents) && result.documents.length > 0
              && result.documents[0].ok == 1) {            // We authenticated correctly save the credentials
            db.serverConfig.auth.add('MONGODB-CR', db.databaseName, username, password, authdb);
            // Return callback
            internalCallback(errorObject, true);
          } else {
            internalCallback(errorObject, false);
          }
        }
      });
    }
  });  
}

exports.authenticate = authenticate;