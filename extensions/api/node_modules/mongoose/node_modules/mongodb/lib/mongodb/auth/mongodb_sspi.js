var DbCommand = require('../commands/db_command').DbCommand
  , utils = require('../utils')
  , format = require('util').format;

// Kerberos class
var Kerberos = null;
var MongoAuthProcess = null;
// Try to grab the Kerberos class
try {
  Kerberos = require('kerberos').Kerberos
  // Authentication process for Mongo
  MongoAuthProcess = require('kerberos').processes.MongoAuthProcess
} catch(err) {}

var authenticate = function(db, username, password, authdb, options, callback) {
  var numberOfConnections = 0;
  var errorObject = null;  
  // We don't have the Kerberos library
  if(Kerberos == null) return callback(new Error("Kerberos library is not installed"));

  if(options['connection'] != null) {
    //if a connection was explicitly passed on options, then we have only one...
    numberOfConnections = 1;
  } else {
    // Get the amount of connections in the pool to ensure we have authenticated all comments
    numberOfConnections = db.serverConfig.allRawConnections().length;
    options['onAll'] = true;
  }

  // Set the sspi server name
  var gssapiServiceName = options['gssapiServiceName'] || 'mongodb';

  // Grab all the connections
  var connections = db.serverConfig.allRawConnections();
  var error = null;
  
  // Authenticate all connections
  for(var i = 0; i < numberOfConnections; i++) {
    // Start Auth process for a connection
    SSIPAuthenticate(db, username, password, authdb, gssapiServiceName, connections[i], function(err, result) {
      // Adjust number of connections left to connect
      numberOfConnections = numberOfConnections - 1;
      // If we have an error save it
      if(err) error = err;

      // We are done
      if(numberOfConnections == 0) {
        if(err) return callback(err, false);
        // We authenticated correctly save the credentials
        db.serverConfig.auth.add('GSSAPI', db.databaseName, username, password, authdb, gssapiServiceName);
        // Return valid callback
        return callback(null, true);
      }
    });    
  }
}

var SSIPAuthenticate = function(db, username, password, authdb, service_name, connection, callback) {
  // --------------------------------------------------------------
  // Async Version
  // --------------------------------------------------------------
  var command = {
      saslStart: 1
    , mechanism: 'GSSAPI'
    , payload: ''
    , autoAuthorize: 1
  };

  // Create authenticator
  var mongo_auth_process = new MongoAuthProcess(connection.socketOptions.host, connection.socketOptions.port, service_name);

  // Execute first sasl step
  db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
    if(err) return callback(err);
    doc = doc.documents[0];

    mongo_auth_process.init(username, password, function(err) {
      if(err) return callback(err);

      mongo_auth_process.transition(doc.payload, function(err, payload) {
        if(err) return callback(err);

        // Perform the next step against mongod
        var command = {
            saslContinue: 1
          , conversationId: doc.conversationId
          , payload: payload
        };

        // Execute the command
        db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
          if(err) return callback(err);
          doc = doc.documents[0];

          mongo_auth_process.transition(doc.payload, function(err, payload) {
            if(err) return callback(err);

            // Perform the next step against mongod
            var command = {
                saslContinue: 1
              , conversationId: doc.conversationId
              , payload: payload
            };

            // Execute the command
            db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
              if(err) return callback(err);
              doc = doc.documents[0];
              
              mongo_auth_process.transition(doc.payload, function(err, payload) {
                // Perform the next step against mongod
                var command = {
                    saslContinue: 1
                  , conversationId: doc.conversationId
                  , payload: payload
                };

                // Execute the command
                db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
                  if(err) return callback(err);
                  doc = doc.documents[0];

                  if(doc.done) return callback(null, true);
                  callback(new Error("Authentication failed"), false);
                });        
              });
            });
          });
        });
      });
    });
  });  
}

exports.authenticate = authenticate;