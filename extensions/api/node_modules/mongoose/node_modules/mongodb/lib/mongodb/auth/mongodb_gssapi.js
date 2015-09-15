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

  // Grab all the connections
  var connections = options['connection'] != null ? [options['connection']] : db.serverConfig.allRawConnections();
  var gssapiServiceName = options['gssapiServiceName'] || 'mongodb';
  var error = null;
  // Authenticate all connections
  for(var i = 0; i < numberOfConnections; i++) {

    // Start Auth process for a connection
    GSSAPIInitialize(db, username, password, authdb, gssapiServiceName, connections[i], function(err, result) {
      // Adjust number of connections left to connect
      numberOfConnections = numberOfConnections - 1;
      // If we have an error save it
      if(err) error = err;

      // We are done
      if(numberOfConnections == 0) {
        if(err) return callback(error, false);
        // We authenticated correctly save the credentials
        db.serverConfig.auth.add('GSSAPI', db.databaseName, username, password, authdb, gssapiServiceName);
        // Return valid callback
        return callback(null, true);
      }
    });    
  }
}

//
// Initialize step
var GSSAPIInitialize = function(db, username, password, authdb, gssapiServiceName, connection, callback) {
  // Create authenticator
  var mongo_auth_process = new MongoAuthProcess(connection.socketOptions.host, connection.socketOptions.port, gssapiServiceName);

  // Perform initialization
  mongo_auth_process.init(username, password, function(err, context) {
    if(err) return callback(err, false);

    // Perform the first step
    mongo_auth_process.transition('', function(err, payload) {
      if(err) return callback(err, false);

      // Call the next db step
      MongoDBGSSAPIFirstStep(mongo_auth_process, payload, db, username, password, authdb, connection, callback);
    });
  });
}

//
// Perform first step against mongodb
var MongoDBGSSAPIFirstStep = function(mongo_auth_process, payload, db, username, password, authdb, connection, callback) {
  // Build the sasl start command
  var command = {
      saslStart: 1
    , mechanism: 'GSSAPI'
    , payload: payload
    , autoAuthorize: 1
  };

  // Execute first sasl step
  db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
    if(err) return callback(err, false);
    // Get the payload
    doc = doc.documents[0];
    var db_payload = doc.payload;

    mongo_auth_process.transition(doc.payload, function(err, payload) {
      if(err) return callback(err, false);

      // MongoDB API Second Step
      MongoDBGSSAPISecondStep(mongo_auth_process, payload, doc, db, username, password, authdb, connection, callback);
    });
  });
}

//
// Perform first step against mongodb
var MongoDBGSSAPISecondStep = function(mongo_auth_process, payload, doc, db, username, password, authdb, connection, callback) {
  // Build Authentication command to send to MongoDB
  var command = {
      saslContinue: 1
    , conversationId: doc.conversationId
    , payload: payload
  };

  // Execute the command
  db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
    if(err) return callback(err, false);

    // Get the result document
    doc = doc.documents[0];

    // Call next transition for kerberos
    mongo_auth_process.transition(doc.payload, function(err, payload) {
      if(err) return callback(err, false);

      // Call the last and third step
      MongoDBGSSAPIThirdStep(mongo_auth_process, payload, doc, db, username, password, authdb, connection, callback);
    });    
  });
}

var MongoDBGSSAPIThirdStep = function(mongo_auth_process, payload, doc, db, username, password, authdb, connection, callback) {
  // Build final command
  var command = {
      saslContinue: 1
    , conversationId: doc.conversationId
    , payload: payload
  };

  // Let's finish the auth process against mongodb
  db._executeQueryCommand(DbCommand.createDbCommand(db, command, {}, '$external'), {connection:connection}, function(err, doc) {
    if(err) return callback(err, false);

    mongo_auth_process.transition(null, function(err, payload) {
      if(err) return callback(err, false);
      callback(null, true);
    });
  });
}

exports.authenticate = authenticate;