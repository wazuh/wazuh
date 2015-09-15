var EventEmitter = require('events').EventEmitter
  , inherits = require('util').inherits
  , mongodb_cr_authenticate = require('../auth/mongodb_cr.js').authenticate
  , mongodb_gssapi_authenticate = require('../auth/mongodb_gssapi.js').authenticate
  , mongodb_sspi_authenticate = require('../auth/mongodb_sspi.js').authenticate;  

var id = 0;

/**
 * Internal class for callback storage
 * @ignore
 */
var CallbackStore = function() {
  // Make class an event emitter
  EventEmitter.call(this);
  // Add a info about call variable
  this._notReplied = {};
  this.id = id++;
}

/**
 * @ignore
 */
inherits(CallbackStore, EventEmitter);

CallbackStore.prototype.notRepliedToIds = function() {
  return Object.keys(this._notReplied);
}

CallbackStore.prototype.callbackInfo = function(id) {
  return this._notReplied[id]; 
}

/**
 * Internal class for holding non-executed commands
 * @ignore
 */
var NonExecutedOperationStore = function(config) {  
  this.config = config;
  this.commands = {
      read: []
    , write_reads: []
    , write: []
  };
}

NonExecutedOperationStore.prototype.write = function(op) {
  this.commands.write.push(op);
}

NonExecutedOperationStore.prototype.read_from_writer = function(op) {  
  this.commands.write_reads.push(op);
}

NonExecutedOperationStore.prototype.read = function(op) {  
  this.commands.read.push(op);
}

NonExecutedOperationStore.prototype.execute_queries = function(executeInsertCommand) {
  var connection = this.config.checkoutReader();
  if(connection == null || connection instanceof Error) return;

  // Write out all the queries
  while(this.commands.read.length > 0) {
    // Get the next command
    var command = this.commands.read.shift();
    command.options.connection = connection;
    // Execute the next command
    command.executeQueryCommand(command.db, command.db_command, command.options, command.callback);
  }
}

NonExecutedOperationStore.prototype.execute_writes = function() {
  var connection = this.config.checkoutWriter();
  if(connection == null || connection instanceof Error) return;

  // Write out all the queries to the primary
  while(this.commands.write_reads.length > 0) {
    // Get the next command
    var command = this.commands.write_reads.shift();
    command.options.connection = connection;
    // Execute the next command
    command.executeQueryCommand(command.db, command.db_command, command.options, command.callback);
  }

  // Execute all write operations
  while(this.commands.write.length > 0) {
    // Get the next command
    var command = this.commands.write.shift();
    // Set the connection
    command.options.connection = connection;
    // Execute the next command
    command.executeInsertCommand(command.db, command.db_command, command.options, command.callback);
  }  
}

/**
 * Internal class for authentication storage
 * @ignore
 */
var AuthStore = function() {
  this._auths = [];
}

AuthStore.prototype.add = function(authMechanism, dbName, username, password, authdbName, gssapiServiceName) {
  // Check for duplicates
  if(!this.contains(dbName)) {
    // Base config
    var config = {
        'username':username
      , 'password':password
      , 'db': dbName
      , 'authMechanism': authMechanism
      , 'gssapiServiceName': gssapiServiceName
    };

    // Add auth source if passed in
    if(typeof authdbName == 'string') {
      config['authdb'] = authdbName;
    }

    // Push the config
    this._auths.push(config);
  }
}

AuthStore.prototype.contains = function(dbName) {
  for(var i = 0; i < this._auths.length; i++) {
    if(this._auths[i].db == dbName) return true;
  }

  return false;
}

AuthStore.prototype.remove = function(dbName) {
  var newAuths = [];

  // Filter out all the login details
  for(var i = 0; i < this._auths.length; i++) {
    if(this._auths[i].db != dbName) newAuths.push(this._auths[i]);
  }

  //  Set the filtered list
  this._auths = newAuths;
}

AuthStore.prototype.get = function(index) {
  return this._auths[index];
}

AuthStore.prototype.length = function() {
  return this._auths.length;
}

AuthStore.prototype.toArray = function() {
  return this._auths.slice(0);
}

/**
 * Internal class for storing db references
 * @ignore
 */
var DbStore = function() {
  this._dbs = [];
}

DbStore.prototype.add = function(db) {
  var found = false;
  
  // Only add if it does not exist already
  for(var i = 0; i < this._dbs.length; i++) {
    if(db.databaseName == this._dbs[i].databaseName) found = true;
  }

  // Only add if it does not already exist
  if(!found) {
    this._dbs.push(db);    
  } 
}

DbStore.prototype.reset = function() {
  this._dbs = [];
}

DbStore.prototype.fetch = function(databaseName) {
  // Only add if it does not exist already
  for(var i = 0; i < this._dbs.length; i++) {
    if(databaseName == this._dbs[i].databaseName)
      return this._dbs[i];
  }  

  return null;
}

DbStore.prototype.emit = function(event, message, object, reset, filterDb, rethrow_if_no_listeners) {
  var emitted = false;

  // Emit the events
  for(var i = 0; i < this._dbs.length; i++) {
    if(this._dbs[i].listeners(event).length > 0) {
      if(filterDb == null || filterDb.databaseName !== this._dbs[i].databaseName 
        || filterDb.tag !== this._dbs[i].tag) {
        this._dbs[i].emit(event, message, object == null ? this._dbs[i] : object);
        emitted = true;
      }
    }
  }

  // Emit error message
  if(message 
    && event == 'error' 
    && !emitted
    && rethrow_if_no_listeners 
    && object && object.db) {
      process.nextTick(function() {
        object.db.emit(event, message, null);      
      })
  }

  // Not emitted and we have enabled rethrow, let process.uncaughtException
  // deal with the issue
  if(!emitted && rethrow_if_no_listeners) {
    throw message;
  }
}

var Base = function Base() {  
  EventEmitter.call(this);

  // Callback store is part of connection specification
  if(Base._callBackStore == null) {
    Base._callBackStore = new CallbackStore();
  }

  // Create a new callback store  
  this._callBackStore = new CallbackStore();
  // All commands not being executed
  this._commandsStore = new NonExecutedOperationStore(this);
  // Create a new auth store
  this.auth = new AuthStore();
  // Contains all the dbs attached to this server config
  this._dbStore = new DbStore();
}

/**
 * @ignore
 */
inherits(Base, EventEmitter);

/**
 * @ignore
 */
Base.prototype._apply_auths = function(db, callback) {
  _apply_auths_serially(this, db, this.auth.toArray(), callback);
}

var _apply_auths_serially = function(self, db, auths, callback) {
  if(auths.length == 0) return callback(null, null);
  // Get the first auth
  var auth = auths.shift();
  var connections = self.allRawConnections();
  var connectionsLeft = connections.length;
  var options = {};

  if(auth.authMechanism == 'GSSAPI') {
    // We have the kerberos library, execute auth process
    if(process.platform == 'win32') {
      mongodb_sspi_authenticate(db, auth.username, auth.password, auth.authdb, options, callback);
    } else {
      mongodb_gssapi_authenticate(db, auth.username, auth.password, auth.authdb, options, callback);
    }
  } else if(auth.authMechanism == 'MONGODB-CR') {
    mongodb_cr_authenticate(db, auth.username, auth.password, auth.authdb, options, callback);
  }
}

/**
 * Fire all the errors
 * @ignore
 */
Base.prototype.__executeAllCallbacksWithError = function(err) {
  // Check all callbacks
  var keys = Object.keys(this._callBackStore._notReplied);
  // For each key check if it's a callback that needs to be returned
  for(var j = 0; j < keys.length; j++) {
    var info = this._callBackStore._notReplied[keys[j]];
    // Execute callback with error
    this._callBackStore.emit(keys[j], err, null);
    // Remove the key
    delete this._callBackStore._notReplied[keys[j]];
    // Force cleanup _events, node.js seems to set it as a null value
    if(this._callBackStore._events) {
      delete this._callBackStore._events[keys[j]];
    }
  }
}

/**
 * Fire all the errors
 * @ignore
 */
Base.prototype.__executeAllServerSpecificErrorCallbacks = function(host, port, err) {  
  // Check all callbacks
  var keys = Object.keys(this._callBackStore._notReplied);
  // For each key check if it's a callback that needs to be returned
  for(var j = 0; j < keys.length; j++) {
    var info = this._callBackStore._notReplied[keys[j]];

    if(info.connection) {
      // Unpack the connection settings
      var _host = info.connection.socketOptions.host;
      var _port = info.connection.socketOptions.port;
      // If the server matches execute the callback with the error
      if(_port == port && _host == host) {
        this._callBackStore.emit(keys[j], err, null);
        // Remove the key
        delete this._callBackStore._notReplied[keys[j]];
        // Force cleanup _events, node.js seems to set it as a null value
        if(this._callBackStore._events) {
          delete this._callBackStore._events[keys[j]];
        } 
      }      
    }
  }
}

/**
 * Register a handler
 * @ignore
 * @api private
 */
Base.prototype._registerHandler = function(db_command, raw, connection, exhaust, callback) {
  // Check if we have exhausted
  if(typeof exhaust == 'function') {
    callback = exhaust;
    exhaust = false;
  }

  // Add the callback to the list of handlers
  this._callBackStore.once(db_command.getRequestId(), callback);
  // Add the information about the reply
  this._callBackStore._notReplied[db_command.getRequestId().toString()] = {start: new Date().getTime(), 'raw': raw, connection:connection, exhaust:exhaust};
}

/**
 * Re-Register a handler, on the cursor id f.ex
 * @ignore
 * @api private
 */
Base.prototype._reRegisterHandler = function(newId, object, callback) {
  // Add the callback to the list of handlers
  this._callBackStore.once(newId, object.callback.listener);
  // Add the information about the reply
  this._callBackStore._notReplied[newId] = object.info;
}

/**
 *
 * @ignore
 * @api private
 */
Base.prototype._callHandler = function(id, document, err) {
  var self = this;

  // If there is a callback peform it
  if(this._callBackStore.listeners(id).length >= 1) {
    // Get info object
    var info = this._callBackStore._notReplied[id];
    // Delete the current object
    delete this._callBackStore._notReplied[id]; 
    // Call the handle directly don't emit
    var callback = this._callBackStore.listeners(id)[0].listener;
    // Remove the listeners
    this._callBackStore.removeAllListeners(id);
    // Force key deletion because it nulling it not deleting in 0.10.X
    if(this._callBackStore._events) {
      delete this._callBackStore._events[id];
    }

    try {
      // Execute the callback if one was provided
      if(typeof callback == 'function') callback(err, document, info.connection);
    } catch(err) {
      self._emitAcrossAllDbInstances(self, null, "error", err, self, true, true);
    }
  }
}

/**
 *
 * @ignore
 * @api private
 */
Base.prototype._hasHandler = function(id) {
  return this._callBackStore.listeners(id).length >= 1;
}

/**
 *
 * @ignore
 * @api private
 */
Base.prototype._removeHandler = function(id) {
  // Remove the information
  if(this._callBackStore._notReplied[id] != null) delete this._callBackStore._notReplied[id];
  // Remove the callback if it's registered
  this._callBackStore.removeAllListeners(id);
  // Force cleanup _events, node.js seems to set it as a null value
  if(this._callBackStore._events) {
    delete this._callBackStore._events[id];
  }
}

/**
 *
 * @ignore
 * @api private
 */
Base.prototype._findHandler = function(id) {
  var info = this._callBackStore._notReplied[id];
  // Return the callback
  return {info:info, callback:(this._callBackStore.listeners(id).length >= 1) ? this._callBackStore.listeners(id)[0] : null}
}

/**
 *
 * @ignore
 * @api private
 */
Base.prototype._emitAcrossAllDbInstances = function(server, filterDb, event, message, object, resetConnection, rethrow_if_no_listeners) {
  if(resetConnection) {
    for(var i = 0; i < this._dbStore._dbs.length; i++) {
      if(typeof this._dbStore._dbs[i].openCalled != 'undefined')
        this._dbStore._dbs[i].openCalled = false;
    }
  }
  
  // Fire event
  this._dbStore.emit(event, message, object, resetConnection, filterDb, rethrow_if_no_listeners);
}

exports.Base = Base;