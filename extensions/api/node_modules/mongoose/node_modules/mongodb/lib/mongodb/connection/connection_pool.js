var utils = require('./connection_utils'),
  inherits = require('util').inherits,
  net = require('net'),
  timers = require('timers'),
  EventEmitter = require('events').EventEmitter,
  inherits = require('util').inherits,
  MongoReply = require("../responses/mongo_reply").MongoReply,
  Connection = require("./connection").Connection;

// Set processor, setImmediate if 0.10 otherwise nextTick
var processor = require('../utils').processor();

var ConnectionPool = exports.ConnectionPool = function(host, port, poolSize, bson, socketOptions) {
  if(typeof host !== 'string') {
    throw new Error("host must be specified [" + host + "]");
  }

  // Set up event emitter
  EventEmitter.call(this);

  // Keep all options for the socket in a specific collection allowing the user to specify the
  // Wished upon socket connection parameters
  this.socketOptions = typeof socketOptions === 'object' ? socketOptions : {};
  this.socketOptions.host = host;
  this.socketOptions.port = port;
  this.socketOptions.domainSocket = false;
  this.bson = bson;
  // PoolSize is always + 1 for special reserved "measurment" socket (like ping, stats etc)
  this.poolSize = poolSize;
  this.minPoolSize = Math.floor(this.poolSize / 2) + 1;

  // Check if the host is a socket
  if(host.match(/^\//)) {
    this.socketOptions.domainSocket = true;
  } else if(typeof port === 'string') {
    try { 
      port = parseInt(port, 10); 
    } catch(err) { 
      new Error("port must be specified or valid integer["  + port + "]"); 
    }
  } else if(typeof port !== 'number') {
    throw new Error("port must be specified ["  + port + "]");
  }

  // Set default settings for the socket options
  utils.setIntegerParameter(this.socketOptions, 'timeout', 0);
  // Delay before writing out the data to the server
  utils.setBooleanParameter(this.socketOptions, 'noDelay', true);
  // Delay before writing out the data to the server
  utils.setIntegerParameter(this.socketOptions, 'keepAlive', 0);
  // Set the encoding of the data read, default is binary == null
  utils.setStringParameter(this.socketOptions, 'encoding', null);
  // Allows you to set a throttling bufferSize if you need to stop overflows
  utils.setIntegerParameter(this.socketOptions, 'bufferSize', 0);

  // Internal structures
  this.openConnections = [];
  // Assign connection id's
  this.connectionId = 0;

  // Current index for selection of pool connection
  this.currentConnectionIndex = 0;
  // The pool state
  this._poolState = 'disconnected';
  // timeout control
  this._timeout = false;
  // Time to wait between connections for the pool
  this._timeToWait = 10;
}

inherits(ConnectionPool, EventEmitter);

ConnectionPool.prototype.setMaxBsonSize = function(maxBsonSize) {
  if(maxBsonSize == null){
    maxBsonSize = Connection.DEFAULT_MAX_BSON_SIZE;
  }

  for(var i = 0; i < this.openConnections.length; i++) {
    this.openConnections[i].maxBsonSize = maxBsonSize;
    this.openConnections[i].maxBsonSettings.maxBsonSize = maxBsonSize;
  }
}

ConnectionPool.prototype.setMaxMessageSizeBytes = function(maxMessageSizeBytes) {
  if(maxMessageSizeBytes == null){
    maxMessageSizeBytes = Connection.DEFAULT_MAX_MESSAGE_SIZE;
  }

  for(var i = 0; i < this.openConnections.length; i++) {
    this.openConnections[i].maxMessageSizeBytes = maxMessageSizeBytes;
    this.openConnections[i].maxBsonSettings.maxMessageSizeBytes = maxMessageSizeBytes;
  }
}

// Start a function
var _connect = function(_self) {
  // return new function() {
    // Create a new connection instance
    var connection = new Connection(_self.connectionId++, _self.socketOptions);
    // Set logger on pool
    connection.logger = _self.logger;
    // Connect handler
    connection.on("connect", function(err, connection) {
      // Add connection to list of open connections
      _self.openConnections.push(connection);
      // If the number of open connections is equal to the poolSize signal ready pool
      if(_self.openConnections.length === _self.poolSize && _self._poolState !== 'disconnected') {
        // Set connected
        _self._poolState = 'connected';
        // Emit pool ready
        _self.emit("poolReady");
      } else if(_self.openConnections.length < _self.poolSize) {
        // Wait a little bit of time to let the close event happen if the server closes the connection
        // so we don't leave hanging connections around
        if(typeof _self._timeToWait == 'number') {
          setTimeout(function() {
            // If we are still connecting (no close events fired in between start another connection)
            if(_self._poolState == 'connecting') {
              _connect(_self);
            }
          }, _self._timeToWait);
        } else {
          processor(function() {
            // If we are still connecting (no close events fired in between start another connection)
            if(_self._poolState == 'connecting') {
              _connect(_self);
            }
          });
        }
      }
    });

    var numberOfErrors = 0

    // Error handler
    connection.on("error", function(err, connection, error_options) {
      numberOfErrors++;
      // If we are already disconnected ignore the event
      if(_self._poolState != 'disconnected' && _self.listeners("error").length > 0) {
        _self.emit("error", err, connection, error_options);
      }

      // Close the connection
      connection.close();
      // Set pool as disconnected
      _self._poolState = 'disconnected';
      // Stop the pool
      _self.stop();
    });

    // Close handler
    connection.on("close", function() {
      // If we are already disconnected ignore the event
      if(_self._poolState !== 'disconnected' && _self.listeners("close").length > 0) {
        _self.emit("close");
      }

      // Set disconnected
      _self._poolState = 'disconnected';
      // Stop
      _self.stop();
    });

    // Timeout handler
    connection.on("timeout", function(err, connection) {
      // If we are already disconnected ignore the event
      if(_self._poolState !== 'disconnected' && _self.listeners("timeout").length > 0) {
        _self.emit("timeout", err);
      }

      // Close the connection
      connection.close();
      // Set disconnected
      _self._poolState = 'disconnected';
      _self.stop();
    });

    // Parse error, needs a complete shutdown of the pool
    connection.on("parseError", function() {
      // If we are already disconnected ignore the event
      if(_self._poolState !== 'disconnected' && _self.listeners("parseError").length > 0) {
        _self.emit("parseError", new Error("parseError occured"));
      }

      // Set disconnected
      _self._poolState = 'disconnected';
      _self.stop();
    });

    connection.on("message", function(message) {
      _self.emit("message", message);
    });

    // Start connection in the next tick
    connection.start();
  // }();
}


// Start method, will throw error if no listeners are available
// Pass in an instance of the listener that contains the api for
// finding callbacks for a given message etc.
ConnectionPool.prototype.start = function() {
  var markerDate = new Date().getTime();
  var self = this;

  if(this.listeners("poolReady").length == 0) {
    throw "pool must have at least one listener ready that responds to the [poolReady] event";
  }

  // Set pool state to connecting
  this._poolState = 'connecting';
  this._timeout = false;

  _connect(self);
}

// Restart a connection pool (on a close the pool might be in a wrong state)
ConnectionPool.prototype.restart = function() {
  // Close all connections
  this.stop(false);
  // Now restart the pool
  this.start();
}

// Stop the connections in the pool
ConnectionPool.prototype.stop = function(removeListeners) {
  removeListeners = removeListeners == null ? true : removeListeners;
  // Set disconnected
  this._poolState = 'disconnected';

  // Clear all listeners if specified
  if(removeListeners) {
    this.removeAllEventListeners();
  }

  // Close all connections
  for(var i = 0; i < this.openConnections.length; i++) {
    this.openConnections[i].close();
  }

  // Clean up
  this.openConnections = [];
}

// Check the status of the connection
ConnectionPool.prototype.isConnected = function() {
  // return this._poolState === 'connected';
  return this.openConnections.length > 0 && this.openConnections[0].isConnected();
}

// Checkout a connection from the pool for usage, or grab a specific pool instance
ConnectionPool.prototype.checkoutConnection = function(id) {
  var index = (this.currentConnectionIndex++ % (this.openConnections.length));
  var connection = this.openConnections[index];
  return connection;
}

ConnectionPool.prototype.getAllConnections = function() {
  return this.openConnections;
}

// Remove all non-needed event listeners
ConnectionPool.prototype.removeAllEventListeners = function() {
  this.removeAllListeners("close");
  this.removeAllListeners("error");
  this.removeAllListeners("timeout");
  this.removeAllListeners("connect");
  this.removeAllListeners("end");
  this.removeAllListeners("parseError");
  this.removeAllListeners("message");
  this.removeAllListeners("poolReady");
}






















