var ReadPreference = require('./read_preference').ReadPreference
  , Base = require('./base').Base
  , Server = require('./server').Server
  , format = require('util').format
  , timers = require('timers')
  , inherits = require('util').inherits;

// Set processor, setImmediate if 0.10 otherwise nextTick
var processor = require('../utils').processor();

/**
 * Mongos constructor provides a connection to a mongos proxy including failover to additional servers
 *
 * Options
 *  - **socketOptions** {Object, default:null}, an object containing socket options to use (noDelay:(boolean), keepAlive:(number), connectTimeoutMS:(number), socketTimeoutMS:(number))
 *  - **ha** {Boolean, default:true}, turn on high availability, attempts to reconnect to down proxies
 *  - **haInterval** {Number, default:2000}, time between each replicaset status check.
 *
 * @class Represents a Mongos connection with failover to backup proxies
 * @param {Array} list of mongos server objects
 * @param {Object} [options] additional options for the mongos connection
 */
var Mongos = function Mongos(servers, options) {
  // Set up basic
  if(!(this instanceof Mongos))
    return new Mongos(servers, options);

  // Set up event emitter
  Base.call(this);

  // Throw error on wrong setup
  if(servers == null || !Array.isArray(servers) || servers.length == 0)
    throw new Error("At least one mongos proxy must be in the array");

  // Ensure we have at least an empty options object
  this.options = options == null ? {} : options;
  // Set default connection pool options
  this.socketOptions = this.options.socketOptions != null ? this.options.socketOptions : {};
  // Enabled ha
  this.haEnabled = this.options['ha'] == null ? true : this.options['ha'];
  this._haInProgress = false;
  // How often are we checking for new servers in the replicaset
  this.mongosStatusCheckInterval = this.options['haInterval'] == null ? 1000 : this.options['haInterval'];
  // Save all the server connections
  this.servers = servers;
  // Servers we need to attempt reconnect with
  this.downServers = {};
  // Servers that are up
  this.upServers = {};
  // Up servers by ping time
  this.upServersByUpTime = {};
  // Emit open setup
  this.emitOpen = this.options.emitOpen || true;
  // Just contains the current lowest ping time and server
  this.lowestPingTimeServer = null;
  this.lowestPingTime = 0;
  // Connection timeout
  this._connectTimeoutMS = this.socketOptions.connectTimeoutMS
    ? this.socketOptions.connectTimeoutMS
    : 1000;

  // Add options to servers
  for(var i = 0; i < this.servers.length; i++) {
    var server = this.servers[i];
    server._callBackStore = this._callBackStore;
    server.auto_reconnect = false;
    // Default empty socket options object
    var socketOptions = {host: server.host, port: server.port};
    // If a socket option object exists clone it
    if(this.socketOptions != null) {
      var keys = Object.keys(this.socketOptions);
      for(var k = 0; k < keys.length;k++) socketOptions[keys[i]] = this.socketOptions[keys[i]];
    }

    // Set socket options
    server.socketOptions = socketOptions;
  }
}

/**
 * @ignore
 */
inherits(Mongos, Base);

/**
 * @ignore
 */
Mongos.prototype.isMongos = function() {
  return true;
}

/**
 * @ignore
 */
Mongos.prototype.connect = function(db, options, callback) {
  if('function' === typeof options) callback = options, options = {};
  if(options == null) options = {};
  if(!('function' === typeof callback)) callback = null;
  var self = this;

  // Keep reference to parent
  this.db = db;
  // Set server state to connecting
  this._serverState = 'connecting';
  // Number of total servers that need to initialized (known servers)
  this._numberOfServersLeftToInitialize = this.servers.length;  
  // Connect handler
  var connectHandler = function(_server) {
    return function(err, result) {
      self._numberOfServersLeftToInitialize = self._numberOfServersLeftToInitialize - 1;

      // Add the server to the list of servers that are up
      if(!err) {
        self.upServers[format("%s:%s", _server.host, _server.port)] = _server;
      }

      // We are done connecting
      if(self._numberOfServersLeftToInitialize == 0) {
        // Start ha function if it exists
        if(self.haEnabled) {
          // Setup the ha process
          if(self._replicasetTimeoutId != null) clearInterval(self._replicasetTimeoutId);
          self._replicasetTimeoutId = setInterval(self.mongosCheckFunction, self.mongosStatusCheckInterval);
        }

        // Set the mongos to connected
        self._serverState = "connected";

        // Emit the open event
        if(self.emitOpen)
          self._emitAcrossAllDbInstances(self, null, "open", null, null, null);        

        self._emitAcrossAllDbInstances(self, null, "fullsetup", null, null, null);      
        // Callback
        callback(null, self.db);
      }
    }
  };

  // Error handler
  var errorOrCloseHandler = function(_server) {
    return function(err, result) {
      // Execute all the callbacks with errors
      self.__executeAllCallbacksWithError(err);
      // Check if we have the server
      var found = false;
      
      // Get the server name
      var server_name = format("%s:%s", _server.host, _server.port);
      // Add the downed server
      self.downServers[server_name] = _server;
      // Remove the current server from the list
      delete self.upServers[server_name]; 

      // Emit close across all the attached db instances
      if(Object.keys(self.upServers).length == 0) {
        self._emitAcrossAllDbInstances(self, null, "close", new Error("mongos disconnected, no valid proxies contactable over tcp"), null, null);
      }
    }
  }

  // Mongo function
  this.mongosCheckFunction = function() {
    // Set as not waiting for check event 
    self._haInProgress = true;
    
    // Servers down
    var numberOfServersLeft = Object.keys(self.downServers).length;
    
    // Check downed servers
    if(numberOfServersLeft > 0) {
      for(var name in self.downServers) {
        // Pop a downed server      
        var downServer = self.downServers[name];
        // Set up the connection options for a Mongos
        var options = {
          auto_reconnect: false,
          returnIsMasterResults: true,
          slaveOk: true,
          poolSize: downServer.poolSize,
          socketOptions: { 
            connectTimeoutMS: self._connectTimeoutMS,
            socketTimeoutMS: self._socketTimeoutMS
          }          
        }

        // Create a new server object
        var newServer = new Server(downServer.host, downServer.port, options);
        // Setup the connection function
        var connectFunction = function(_db, _server, _options, _callback)  {
          return function() {
            // Attempt to connect
            _server.connect(_db, _options, function(err, result) {
              numberOfServersLeft = numberOfServersLeft - 1;

              if(err) {
                return _callback(err, _server);
              } else {                
                // Set the new server settings
                _server._callBackStore = self._callBackStore;

                // Add server event handlers
                _server.on("close", errorOrCloseHandler(_server));
                _server.on("timeout", errorOrCloseHandler(_server));
                _server.on("error", errorOrCloseHandler(_server));
                
                // Get a read connection
                var _connection = _server.checkoutReader();
                // Get the start time
                var startTime = new Date().getTime();
                
                // Execute ping command to mark each server with the expected times
                self.db.command({ping:1}
                  , {failFast:true, connection:_connection}, function(err, result) {
                  // Get the start time
                  var endTime = new Date().getTime();
                  // Mark the server with the ping time
                  _server.runtimeStats['pingMs'] = endTime - startTime;
                  // Execute any waiting reads
                  self._commandsStore.execute_writes();   
                  self._commandsStore.execute_queries();   
                  // Callback
                  return _callback(null, _server);
                });
              }
            });
          }
        } 

        // Attempt to connect to the database
        connectFunction(self.db, newServer, options, function(err, _server) {
          // If we have an error
          if(err) {
            self.downServers[format("%s:%s", _server.host, _server.port)] = _server;
          }

          // Connection function
          var connectionFunction = function(_auth, _connection, _callback) {
            var pending = _auth.length();

            for(var j = 0; j < pending; j++) {
              // Get the auth object
              var _auth = _auth.get(j);
              // Unpack the parameter
              var username = _auth.username;
              var password = _auth.password;
              var options = { 
                  authMechanism: _auth.authMechanism
                , authSource: _auth.authdb
                , connection: _connection 
              };

              // If we have changed the service name
              if(_auth.gssapiServiceName) 
                options.gssapiServiceName = _auth.gssapiServiceName;

              // Hold any error
              var _error = null;
              // Authenticate against the credentials
              self.db.authenticate(username, password, options, function(err, result) {
                _error = err != null ? err : _error;
                // Adjust the pending authentication
                pending = pending - 1;
                // Finished up
                if(pending == 0) _callback(_error ? _error : null, _error ? false : true);
              });
            }
          }

          // Run auths against the connections
          if(self.auth.length() > 0) {
            var connections = _server.allRawConnections();
            var pendingAuthConn = connections.length;

            // No connections we are done
            if(connections.length == 0) {
              // Set ha done
              if(numberOfServersLeft == 0) {
                self._haInProgress = false;
              }              
            }

            // Final error object
            var finalError = null;
            // Go over all the connections
            for(var j = 0; j < connections.length; j++) {
              
              // Execute against all the connections
              connectionFunction(self.auth, connections[j], function(err, result) {
                // Pending authentication
                pendingAuthConn = pendingAuthConn - 1 ;

                // Save error if any
                finalError = err ? err : finalError;

                // If we are done let's finish up
                if(pendingAuthConn == 0) {
                  // Set ha done
                  if(numberOfServersLeft == 0) {
                    self._haInProgress = false;
                  }

                  if(!err) {
                    add_server(self, _server);
                  }

                  // Execute any waiting reads
                  self._commandsStore.execute_writes();   
                  self._commandsStore.execute_queries();                  
                }
              });
            }
          } else {
            if(!err) {
              add_server(self, _server);
            }

            // Set ha done
            if(numberOfServersLeft == 0) {
              self._haInProgress = false;
              // Execute any waiting reads
              self._commandsStore.execute_writes();   
              self._commandsStore.execute_queries();   
            }
          }
        })();
      }
    } else {
      self._haInProgress = false;
    }
  }

  // Connect all the server instances
  for(var i = 0; i < this.servers.length; i++) {
    // Get the connection
    var server = this.servers[i];
    server.mongosInstance = this;
    // Add server event handlers
    server.on("close", errorOrCloseHandler(server));
    server.on("timeout", errorOrCloseHandler(server));
    server.on("error", errorOrCloseHandler(server));
    
    // Configuration
    var options = {
      slaveOk: true,
      poolSize: server.poolSize,
      socketOptions: { connectTimeoutMS: self._connectTimeoutMS },
      returnIsMasterResults: true
    }        

    // Connect the instance
    server.connect(self.db, options, connectHandler(server));
  }
}

/**
 * @ignore
 * Add a server to the list of up servers and sort them by ping time
 */
var add_server = function(self, _server) {
  var server_key = format("%s:%s", _server.host, _server.port);
  // Push to list of valid server
  self.upServers[server_key] = _server;
  // Remove the server from the list of downed servers
  delete self.downServers[server_key];              

  // Sort the keys by ping time
  var keys = Object.keys(self.upServers);
  var _upServersSorted = {};
  var _upServers = []
  
  // Get all the servers
  for(var name in self.upServers) {
    _upServers.push(self.upServers[name]);
  }

  // Sort all the server
  _upServers.sort(function(a, b) {
    return a.runtimeStats['pingMs'] > b.runtimeStats['pingMs'];
  });

  // Rebuild the upServer
  for(var i = 0; i < _upServers.length; i++) {
    _upServersSorted[format("%s:%s", _upServers[i].host, _upServers[i].port)] = _upServers[i];
  }

  // Set the up servers
  self.upServers = _upServersSorted;
}

/**
 * @ignore
 * Just return the currently picked active connection
 */
Mongos.prototype.allServerInstances = function() {
  return this.servers;
}

/**
 * Always ourselves
 * @ignore
 */
Mongos.prototype.setReadPreference = function() {}

/**
 * @ignore
 */
Mongos.prototype.allRawConnections = function() {
  // Neeed to build a complete list of all raw connections, start with master server
  var allConnections = [];
  // Get all connected connections
  for(var name in this.upServers) {
    allConnections = allConnections.concat(this.upServers[name].allRawConnections());
  }
  // Return all the conections
  return allConnections;
}

/**
 * @ignore
 */
Mongos.prototype.isConnected = function() {
  return Object.keys(this.upServers).length > 0;
}

/**
 * @ignore
 */
Mongos.prototype.isAutoReconnect = function() {
  return true;
}

/**
 * @ignore
 */
Mongos.prototype.canWrite = Mongos.prototype.isConnected;

/**
 * @ignore
 */
Mongos.prototype.canRead = Mongos.prototype.isConnected;

/**
 * @ignore
 */
Mongos.prototype.isDestroyed = function() {
  return this._serverState == 'destroyed';
}

/**
 * @ignore
 */
Mongos.prototype.checkoutWriter = function() {
  // Checkout a writer
  var keys = Object.keys(this.upServers);
  // console.dir("============================ checkoutWriter :: " + keys.length)
  if(keys.length == 0) return null;
  // console.log("=============== checkoutWriter :: " + this.upServers[keys[0]].checkoutWriter().socketOptions.port)
  return this.upServers[keys[0]].checkoutWriter();
}

/**
 * @ignore
 */
Mongos.prototype.checkoutReader = function(read) {
  // console.log("=============== checkoutReader :: read :: " + read);
  // If read is set to null default to primary
  read = read || 'primary'
  // If we have a read preference object unpack it
  if(read != null && typeof read == 'object' && read['_type'] == 'ReadPreference') {
    // Validate if the object is using a valid mode
    if(!read.isValid()) throw new Error("Illegal readPreference mode specified, " + read.mode);
  } else if(!ReadPreference.isValid(read)) {
    throw new Error("Illegal readPreference mode specified, " + read);
  }

  // Checkout a writer
  var keys = Object.keys(this.upServers);
  if(keys.length == 0) return null;
  // console.log("=============== checkoutReader :: " + this.upServers[keys[0]].checkoutWriter().socketOptions.port)
  // console.dir(this._commandsStore.commands)
  return this.upServers[keys[0]].checkoutWriter();
}

/**
 * @ignore
 */
Mongos.prototype.close = function(callback) {
  var self = this;
  // Set server status as disconnected
  this._serverState = 'destroyed';
  // Number of connections to close
  var numberOfConnectionsToClose = self.servers.length;
  // If we have a ha process running kill it
  if(self._replicasetTimeoutId != null) clearInterval(self._replicasetTimeoutId);
  self._replicasetTimeoutId = null;
  
  // Emit close event
  processor(function() {
    self._emitAcrossAllDbInstances(self, null, "close", null, null, true)    
  });

  // Close all the up servers
  for(var name in this.upServers) {
    this.upServers[name].close(function(err, result) {
      numberOfConnectionsToClose = numberOfConnectionsToClose - 1;

      // Callback if we have one defined
      if(numberOfConnectionsToClose == 0 && typeof callback == 'function') {
        callback(null);
      }
    });
  }
}

/**
 * @ignore
 * Return the used state
 */
Mongos.prototype._isUsed = function() {
  return this._used;
}

exports.Mongos = Mongos;