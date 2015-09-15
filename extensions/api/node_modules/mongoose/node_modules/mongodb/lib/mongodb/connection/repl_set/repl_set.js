var ReadPreference = require('../read_preference').ReadPreference
  , DbCommand = require('../../commands/db_command').DbCommand
  , inherits = require('util').inherits
  , format = require('util').format
  , timers = require('timers')
  , Server = require('../server').Server
  , utils = require('../../utils')
  , PingStrategy = require('./strategies/ping_strategy').PingStrategy
  , StatisticsStrategy = require('./strategies/statistics_strategy').StatisticsStrategy
  , Options = require('./options').Options
  , ReplSetState = require('./repl_set_state').ReplSetState
  , HighAvailabilityProcess = require('./ha').HighAvailabilityProcess
  , Base = require('../base').Base;

const STATE_STARTING_PHASE_1 = 0;
const STATE_PRIMARY = 1;
const STATE_SECONDARY = 2;
const STATE_RECOVERING = 3;
const STATE_FATAL_ERROR = 4;
const STATE_STARTING_PHASE_2 = 5;
const STATE_UNKNOWN = 6;
const STATE_ARBITER = 7;
const STATE_DOWN = 8;
const STATE_ROLLBACK = 9;

// Set processor, setImmediate if 0.10 otherwise nextTick
var processor = require('../../utils').processor();

/**
 * ReplSet constructor provides replicaset functionality
 *
 * Options
 *  - **ha** {Boolean, default:true}, turn on high availability.
 *  - **haInterval** {Number, default:2000}, time between each replicaset status check.
 *  - **reconnectWait** {Number, default:1000}, time to wait in miliseconds before attempting reconnect.
 *  - **retries** {Number, default:30}, number of times to attempt a replicaset reconnect.
 *  - **rs_name** {String}, the name of the replicaset to connect to.
 *  - **socketOptions** {Object, default:null}, an object containing socket options to use (noDelay:(boolean), keepAlive:(number), connectTimeoutMS:(number), socketTimeoutMS:(number))
 *  - **readPreference** {String}, the prefered read preference (ReadPreference.PRIMARY, ReadPreference.PRIMARY_PREFERRED, ReadPreference.SECONDARY, ReadPreference.SECONDARY_PREFERRED, ReadPreference.NEAREST).
 *  - **strategy** {String, default:'ping'}, selection strategy for reads choose between (ping, statistical and none, default is ping)
 *  - **secondaryAcceptableLatencyMS** {Number, default:15}, sets the range of servers to pick when using NEAREST (lowest ping ms + the latency fence, ex: range of 1 to (1 + 15) ms)
 *  - **connectWithNoPrimary** {Boolean, default:false}, sets if the driver should connect even if no primary is available
 *  - **connectArbiter** {Boolean, default:false}, sets if the driver should connect to arbiters or not.
 *  - **logger** {Object, default:null}, an object representing a logger that you want to use, needs to support functions debug, log, error **({error:function(message, object) {}, log:function(message, object) {}, debug:function(message, object) {}})**.
 *  - **poolSize** {Number, default:5}, number of connections in the connection pool for each server instance, set to 5 as default for legacy reasons.
 *  - **ssl** {Boolean, default:false}, use ssl connection (needs to have a mongod server with ssl support)
 *  - **sslValidate** {Boolean, default:false}, validate mongod server certificate against ca (needs to have a mongod server with ssl support, 2.4 or higher)
 *  - **sslCA** {Array, default:null}, Array of valid certificates either as Buffers or Strings (needs to have a mongod server with ssl support, 2.4 or higher)
 *  - **sslCert** {Buffer/String, default:null}, String or buffer containing the certificate we wish to present (needs to have a mongod server with ssl support, 2.4 or higher)
 *  - **sslKey** {Buffer/String, default:null}, String or buffer containing the certificate private key we wish to present (needs to have a mongod server with ssl support, 2.4 or higher)
 *  - **sslPass** {Buffer/String, default:null}, String or buffer containing the certificate password (needs to have a mongod server with ssl support, 2.4 or higher)
 *
 * @class Represents a 
 Replicaset Configuration
 * @param {Array} list of server objects participating in the replicaset.
 * @param {Object} [options] additional options for the replicaset connection.
 */
var ReplSet = exports.ReplSet = function(servers, options) {
  // Set up basic
  if(!(this instanceof ReplSet))
    return new ReplSet(servers, options);

  // Set up event emitter
  Base.call(this);

  // Ensure we have a list of servers
  if(!Array.isArray(servers)) throw Error("The parameter must be an array of servers and contain at least one server");
  // Ensure no Mongos's
  for(var i = 0; i < servers.length; i++) {
    if(!(servers[i] instanceof Server)) throw new Error("list of servers must be of type Server");
  }

  // Save the options
  this.options = new Options(options);
  // Ensure basic validation of options
  this.options.init();

  // Server state
  this._serverState = ReplSet.REPLSET_DISCONNECTED;
  // Add high availability process
  this._haProcess = new HighAvailabilityProcess(this, this.options);


  // Let's iterate over all the provided server objects and decorate them
  this.servers = this.options.decorateAndClean(servers, this._callBackStore);
  // Throw error if no seed servers
  if(this.servers.length == 0) throw new Error("No valid seed servers in the array");

  // Let's set up our strategy object for picking secondaries
  if(this.options.strategy == 'ping') {
    // Create a new instance
    this.strategyInstance = new PingStrategy(this, this.options.secondaryAcceptableLatencyMS);
  } else if(this.options.strategy == 'statistical') {
    // Set strategy as statistical
    this.strategyInstance = new StatisticsStrategy(this);
    // Add enable query information
    this.enableRecordQueryStats(true);
  }

  this.emitOpen = this.options.emitOpen || true;
  // Set up a clean state
  this._state = new ReplSetState();
  // Current round robin selected server
  this._currentServerChoice = 0;
  // Ensure up the server callbacks
  for(var i = 0; i < this.servers.length; i++) {
    this.servers[i]._callBackStore = this._callBackStore;
    this.servers[i].name = format("%s:%s", this.servers[i].host, this.servers[i].port)
    this.servers[i].replicasetInstance = this;
    this.servers[i].options.auto_reconnect = false;
    this.servers[i].inheritReplSetOptionsFrom(this);
  }
}

/**
 * @ignore
 */
inherits(ReplSet, Base);

// Replicaset states
ReplSet.REPLSET_CONNECTING = 'connecting';
ReplSet.REPLSET_DISCONNECTED = 'disconnected';
ReplSet.REPLSET_CONNECTED = 'connected';
ReplSet.REPLSET_RECONNECTING = 'reconnecting';
ReplSet.REPLSET_DESTROYED = 'destroyed';
ReplSet.REPLSET_READ_ONLY = 'readonly';

ReplSet.prototype.isAutoReconnect = function() {
  return true;
}

ReplSet.prototype.canWrite = function() {
  return this._state.master && this._state.master.isConnected();
}

ReplSet.prototype.canRead = function(read) {
  if((read == ReadPreference.PRIMARY 
      || read == null || read == false) && (this._state.master == null || !this._state.master.isConnected())) return false;
  return Object.keys(this._state.secondaries).length > 0;
}

/**
 * @ignore
 */
ReplSet.prototype.enableRecordQueryStats = function(enable) {
  // Set the global enable record query stats
  this.recordQueryStats = enable;

  // Enable all the servers
  for(var i = 0; i < this.servers.length; i++) {
    this.servers[i].enableRecordQueryStats(enable);
  }
}

/**
 * @ignore
 */
ReplSet.prototype.setReadPreference = function(preference) {
  this.options.readPreference = preference;
}

ReplSet.prototype.connect = function(parent, options, callback) {
  if(this._serverState != ReplSet.REPLSET_DISCONNECTED) 
    return callback(new Error("in process of connection"));

  // If no callback throw
  if(!(typeof callback == 'function')) 
    throw new Error("cannot call ReplSet.prototype.connect with no callback function");

  var self = this;
  // Save db reference
  this.options.db = parent;
  // Set replicaset as connecting
  this._serverState = ReplSet.REPLSET_CONNECTING
  // Copy all the servers to our list of seeds
  var candidateServers = this.servers.slice(0);
  // Pop the first server
  var server = candidateServers.pop();
  server.name = format("%s:%s", server.host, server.port);
  // Set up the options
  var opts = {
    returnIsMasterResults: true,
    eventReceiver: server
  }

  // Register some event listeners
  this.once("fullsetup", function(err, db, replset) {
    // Set state to connected
    self._serverState = ReplSet.REPLSET_CONNECTED;
    // Stop any process running
    if(self._haProcess) self._haProcess.stop();
    // Start the HA process
    self._haProcess.start();

    // Emit fullsetup
    processor(function() {
      if(self.emitOpen)
        self._emitAcrossAllDbInstances(self, null, "open", null, null, null);        

      self._emitAcrossAllDbInstances(self, null, "fullsetup", null, null, null);        
    });

    // If we have a strategy defined start it
    if(self.strategyInstance) {
      self.strategyInstance.start();
    }

    // Finishing up the call
    callback(err, db, replset);
  });

  // Errors
  this.once("connectionError", function(err, result) {
    callback(err, result);
  });

  // Attempt to connect to the server
  server.connect(this.options.db, opts, _connectHandler(this, candidateServers, server));
}

ReplSet.prototype.close = function(callback) {  
  var self = this;
  // Set as destroyed
  this._serverState = ReplSet.REPLSET_DESTROYED;
  // Stop the ha
  this._haProcess.stop();
  
  // If we have a strategy stop it
  if(this.strategyInstance) {
    this.strategyInstance.stop();
  }

  // Kill all servers available
  for(var name in this._state.addresses) {
    this._state.addresses[name].close();
  }

  // Clean out the state
  this._state = new ReplSetState(); 
  
  // Emit close event
  processor(function() {
    self._emitAcrossAllDbInstances(self, null, "close", null, null, true)    
  });

  // Callback
  if(typeof callback == 'function') 
    return callback(null, null);
}

/**
 * Creates a new server for the `replset` based on `host`.
 *
 * @param {String} host - host:port pair (localhost:27017)
 * @param {ReplSet} replset - the ReplSet instance
 * @return {Server}
 * @ignore
 */
var createServer = function(self, host, options) {
  // copy existing socket options to new server
  var socketOptions = {}
  if(options.socketOptions) {
    var keys = Object.keys(options.socketOptions);
    for(var k = 0; k < keys.length; k++) {
      socketOptions[keys[k]] = options.socketOptions[keys[k]];
    }
  }

  var parts = host.split(/:/);
  if(1 === parts.length) {
    parts[1] = Connection.DEFAULT_PORT;
  }

  socketOptions.host = parts[0];
  socketOptions.port = parseInt(parts[1], 10);

  var serverOptions = {
    readPreference: options.readPreference,
    socketOptions: socketOptions,
    poolSize: options.poolSize,
    logger: options.logger,
    auto_reconnect: false,
    ssl: options.ssl,
    sslValidate: options.sslValidate,
    sslCA: options.sslCA,
    sslCert: options.sslCert,
    sslKey: options.sslKey,
    sslPass: options.sslPass
  }

  var server = new Server(socketOptions.host, socketOptions.port, serverOptions);
  // Set up shared state
  server._callBackStore = self._callBackStore;
  server.replicasetInstance = self;
  server.enableRecordQueryStats(self.recordQueryStats);
  // Set up event handlers
  server.on("close", _handler("close", self, server));
  server.on("error", _handler("error", self, server));
  server.on("timeout", _handler("timeout", self, server));
  return server;
}

var _handler = function(event, self, server) {
  return function(err, doc) {
    // The event happened to a primary
    // Remove it from play
    if(self._state.isPrimary(server)) {
      var current_master = self._state.master;
      self._state.master = null;
      self._serverState = ReplSet.REPLSET_READ_ONLY;
    
      if(current_master != null) {
        // Unpack variables
        var host = current_master.socketOptions.host;
        var port = current_master.socketOptions.port;

        // Fire error on any unknown callbacks
        self.__executeAllServerSpecificErrorCallbacks(host, port, err);        
      }
    } else if(self._state.isSecondary(server)) {
      delete self._state.secondaries[server.name];
    }

    // If there is no more connections left and the setting is not destroyed
    // set to disconnected
    if(Object.keys(self._state.addresses).length == 0 
      && self._serverState != ReplSet.REPLSET_DESTROYED) {
        self._serverState = ReplSet.REPLSET_DISCONNECTED;

        // Emit close across all the attached db instances
        self._dbStore.emit("close", new Error("replicaset disconnected, no valid servers contactable over tcp"), null, true);
    }

    // Unpack variables
    var host = server.socketOptions.host;
    var port = server.socketOptions.port;

    // Fire error on any unknown callbacks
    self.__executeAllServerSpecificErrorCallbacks(host, port, err);
  }
}

var locateNewServers = function(self, state, candidateServers, ismaster) {
  // Retrieve the host
  var hosts = ismaster.hosts;
  // In candidate servers
  var inCandidateServers = function(name, candidateServers) {
    for(var i = 0; i < candidateServers.length; i++) {
      if(candidateServers[i].name == name) return true;
    }

    return false;
  }

  // New servers
  var newServers = [];
  if(Array.isArray(hosts)) {
    // Let's go over all the hosts
    for(var i = 0; i < hosts.length; i++) {
      if(!state.contains(hosts[i]) 
        && !inCandidateServers(hosts[i], candidateServers)) {
          newServers.push(createServer(self, hosts[i], self.options));
      }
    }    
  }

  // Return list of possible new servers
  return newServers;
}

var _connectHandler = function(self, candidateServers, instanceServer) {
  return function(err, doc) {
    // If we have an error add to the list
    if(err) {
      self._state.errors[instanceServer.name] = instanceServer;
    } else {
      delete self._state.errors[instanceServer.name];
    }

    if(!err) {      
      var ismaster = doc.documents[0]

      // Error the server if 
      if(!ismaster.ismaster
        && !ismaster.secondary) {
        self._state.errors[instanceServer.name] = instanceServer;
      }
    }


    // No error let's analyse the ismaster command
    if(!err && self._state.errors[instanceServer.name] == null) {
      var ismaster = doc.documents[0]

      // If no replicaset name exists set the current one
      if(self.options.rs_name == null) {
        self.options.rs_name = ismaster.setName;
      }

      // If we have a member that is not part of the set let's finish up
      if(typeof ismaster.setName == 'string' && ismaster.setName != self.options.rs_name) {
        return self.emit("connectionError", new Error("Replicaset name " + ismaster.setName + " does not match specified name " + self.options.rs_name));
      }

      // Add the error handlers
      instanceServer.on("close", _handler("close", self, instanceServer));
      instanceServer.on("error", _handler("error", self, instanceServer));
      instanceServer.on("timeout", _handler("timeout", self, instanceServer));
      
      // Set any tags on the instance server
      instanceServer.name = ismaster.me;
      instanceServer.tags = ismaster.tags;

      // Add the server to the list
      self._state.addServer(instanceServer, ismaster);

      // Check if we have more servers to add (only check when done with initial set)
      if(candidateServers.length == 0) {
        // Get additional new servers that are not currently in set
        var new_servers = locateNewServers(self, self._state, candidateServers, ismaster);

        // Locate any new servers that have not errored out yet
        for(var i = 0; i < new_servers.length; i++) {
          if(self._state.errors[new_servers[i].name] == null) {
            candidateServers.push(new_servers[i])            
          }
        }
      }
    }

    // If the candidate server list is empty and no valid servers
    if(candidateServers.length == 0 &&
      !self._state.hasValidServers()) {
        return self.emit("connectionError", new Error("No valid replicaset instance servers found"));
    } else if(candidateServers.length == 0) {      
      if(!self.options.connectWithNoPrimary && (self._state.master == null || !self._state.master.isConnected())) {
        return self.emit("connectionError", new Error("No primary found in set"));
      }
      return self.emit("fullsetup", null, self.options.db, self);
    }
        
    // Let's connect the next server    
    var nextServer = candidateServers.pop();
  
    // Set up the options
    var opts = {
      returnIsMasterResults: true,
      eventReceiver: nextServer
    }

    // Attempt to connect to the server
    nextServer.connect(self.options.db, opts, _connectHandler(self, candidateServers, nextServer));
  }
}

ReplSet.prototype.isDestroyed = function() {
  return this._serverState == ReplSet.REPLSET_DESTROYED;
}

ReplSet.prototype.isConnected = function(read) {
  var isConnected = false;  

  if(read == null || read == ReadPreference.PRIMARY || read == false)
    isConnected = this._state.master != null && this._state.master.isConnected();

  if((read == ReadPreference.PRIMARY_PREFERRED || read == ReadPreference.SECONDARY_PREFERRED || read == ReadPreference.NEAREST)
    && ((this._state.master != null && this._state.master.isConnected())
    || (this._state && this._state.secondaries && Object.keys(this._state.secondaries).length > 0))) {
      isConnected = true;
  } else if(read == ReadPreference.SECONDARY) {
    isConnected = this._state && this._state.secondaries && Object.keys(this._state.secondaries).length > 0;
  }

  // No valid connection return false
  return isConnected;
}

ReplSet.prototype.isMongos = function() {
  return false;
}

ReplSet.prototype.checkoutWriter = function() {
  if(this._state.master) return this._state.master.checkoutWriter();
  return new Error("no writer connection available");
}

ReplSet.prototype.processIsMaster = function(_server, _ismaster) {
  // Server in recovery mode, remove it from available servers
  if(!_ismaster.ismaster && !_ismaster.secondary) {
    // Locate the actual server
    var server = this._state.addresses[_server.name];
    // Close the server, simulating the closing of the connection
    // to get right removal semantics
    if(server) server.close();
    // Execute any callback errors
    _handler(null, this, server)(new Error("server is in recovery mode"));
  }
}

ReplSet.prototype.allRawConnections = function() {
  var connections = [];

  for(var name in this._state.addresses) {
    connections = connections.concat(this._state.addresses[name].allRawConnections());
  }

  return connections;
}

/**
 * @ignore
 */
ReplSet.prototype.allServerInstances = function() {
  var self = this;
  // If no state yet return empty
  if(!self._state) return [];
  // Close all the servers (concatenate entire list of servers first for ease)
  var allServers = self._state.master != null ? [self._state.master] : [];

  // Secondary keys
  var keys = Object.keys(self._state.secondaries);
  // Add all secondaries
  for(var i = 0; i < keys.length; i++) {
    allServers.push(self._state.secondaries[keys[i]]);
  }

  // Return complete list of all servers
  return allServers;
}

/**
 * @ignore
 */
ReplSet.prototype.checkoutReader = function(readPreference, tags) {
  var connection = null;

  // If we have a read preference object unpack it
  if(typeof readPreference == 'object' && readPreference['_type'] == 'ReadPreference') {
    // Validate if the object is using a valid mode
    if(!readPreference.isValid()) throw new Error("Illegal readPreference mode specified, " + readPreference.mode);
    // Set the tag
    tags = readPreference.tags;
    readPreference = readPreference.mode;
  } else if(typeof readPreference == 'object' && readPreference['_type'] != 'ReadPreference') {
    return new Error("read preferences must be either a string or an instance of ReadPreference");
  }

  // Set up our read Preference, allowing us to override the readPreference
  var finalReadPreference = readPreference != null ? readPreference : this.options.readPreference;

  // Ensure we unpack a reference
  if(finalReadPreference != null && typeof finalReadPreference == 'object' && finalReadPreference['_type'] == 'ReadPreference') {
    // Validate if the object is using a valid mode
    if(!finalReadPreference.isValid()) throw new Error("Illegal readPreference mode specified, " + finalReadPreference.mode);
    // Set the tag
    tags = finalReadPreference.tags;
    readPreference = finalReadPreference.mode;
  }

  // Finalize the read preference setup
  finalReadPreference = finalReadPreference == true ? ReadPreference.SECONDARY_PREFERRED : finalReadPreference;
  finalReadPreference = finalReadPreference == null ? ReadPreference.PRIMARY : finalReadPreference;

  // If we are reading from a primary
  if(finalReadPreference == 'primary') {
    // If we provide a tags set send an error
    if(typeof tags == 'object' && tags != null) {
      return new Error("PRIMARY cannot be combined with tags");
    }

    // If we provide a tags set send an error
    if(this._state.master == null) {
      return new Error("No replica set primary available for query with ReadPreference PRIMARY");
    }

    // Checkout a writer
    return this.checkoutWriter();
  }

  // If we have specified to read from a secondary server grab a random one and read
  // from it, otherwise just pass the primary connection
  if((this.options.readSecondary || finalReadPreference == ReadPreference.SECONDARY_PREFERRED || finalReadPreference == ReadPreference.SECONDARY) && Object.keys(this._state.secondaries).length > 0) {
    // If we have tags, look for servers matching the specific tag
    if(this.strategyInstance != null) {
      // Only pick from secondaries
      var _secondaries = [];
      for(var key in this._state.secondaries) {
        _secondaries.push(this._state.secondaries[key]);
      }

      if(finalReadPreference == ReadPreference.SECONDARY) {
        // Check out the nearest from only the secondaries
        connection = this.strategyInstance.checkoutConnection(tags, _secondaries);
      } else {
        connection = this.strategyInstance.checkoutConnection(tags, _secondaries);
        // No candidate servers that match the tags, error
        if(connection == null || connection instanceof Error) {
          // No secondary server avilable, attemp to checkout a primary server
          connection = this.checkoutWriter();
          // If no connection return an error
          if(connection == null || connection instanceof Error) {
            return new Error("No replica set members available for query");
          }
        }
      }
    } else if(tags != null && typeof tags == 'object') {
      // Get connection
      connection = _pickFromTags(this, tags);// = function(self, readPreference, tags) {
      // No candidate servers that match the tags, error
      if(connection == null) {
        return new Error("No replica set members available for query");
      }
    } else {
      connection = _roundRobin(this, tags);
    }
  } else if(finalReadPreference == ReadPreference.PRIMARY_PREFERRED) {
    // Check if there is a primary available and return that if possible
    connection = this.checkoutWriter();
    // If no connection available checkout a secondary
    if(connection == null || connection instanceof Error) {
      // If we have tags, look for servers matching the specific tag
      if(tags != null && typeof tags == 'object') {
        // Get connection
        connection = _pickFromTags(this, tags);// = function(self, readPreference, tags) {
        // No candidate servers that match the tags, error
        if(connection == null) {
          return new Error("No replica set members available for query");
        }
      } else {
        connection = _roundRobin(this, tags);
      }
    }
  } else if(finalReadPreference == ReadPreference.SECONDARY_PREFERRED) {
    // If we have tags, look for servers matching the specific tag
    if(this.strategyInstance != null) {
      connection = this.strategyInstance.checkoutConnection(tags);
      
      // No candidate servers that match the tags, error
      if(connection == null || connection instanceof Error) {
        // No secondary server avilable, attemp to checkout a primary server
        connection = this.checkoutWriter();
        // If no connection return an error
        if(connection == null || connection instanceof Error) {
          var preferenceName = finalReadPreference == ReadPreference.SECONDARY ? 'secondary' : finalReadPreference;
          return new Error("No replica set member available for query with ReadPreference " + preferenceName + " and tags " + JSON.stringify(tags));
        }
      }
    } else if(tags != null && typeof tags == 'object') {
      // Get connection
      connection = _pickFromTags(this, tags);// = function(self, readPreference, tags) {
      // No candidate servers that match the tags, error
      if(connection == null) {
        // No secondary server avilable, attemp to checkout a primary server
        connection = this.checkoutWriter();
        // If no connection return an error
        if(connection == null || connection instanceof Error) {
          var preferenceName = finalReadPreference == ReadPreference.SECONDARY ? 'secondary' : finalReadPreference;
          return new Error("No replica set member available for query with ReadPreference " + preferenceName + " and tags " + JSON.stringify(tags));
        }
      }
    }
  } else if(finalReadPreference == ReadPreference.NEAREST && this.strategyInstance != null) {
    connection = this.strategyInstance.checkoutConnection(tags);
  } else if(finalReadPreference == ReadPreference.NEAREST && this.strategyInstance == null) {
    return new Error("A strategy for calculating nearness must be enabled such as ping or statistical");
  } else if(finalReadPreference == ReadPreference.SECONDARY && Object.keys(this._state.secondaries).length == 0) {
    if(tags != null && typeof tags == 'object') {
      var preferenceName = finalReadPreference == ReadPreference.SECONDARY ? 'secondary' : finalReadPreference;
      return new Error("No replica set member available for query with ReadPreference " + preferenceName + " and tags " + JSON.stringify(tags));
    } else {
      return new Error("No replica set secondary available for query with ReadPreference SECONDARY");
    }
  } else {
    connection = this.checkoutWriter();
  }

  // Return the connection
  return connection;
}

/**
 * @ignore
 */
var _pickFromTags = function(self, tags) {
  // If we have an array or single tag selection
  var tagObjects = Array.isArray(tags) ? tags : [tags];
  // Iterate over all tags until we find a candidate server
  for(var _i = 0; _i < tagObjects.length; _i++) {
    // Grab a tag object
    var tagObject = tagObjects[_i];
    // Matching keys
    var matchingKeys = Object.keys(tagObject);
    // Match all the servers that match the provdided tags
    var keys = Object.keys(self._state.secondaries);
    var candidateServers = [];

    for(var i = 0; i < keys.length; i++) {
      var server = self._state.secondaries[keys[i]];
      // If we have tags match
      if(server.tags != null) {
        var matching = true;
        // Ensure we have all the values
        for(var j = 0; j < matchingKeys.length; j++) {
          if(server.tags[matchingKeys[j]] != tagObject[matchingKeys[j]]) {
            matching = false;
            break;
          }
        }

        // If we have a match add it to the list of matching servers
        if(matching) {
          candidateServers.push(server);
        }
      }
    }

    // If we have a candidate server return
    if(candidateServers.length > 0) {
      if(self.strategyInstance) return self.strategyInstance.checkoutConnection(tags, candidateServers);
      // Set instance to return
      return candidateServers[Math.floor(Math.random() * candidateServers.length)].checkoutReader();
    }
  }

  // No connection found
  return null;
}

/**
 * Pick a secondary using round robin
 *
 * @ignore
 */
function _roundRobin (replset, tags) {
  var keys = Object.keys(replset._state.secondaries);
  // Update index
  replset._currentServerChoice = replset._currentServerChoice + 1;
  // Pick a server
  var key = keys[replset._currentServerChoice % keys.length];

  var conn = null != replset._state.secondaries[key]
    ? replset._state.secondaries[key].checkoutReader()
    : null;

  // If connection is null fallback to first available secondary
  if(null == conn) {
    conn = pickFirstConnectedSecondary(replset, tags);
  }

  return conn;
}

/**
 * @ignore
 */
var pickFirstConnectedSecondary = function pickFirstConnectedSecondary(self, tags) {
  var keys = Object.keys(self._state.secondaries);
  var connection;

  // Find first available reader if any
  for(var i = 0; i < keys.length; i++) {
    connection = self._state.secondaries[keys[i]].checkoutReader();
    if(connection) return connection;
  }

  // If we still have a null, read from primary if it's not secondary only
  if(self._readPreference == ReadPreference.SECONDARY_PREFERRED) {
    connection = self._state.master.checkoutReader();
    if(connection) return connection;
  }

  var preferenceName = self._readPreference == ReadPreference.SECONDARY_PREFERRED
    ? 'secondary'
    : self._readPreference;

  return new Error("No replica set member available for query with ReadPreference "
                  + preferenceName + " and tags " + JSON.stringify(tags));
}

/**
 * Get list of secondaries
 * @ignore
 */
Object.defineProperty(ReplSet.prototype, "secondaries", {enumerable: true
  , get: function() {
      return utils.objectToArray(this._state.secondaries);
    }
});

/**
 * Get list of secondaries
 * @ignore
 */
Object.defineProperty(ReplSet.prototype, "arbiters", {enumerable: true
  , get: function() {
      return utils.objectToArray(this._state.arbiters);
    }
});

