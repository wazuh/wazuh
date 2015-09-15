var DbCommand = require('../../commands/db_command').DbCommand
  , format = require('util').format;

var HighAvailabilityProcess = function(replset, options) {  
  this.replset = replset;
  this.options = options;
  this.server = null;
  this.state = HighAvailabilityProcess.INIT;
  this.selectedIndex = 0;
}

HighAvailabilityProcess.INIT = 'init';
HighAvailabilityProcess.RUNNING = 'running';
HighAvailabilityProcess.STOPPED = 'stopped';

HighAvailabilityProcess.prototype.start = function() {  
  var self = this;
  if(this.replset._state 
    && Object.keys(this.replset._state.addresses).length == 0) {
    if(this.server) this.server.close();
    this.state = HighAvailabilityProcess.STOPPED;
    return;      
  }

  if(this.server) this.server.close();
  // Start the running
  this._haProcessInProcess = false;
  this.state = HighAvailabilityProcess.RUNNING;
  
  // Get all possible reader servers
  var candidate_servers = this.replset._state.getAllReadServers();
  if(candidate_servers.length == 0) {
    return;
  }

  // Select a candidate server for the connection
  var server = candidate_servers[this.selectedIndex % candidate_servers.length];
  this.selectedIndex = this.selectedIndex + 1;
  
  // Unpack connection options
  var connectTimeoutMS = self.options.connectTimeoutMS || 10000;
  var socketTimeoutMS = self.options.socketTimeoutMS || 30000;

  // Just ensure we don't have a full cycle dependency
  var Db = require('../../db').Db
  var Server = require('../server').Server;

  // Set up a new server instance
  var newServer = new Server(server.host, server.port, {
      auto_reconnect: false
    , returnIsMasterResults: true
    , poolSize: 1
    , socketOptions: { 
        connectTimeoutMS: connectTimeoutMS,
        socketTimeoutMS: socketTimeoutMS,
        keepAlive: 100
      }
    , ssl: this.options.ssl
    , sslValidate: this.options.sslValidate
    , sslCA: this.options.sslCA
    , sslCert: this.options.sslCert
    , sslKey: this.options.sslKey
    , sslPass: this.options.sslPass
  });

  // Create new dummy db for app
  self.db = new Db('local', newServer, {w:1});

  // Set up the event listeners
  newServer.once("error", _handle(this, newServer));
  newServer.once("close", _handle(this, newServer));
  newServer.once("timeout", _handle(this, newServer));
  newServer.name = format("%s:%s", server.host, server.port);

  // Let's attempt a connection over here
  newServer.connect(self.db, function(err, result, _server) {
    if(self.state == HighAvailabilityProcess.STOPPED) {
      _server.close();
    }

    if(err) {
      // Close the server
      _server.close();
      // Check if we can even do HA (is there anything running)
      if(Object.keys(self.replset._state.addresses).length == 0) {
        return;
      }
      
      // Let's boot the ha timeout settings
      setTimeout(function() {
        self.start();
      }, self.options.haInterval);
    } else {
      self.server = _server;
      // Let's boot the ha timeout settings
      setTimeout(_timeoutHandle(self), self.options.haInterval);
    }
  });
}

HighAvailabilityProcess.prototype.stop = function() {
  this.state = HighAvailabilityProcess.STOPPED;
  if(this.server) this.server.close();
}

var _timeoutHandle = function(self) {
  return function() {
    if(self.state == HighAvailabilityProcess.STOPPED) {
      // Stop all server instances
      for(var name in self.replset._state.addresses) {
        self.replset._state.addresses[name].close();
        delete self.replset._state.addresses[name];
      }

      // Finished pinging
      return;
    }

    // If the server is connected
    if(self.server.isConnected() && !self._haProcessInProcess) {
      // Start HA process
      self._haProcessInProcess = true;
      // Execute is master command
      self.db._executeQueryCommand(DbCommand.createIsMasterCommand(self.db), 
          {failFast:true, connection: self.server.checkoutReader()}
        , function(err, res) {
          if(err) {
            self.server.close();
            return setTimeout(_timeoutHandle(self), self.options.haInterval);
          }

          // Master document
          var master = res.documents[0];
          var hosts = master.hosts || [];
          var reconnect_servers = [];
          var state = self.replset._state;

          // We are in recovery mode, let's remove the current server
          if(!master.ismaster 
            && !master.secondary
            && state.addresses[master.me]) {
              self.server.close();
              state.addresses[master.me].close();
              delete state.secondaries[master.me];
              return setTimeout(_timeoutHandle(self), self.options.haInterval);
          }

          // For all the hosts let's check that we have connections
          for(var i = 0; i < hosts.length; i++) {
            var host = hosts[i];
            // Check if we need to reconnect to a server
            if(state.addresses[host] == null) {
              reconnect_servers.push(host);
            } else if(state.addresses[host] && !state.addresses[host].isConnected()) {
              state.addresses[host].close();
              delete state.secondaries[host];
              reconnect_servers.push(host);              
            }

            if((master.primary && state.master == null)
              || (master.primary && state.master.name != master.primary)) {

              // Locate the primary and set it
              if(state.addresses[master.primary]) {
                if(state.master) state.master.close();
                delete state.secondaries[master.primary];
                state.master = state.addresses[master.primary];
              }
              
              // Set up the changes
              if(state.master != null && state.master.isMasterDoc != null) {
                state.master.isMasterDoc.ismaster = true;
                state.master.isMasterDoc.secondary = false;                
              } else if(state.master != null) {
                state.master.isMasterDoc = master;
                state.master.isMasterDoc.ismaster = true;
                state.master.isMasterDoc.secondary = false;                
              }

              // Execute any waiting commands (queries or writes)
              self.replset._commandsStore.execute_queries();
              self.replset._commandsStore.execute_writes();   
            }
          }

          // Let's reconnect to any server needed
          if(reconnect_servers.length > 0) {
            _reconnect_servers(self, reconnect_servers);  
          } else {
            self._haProcessInProcess = false
            return setTimeout(_timeoutHandle(self), self.options.haInterval);
          }
      });
    } else if(!self.server.isConnected()) {
      setTimeout(function() {
        return self.start();
      }, self.options.haInterval);
    } else {
      setTimeout(_timeoutHandle(self), self.options.haInterval);
    }
  }
}

var _reconnect_servers = function(self, reconnect_servers) {
  if(reconnect_servers.length == 0) {
    self._haProcessInProcess = false    
    return setTimeout(_timeoutHandle(self), self.options.haInterval);
  }

  // Unpack connection options
  var connectTimeoutMS = self.options.connectTimeoutMS || 10000;
  var socketTimeoutMS = self.options.socketTimeoutMS || 30000;

  // Server class
  var Db = require('../../db').Db
  var Server = require('../server').Server;
  // Get the host
  var host = reconnect_servers.shift();
  // Split it up
  var _host = host.split(":")[0];
  var _port = parseInt(host.split(":")[1], 10);

  // Set up a new server instance
  var newServer = new Server(_host, _port, {
      auto_reconnect: false
    , returnIsMasterResults: true
    , poolSize: self.options.poolSize
    , socketOptions: { 
        connectTimeoutMS: connectTimeoutMS,
        socketTimeoutMS: socketTimeoutMS
      }
    , ssl: self.options.ssl
    , sslValidate: self.options.sslValidate
    , sslCA: self.options.sslCA
    , sslCert: self.options.sslCert
    , sslKey: self.options.sslKey
    , sslPass: self.options.sslPass
  });

  // Create new dummy db for app
  var db = new Db('local', newServer, {w:1});
  var state = self.replset._state;

  // Set up the event listeners
  newServer.once("error", _repl_set_handler("error", self.replset, newServer));
  newServer.once("close", _repl_set_handler("close", self.replset, newServer));
  newServer.once("timeout", _repl_set_handler("timeout", self.replset, newServer));

  // Set shared state
  newServer.name = host;
  newServer._callBackStore = self.replset._callBackStore;
  newServer.replicasetInstance = self.replset;
  newServer.enableRecordQueryStats(self.replset.recordQueryStats);

  // Let's attempt a connection over here
  newServer.connect(db, function(err, result, _server) {
    if(self.state == HighAvailabilityProcess.STOPPED) {
      _server.close();
    }

    // If we connected let's check what kind of server we have
    if(!err) {
      _apply_auths(self, db, _server, function(err, result) {
        if(err) {
          _server.close();
          // Process the next server
          return setTimeout(function() {
            _reconnect_servers(self, reconnect_servers);  
          }, self.options.haInterval);                      
        }
        var doc = _server.isMasterDoc;    
        // Fire error on any unknown callbacks for this server
        self.replset.__executeAllServerSpecificErrorCallbacks(_server.socketOptions.host, _server.socketOptions.port, err);    

        if(doc.ismaster) {
          if(state.secondaries[doc.me]) {
            delete state.secondaries[doc.me];
          }

          // Override any server in list of addresses
          state.addresses[doc.me] = _server;
          // Set server as master
          state.master = _server;     
          // Execute any waiting writes
          self.replset._commandsStore.execute_writes();   
        } else if(doc.secondary) {
          state.secondaries[doc.me] = _server;
          // Override any server in list of addresses
          state.addresses[doc.me] = _server;
          // Execute any waiting reads
          self.replset._commandsStore.execute_queries();   
        } else {
          _server.close();
        }

        // Set any tags on the instance server
        _server.name = doc.me;
        _server.tags = doc.tags;
        // Process the next server
        setTimeout(function() {
          _reconnect_servers(self, reconnect_servers);  
        }, self.options.haInterval);            
      });
    } else {
      _server.close();
      self.replset.__executeAllServerSpecificErrorCallbacks(_server.socketOptions.host, _server.socketOptions.port, err);    

      setTimeout(function() {
        _reconnect_servers(self, reconnect_servers);  
      }, self.options.haInterval);            
    }
  });
}

var _apply_auths = function(self, _db, _server, _callback) {
  if(self.replset.auth.length() == 0) return _callback(null);
  // Apply any authentication needed
  if(self.replset.auth.length() > 0) {
    var pending = self.replset.auth.length();
    var connections = _server.allRawConnections();
    var pendingAuthConn = connections.length;

    // Connection function
    var connectionFunction = function(_auth, _connection, __callback) {
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
        _db.authenticate(username, password, options, function(err, result) {
          _error = err != null ? err : _error;
          // Adjust the pending authentication
          pending = pending - 1;
          // Finished up
          if(pending == 0) __callback(_error ? _error : null, _error ? false : true);
        });
      }
    }

    // Final error object
    var finalError = null;
    // Iterate over all the connections
    for(var i = 0; i < connections.length; i++) {
      connectionFunction(self.replset.auth, connections[i], function(err, result) {
        // Pending authentication
        pendingAuthConn = pendingAuthConn - 1 ;

        // Save error if any
        finalError = err ? err : finalError;

        // If we are done let's finish up
        if(pendingAuthConn == 0) {
          _callback(null);
        }
      });
    }
  }
}

var _handle = function(self, server) {
  return function(err) {
    server.close();    
  }
}

var _repl_set_handler = function(event, self, server) {
  var ReplSet = require('./repl_set').ReplSet;

  return function(err, doc) {
    server.close();

    // The event happened to a primary
    // Remove it from play
    if(self._state.isPrimary(server)) {
      self._state.master == null;
      self._serverState = ReplSet.REPLSET_READ_ONLY;
    } else if(self._state.isSecondary(server)) {
      delete self._state.secondaries[server.name];
    }

    // Unpack variables
    var host = server.socketOptions.host;
    var port = server.socketOptions.port;

    // Fire error on any unknown callbacks
    self.__executeAllServerSpecificErrorCallbacks(host, port, err);    
  }
}

exports.HighAvailabilityProcess = HighAvailabilityProcess;
