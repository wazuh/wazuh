var Server = require("../../server").Server
  , format = require('util').format;

// The ping strategy uses pings each server and records the
// elapsed time for the server so it can pick a server based on lowest
// return time for the db command {ping:true}
var PingStrategy = exports.PingStrategy = function(replicaset, secondaryAcceptableLatencyMS) {
  this.replicaset = replicaset;
  this.secondaryAcceptableLatencyMS = secondaryAcceptableLatencyMS;
  this.state = 'disconnected';
  this.pingInterval = 5000;
  // Class instance
  this.Db = require("../../../db").Db;
  // Active db connections
  this.dbs = {};
  // Current server index
  this.index = 0;
  // Logger api
  this.Logger = null;
}

// Starts any needed code
PingStrategy.prototype.start = function(callback) {
  // already running?
  if ('connected' == this.state) return;

  this.state = 'connected';

  // Start ping server
  this._pingServer(callback);
}

// Stops and kills any processes running
PingStrategy.prototype.stop = function(callback) {
  // Stop the ping process
  this.state = 'disconnected';

  // Stop all the server instances
  for(var key in this.dbs) {
    this.dbs[key].close();
  }

  // optional callback
  callback && callback(null, null);
}

PingStrategy.prototype.checkoutConnection = function(tags, secondaryCandidates) {
  // Servers are picked based on the lowest ping time and then servers that lower than that + secondaryAcceptableLatencyMS
  // Create a list of candidat servers, containing the primary if available
  var candidateServers = [];
  var self = this;

  // If we have not provided a list of candidate servers use the default setup
  if(!Array.isArray(secondaryCandidates)) {
    candidateServers = this.replicaset._state.master != null ? [this.replicaset._state.master] : [];
    // Add all the secondaries
    var keys = Object.keys(this.replicaset._state.secondaries);
    for(var i = 0; i < keys.length; i++) {
      candidateServers.push(this.replicaset._state.secondaries[keys[i]])
    }
  } else {
    candidateServers = secondaryCandidates;
  }

  // Final list of eligable server
  var finalCandidates = [];

  // If we have tags filter by tags
  if(tags != null && typeof tags == 'object') {
    // If we have an array or single tag selection
    var tagObjects = Array.isArray(tags) ? tags : [tags];
    // Iterate over all tags until we find a candidate server
    for(var _i = 0; _i < tagObjects.length; _i++) {
      // Grab a tag object
      var tagObject = tagObjects[_i];
      // Matching keys
      var matchingKeys = Object.keys(tagObject);
      // Remove any that are not tagged correctly
      for(var i = 0; i < candidateServers.length; i++) {
        var server = candidateServers[i];
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
            finalCandidates.push(server);
          }
        }
      }
    }
  } else {
    // Final array candidates
    var finalCandidates = candidateServers;
  }

  // Sort by ping time
  finalCandidates.sort(function(a, b) {
    return a.runtimeStats['pingMs'] > b.runtimeStats['pingMs'];
  });

  if(0 === finalCandidates.length)
    return new Error("No replica set members available for query");

  // find lowest server with a ping time
  var lowest = finalCandidates.filter(function (server) {
    return undefined != server.runtimeStats.pingMs;
  })[0];

  if(!lowest) {
    lowest = finalCandidates[0];
  }

  // convert to integer
  var lowestPing = lowest.runtimeStats.pingMs | 0;
  
  // determine acceptable latency
  var acceptable = lowestPing + this.secondaryAcceptableLatencyMS;

  // remove any server responding slower than acceptable
  var len = finalCandidates.length;
  while(len--) {
    if(finalCandidates[len].runtimeStats['pingMs'] > acceptable) {
      finalCandidates.splice(len, 1);
    }
  }

  if(self.logger && self.logger.debug) {    
    self.logger.debug("Ping strategy selection order for tags", tags);
    finalCandidates.forEach(function(c) {
      self.logger.debug(format("%s:%s = %s ms", c.host, c.port, c.runtimeStats['pingMs']), null);
    })    
  }

  // If no candidates available return an error
  if(finalCandidates.length == 0)
    return new Error("No replica set members available for query");

  // Ensure no we don't overflow
  this.index = this.index % finalCandidates.length
  // Pick a random acceptable server  
  var connection = finalCandidates[this.index].checkoutReader();
  // Point to next candidate (round robin style)
  this.index = this.index + 1;

  if(self.logger && self.logger.debug) {    
    if(connection)
      self.logger.debug("picked server %s:%s", connection.socketOptions.host, connection.socketOptions.port);
  }

  return connection;
}

PingStrategy.prototype._pingServer = function(callback) {
  var self = this;

  // Ping server function
  var pingFunction = function() {
    // Our state changed to disconnected or destroyed return
    if(self.state == 'disconnected' || self.state == 'destroyed') return;
    // If the replicaset is destroyed return
    if(self.replicaset.isDestroyed() || self.replicaset._serverState == 'disconnected') return

    // Create a list of all servers we can send the ismaster command to
    var allServers = self.replicaset._state.master != null ? [self.replicaset._state.master] : [];

    // Secondary keys
    var keys = Object.keys(self.replicaset._state.secondaries);
    // Add all secondaries
    for(var i = 0; i < keys.length; i++) {
      allServers.push(self.replicaset._state.secondaries[keys[i]]);
    }

    // Number of server entries
    var numberOfEntries = allServers.length;

    // We got keys
    for(var i = 0; i < allServers.length; i++) {

      // We got a server instance
      var server = allServers[i];

      // Create a new server object, avoid using internal connections as they might
      // be in an illegal state
      new function(serverInstance) {
        var _db = self.dbs[serverInstance.host + ":" + serverInstance.port];
        // If we have a db
        if(_db != null) {
          // Startup time of the command
          var startTime = Date.now();

          // Execute ping command in own scope
          var _ping = function(__db, __serverInstance) {
            // Execute ping on this connection
            __db.executeDbCommand({ping:1}, {failFast:true}, function(err) {
              if(err) {
                delete self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port];
                __db.close();
                return done();
              }

              if(null != __serverInstance.runtimeStats && __serverInstance.isConnected()) {
                __serverInstance.runtimeStats['pingMs'] = Date.now() - startTime;
              }

              __db.executeDbCommand({ismaster:1}, {failFast:true}, function(err, result) {
                if(err) {
                  delete self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port];
                  __db.close();
                  return done();
                }

                // Process the ismaster for the server
                if(result && result.documents && self.replicaset.processIsMaster) {
                  self.replicaset.processIsMaster(__serverInstance, result.documents[0]);
                }

                // Done with the pinging
                done();
              });
            });            
          };
          // Ping
          _ping(_db, serverInstance);
        } else {
          var connectTimeoutMS = self.replicaset.options.socketOptions 
            ? self.replicaset.options.socketOptions.connectTimeoutMS : 0

          // Create a new master connection
          var _server = new Server(serverInstance.host, serverInstance.port, {
            auto_reconnect: false,
            returnIsMasterResults: true,
            slaveOk: true,
            poolSize: 1,
            socketOptions: { connectTimeoutMS: connectTimeoutMS },
            ssl: self.replicaset.ssl,
            sslValidate: self.replicaset.sslValidate,
            sslCA: self.replicaset.sslCA,
            sslCert: self.replicaset.sslCert,
            sslKey: self.replicaset.sslKey,
            sslPass: self.replicaset.sslPass
          });

          // Create Db instance        
          var _db = new self.Db('local', _server, { safe: true });
          _db.on("close", function() {
            delete self.dbs[this.serverConfig.host + ":" + this.serverConfig.port];
          })

          var _ping = function(__db, __serverInstance) {
            if(self.state == 'disconnected') {
              self.stop();
              return;
            }

            __db.open(function(err, db) {              
              if(self.state == 'disconnected' && __db != null) {
                return __db.close();
              }

              if(err) {
                delete self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port];
                __db.close();
                return done();
              }

              // Save instance
              self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port] = __db;

              // Startup time of the command
              var startTime = Date.now();

              // Execute ping on this connection
              __db.executeDbCommand({ping:1}, {failFast:true}, function(err) {
                if(err) {
                  delete self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port];
                  __db.close();
                  return done();
                }

                if(null != __serverInstance.runtimeStats && __serverInstance.isConnected()) {
                  __serverInstance.runtimeStats['pingMs'] = Date.now() - startTime;
                }

                __db.executeDbCommand({ismaster:1}, {failFast:true}, function(err, result) {
                  if(err) {
                    delete self.dbs[__db.serverConfig.host + ":" + __db.serverConfig.port];
                    __db.close();
                    return done();
                  }
    
                  // Process the ismaster for the server
                  if(result && result.documents && self.replicaset.processIsMaster) {
                    self.replicaset.processIsMaster(__serverInstance, result.documents[0]);
                  }

                  // Done with the pinging
                  done();
                });
              });
            });            
          };

          // Ping the server
          _ping(_db, serverInstance);
        }

        function done() {
          // Adjust the number of checks
          numberOfEntries--;

          // If we are done with all results coming back trigger ping again
          if(0 === numberOfEntries && 'connected' == self.state) {
            setTimeout(pingFunction, self.pingInterval);
          }
        }
      }(server);
    }
  }

  // Start pingFunction
  pingFunction();

  callback && callback(null);
}
