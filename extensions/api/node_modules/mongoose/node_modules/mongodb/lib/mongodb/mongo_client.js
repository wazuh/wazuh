var Db = require('./db').Db
  , Server = require('./connection/server').Server
  , Mongos = require('./connection/mongos').Mongos
  , ReplSet = require('./connection/repl_set/repl_set').ReplSet
  , ReadPreference = require('./connection/read_preference').ReadPreference
  , inherits = require('util').inherits
  , EventEmitter = require('events').EventEmitter
  , parse = require('./connection/url_parser').parse;

/**
 * Create a new MongoClient instance.
 *
 * Options
 *  - **w**, {Number/String, > -1 || 'majority' || tag name} the write concern for the operation where < 1 is no acknowlegement of write and w >= 1, w = 'majority' or tag acknowledges the write
 *  - **wtimeout**, {Number, 0} set the timeout for waiting for write concern to finish (combines with w option)
 *  - **fsync**, (Boolean, default:false) write waits for fsync before returning
 *  - **journal**, (Boolean, default:false) write waits for journal sync before returning
 *  - **readPreference** {String}, the prefered read preference (ReadPreference.PRIMARY, ReadPreference.PRIMARY_PREFERRED, ReadPreference.SECONDARY, ReadPreference.SECONDARY_PREFERRED, ReadPreference.NEAREST).
 *  - **native_parser** {Boolean, default:false}, use c++ bson parser.
 *  - **forceServerObjectId** {Boolean, default:false}, force server to create _id fields instead of client.
 *  - **pkFactory** {Object}, object overriding the basic ObjectID primary key generation.
 *  - **serializeFunctions** {Boolean, default:false}, serialize functions.
 *  - **raw** {Boolean, default:false}, peform operations using raw bson buffers.
 *  - **recordQueryStats** {Boolean, default:false}, record query statistics during execution.
 *  - **retryMiliSeconds** {Number, default:5000}, number of miliseconds between retries.
 *  - **numberOfRetries** {Number, default:5}, number of retries off connection.
 * 
 * Deprecated Options 
 *  - **safe** {true | {w:n, wtimeout:n} | {fsync:true}, default:false}, executes with a getLastError command returning the results of the command on MongoDB.
 *
 * @class Represents a MongoClient
 * @param {Object} serverConfig server config object.
 * @param {Object} [options] additional options for the collection.
 */
function MongoClient(serverConfig, options) {
  if(serverConfig != null) {
    options = options == null ? {} : options;
    // If no write concern is set set the default to w:1
    if(options != null && !options.journal && !options.w && !options.fsync) {
      options.w = 1;
    }
    
    // The internal db instance we are wrapping
    this._db = new Db('test', serverConfig, options);    
  }
}

/**
 * @ignore
 */
inherits(MongoClient, EventEmitter);

/**
 * Connect to MongoDB using a url as documented at
 *
 *  docs.mongodb.org/manual/reference/connection-string/
 *
 * Options
 *  - **uri_decode_auth** {Boolean, default:false} uri decode the user name and password for authentication
 *  - **db** {Object, default: null} a hash off options to set on the db object, see **Db constructor**
 *  - **server** {Object, default: null} a hash off options to set on the server objects, see **Server** constructor**
 *  - **replSet** {Object, default: null} a hash off options to set on the replSet object, see **ReplSet** constructor**
 *  - **mongos** {Object, default: null} a hash off options to set on the mongos object, see **Mongos** constructor**
 *
 * @param {String} url connection url for MongoDB.
 * @param {Object} [options] optional options for insert command
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the initialized db object or null if an error occured.
 * @return {null}
 * @api public
 */
MongoClient.prototype.connect = function(url, options, callback) {
  var self = this;

  if(typeof options == 'function') {
    callback = options;
    options = {};
  }

  MongoClient.connect(url, options, function(err, db) {
    if(err) return callback(err, db);
    // Store internal db instance reference
    self._db = db;
    // Emit open and perform callback
    self.emit("open", err, db);
    callback(err, db);
  });
}

/**
 * Initialize the database connection.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the connected mongoclient or null if an error occured.
 * @return {null}
 * @api public
 */
MongoClient.prototype.open = function(callback) {
  // Self reference
  var self = this;
  // Open the db
  this._db.open(function(err, db) {
    if(err) return callback(err, null);
    // Emit open event
    self.emit("open", err, db);
    // Callback
    callback(null, self);
  })
}

/**
 * Close the current db connection, including all the child db instances. Emits close event if no callback is provided.
 *
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the results from the close method or null if an error occured.
 * @return {null}
 * @api public
 */
MongoClient.prototype.close = function(callback) {
  this._db.close(callback);
}

/**
 * Create a new Db instance sharing the current socket connections.
 *
 * @param {String} dbName the name of the database we want to use.
 * @return {Db} a db instance using the new database.
 * @api public
 */
MongoClient.prototype.db = function(dbName) {
  return this._db.db(dbName);
}

/**
 * Connect to MongoDB using a url as documented at
 *
 *  docs.mongodb.org/manual/reference/connection-string/
 *
 * Options
 *  - **uri_decode_auth** {Boolean, default:false} uri decode the user name and password for authentication
 *  - **db** {Object, default: null} a hash off options to set on the db object, see **Db constructor**
 *  - **server** {Object, default: null} a hash off options to set on the server objects, see **Server** constructor**
 *  - **replSet** {Object, default: null} a hash off options to set on the replSet object, see **ReplSet** constructor**
 *  - **mongos** {Object, default: null} a hash off options to set on the mongos object, see **Mongos** constructor**
 *
 * @param {String} url connection url for MongoDB.
 * @param {Object} [options] optional options for insert command
 * @param {Function} callback this will be called after executing this method. The first parameter will contain the Error object if an error occured, or null otherwise. While the second parameter will contain the initialized db object or null if an error occured.
 * @return {null}
 * @api public
 */
MongoClient.connect = function(url, options, callback) {
  var args = Array.prototype.slice.call(arguments, 1);
  callback = typeof args[args.length - 1] == 'function' ? args.pop() : null;
  options = args.length ? args.shift() : null;
  options = options || {};

  // Set default empty server options  
  var serverOptions = options.server || {};
  var mongosOptions = options.mongos || {};
  var replSetServersOptions = options.replSet || options.replSetServers || {};
  var dbOptions = options.db || {};

  // If callback is null throw an exception
  if(callback == null) 
    throw new Error("no callback function provided");

  // Parse the string
  var object = parse(url, options);
  // Merge in any options for db in options object
  if(dbOptions) {
    for(var name in dbOptions) object.db_options[name] = dbOptions[name];
  }

  // Added the url to the options
  object.db_options.url = url;

  // Merge in any options for server in options object
  if(serverOptions) {
    for(var name in serverOptions) object.server_options[name] = serverOptions[name];
  }

  // Merge in any replicaset server options
  if(replSetServersOptions) {
    for(var name in replSetServersOptions) object.rs_options[name] = replSetServersOptions[name];    
  }

  // Merge in any replicaset server options
  if(mongosOptions) {
    for(var name in mongosOptions) object.mongos_options[name] = mongosOptions[name];    
  }

  // We need to ensure that the list of servers are only either direct members or mongos
  // they cannot be a mix of monogs and mongod's
  var totalNumberOfServers = object.servers.length;
  var totalNumberOfMongosServers = 0;
  var totalNumberOfMongodServers = 0;
  var serverConfig = null;
  var errorServers = {};

  // Failure modes
  if(object.servers.length == 0) throw new Error("connection string must contain at least one seed host");

  // If we have no db setting for the native parser try to set the c++ one first
  object.db_options.native_parser = _setNativeParser(object.db_options);
  // If no auto_reconnect is set, set it to true as default for single servers
  if(typeof object.server_options.auto_reconnect != 'boolean') {
    object.server_options.auto_reconnect = true;
  }

  // If we have more than a server, it could be replicaset or mongos list
  // need to verify that it's one or the other and fail if it's a mix
  // Connect to all servers and run ismaster
  for(var i = 0; i < object.servers.length; i++) {
    // Set up socket options
    var _server_options = {poolSize:1, socketOptions:{connectTimeoutMS:1000}, auto_reconnect:false};

    // Ensure we have ssl setup for the servers
    if(object.rs_options.ssl) {
      _server_options.ssl = object.rs_options.ssl;
      _server_options.sslValidate = object.rs_options.sslValidate;
      _server_options.sslCA = object.rs_options.sslCA;
      _server_options.sslCert = object.rs_options.sslCert;
      _server_options.sslKey = object.rs_options.sslKey;
      _server_options.sslPass = object.rs_options.sslPass;
    } else if(object.server_options.ssl) {
      _server_options.ssl = object.server_options.ssl;
      _server_options.sslValidate = object.server_options.sslValidate;
      _server_options.sslCA = object.server_options.sslCA;
      _server_options.sslCert = object.server_options.sslCert;
      _server_options.sslKey = object.server_options.sslKey;
      _server_options.sslPass = object.server_options.sslPass;
    }

    // Set up the Server object
    var _server = object.servers[i].domain_socket 
        ? new Server(object.servers[i].domain_socket, _server_options)
        : new Server(object.servers[i].host, object.servers[i].port, _server_options);

    var connectFunction = function(__server) { 
      // Attempt connect
      new Db(object.dbName, __server, {safe:false, native_parser:false}).open(function(err, db) {
        // Update number of servers
        totalNumberOfServers = totalNumberOfServers - 1;          
        // If no error do the correct checks
        if(!err) {
          // Close the connection
          db.close(true);
          var isMasterDoc = db.serverConfig.isMasterDoc;
          // Check what type of server we have
          if(isMasterDoc.setName) totalNumberOfMongodServers++;
          if(isMasterDoc.msg && isMasterDoc.msg == "isdbgrid") totalNumberOfMongosServers++;
        } else {
          errorServers[__server.host + ":" + __server.port] = __server;
        }

        if(totalNumberOfServers == 0) {
          // If we have a mix of mongod and mongos, throw an error
          if(totalNumberOfMongosServers > 0 && totalNumberOfMongodServers > 0) {
            return process.nextTick(function() {
              try {
                callback(new Error("cannot combine a list of replicaset seeds and mongos seeds"));
              } catch (err) {
                if(db) db.close();
                throw err
              }              
            })
          }
          
          if(totalNumberOfMongodServers == 0 && object.servers.length == 1) {
            var obj = object.servers[0];
            serverConfig = obj.domain_socket ? 
                new Server(obj.domain_socket, object.server_options)
              : new Server(obj.host, obj.port, object.server_options);            
          } else if(totalNumberOfMongodServers > 0 || totalNumberOfMongosServers > 0) {
            var finalServers = object.servers
              .filter(function(serverObj) {
                return errorServers[serverObj.host + ":" + serverObj.port] == null;
              })
              .map(function(serverObj) {
                  return new Server(serverObj.host, serverObj.port, object.server_options);
              });
            // Clean out any error servers
            errorServers = {};
            // Set up the final configuration
            if(totalNumberOfMongodServers > 0) {
              serverConfig = new ReplSet(finalServers, object.rs_options);                
            } else {
              serverConfig = new Mongos(finalServers, object.mongos_options);                         
            }
          }

          if(serverConfig == null) {
            return process.nextTick(function() {
              try {
                callback(new Error("Could not locate any valid servers in initial seed list"));
              } catch (err) {
                if(db) db.close();
                throw err
              }
            });
          }
          // Ensure no firing off open event before we are ready
          serverConfig.emitOpen = false;
          // Set up all options etc and connect to the database
          _finishConnecting(serverConfig, object, options, callback)
        }
      });        
    }

    // Wrap the context of the call
    connectFunction(_server);    
  }    
}

var _setNativeParser = function(db_options) {
  if(typeof db_options.native_parser == 'boolean') return db_options.native_parser;

  try {
    require('bson').BSONNative.BSON;
    return true;
  } catch(err) {
    return false;
  }
}

var _finishConnecting = function(serverConfig, object, options, callback) {
  // Safe settings
  var safe = {};
  // Build the safe parameter if needed
  if(object.db_options.journal) safe.j = object.db_options.journal;
  if(object.db_options.w) safe.w = object.db_options.w;
  if(object.db_options.fsync) safe.fsync = object.db_options.fsync;
  if(object.db_options.wtimeoutMS) safe.wtimeout = object.db_options.wtimeoutMS;

  // If we have a read Preference set
  if(object.db_options.read_preference) {
    var readPreference = new ReadPreference(object.db_options.read_preference);
    // If we have the tags set up
    if(object.db_options.read_preference_tags)
      readPreference = new ReadPreference(object.db_options.read_preference, object.db_options.read_preference_tags);
    // Add the read preference
    object.db_options.readPreference = readPreference;
  }

  // No safe mode if no keys
  if(Object.keys(safe).length == 0) safe = false;

  // Add the safe object
  object.db_options.safe = safe;

  // Set up the db options
  var db = new Db(object.dbName, serverConfig, object.db_options);
  // Open the db
  db.open(function(err, db){
    if(err) {
      return process.nextTick(function() {
        try {
          callback(err, null);
        } catch (err) {
          if(db) db.close();
          throw err
        }
      });
    }

    if(db.options !== null && !db.options.safe && !db.options.journal 
      && !db.options.w && !db.options.fsync && typeof db.options.w != 'number'
      && (db.options.safe == false && object.db_options.url.indexOf("safe=") == -1)) {
        db.options.w = 1;
    }

    if(err == null && object.auth){
      // What db to authenticate against
      var authentication_db = db;
      if(object.db_options && object.db_options.authSource) {
        authentication_db = db.db(object.db_options.authSource);
      }

      // Build options object
      var options = {};
      if(object.db_options.authMechanism) options.authMechanism = object.db_options.authMechanism;
      if(object.db_options.gssapiServiceName) options.gssapiServiceName = object.db_options.gssapiServiceName;

      // Authenticate
      authentication_db.authenticate(object.auth.user, object.auth.password, options, function(err, success){
        if(success){
          process.nextTick(function() {
            try {
              callback(null, db);            
            } catch (err) {
              if(db) db.close();
              throw err
            }
          });
        } else {
          if(db) db.close();
          process.nextTick(function() {
            try {
              callback(err ? err : new Error('Could not authenticate user ' + auth[0]), null);
            } catch (err) {
              if(db) db.close();
              throw err
            }
          });
        }
      });
    } else {
      process.nextTick(function() {
        try {
          callback(err, db);            
        } catch (err) {
          if(db) db.close();
          throw err
        }
      })
    }
  });
}


exports.MongoClient = MongoClient;