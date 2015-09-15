var fs = require('fs'),
  ReadPreference = require('./read_preference').ReadPreference;

exports.parse = function(url, options) {
  // Ensure we have a default options object if none set
  options = options || {};
  // Variables
  var connection_part = '';
  var auth_part = '';
  var query_string_part = '';
  var dbName = 'admin';

  // Must start with mongodb
  if(url.indexOf("mongodb://") != 0)
    throw Error("URL must be in the format mongodb://user:pass@host:port/dbname");
  // If we have a ? mark cut the query elements off
  if(url.indexOf("?") != -1) {
    query_string_part = url.substr(url.indexOf("?") + 1);
    connection_part = url.substring("mongodb://".length, url.indexOf("?"))
  } else {
    connection_part = url.substring("mongodb://".length);
  }

  // Check if we have auth params
  if(connection_part.indexOf("@") != -1) {
    auth_part = connection_part.split("@")[0];
    connection_part = connection_part.split("@")[1];
  }

  // Check if the connection string has a db
  if(connection_part.indexOf(".sock") != -1) {
    if(connection_part.indexOf(".sock/") != -1) {
      dbName = connection_part.split(".sock/")[1];
      connection_part = connection_part.split("/", connection_part.indexOf(".sock") + ".sock".length);
    } 
  } else if(connection_part.indexOf("/") != -1) {
    dbName = connection_part.split("/")[1];
    connection_part = connection_part.split("/")[0];
  }

  // Result object
  var object = {};

  // Pick apart the authentication part of the string
  var authPart = auth_part || '';
  var auth = authPart.split(':', 2);
  if(options['uri_decode_auth']){
    auth[0] = decodeURIComponent(auth[0]);
    if(auth[1]){
      auth[1] = decodeURIComponent(auth[1]);
    }
  }

  // Add auth to final object if we have 2 elements
  if(auth.length == 2) object.auth = {user: auth[0], password: auth[1]};

  // Variables used for temporary storage
  var hostPart;
  var urlOptions;
  var servers;
  var serverOptions = {socketOptions: {}};
  var dbOptions = {read_preference_tags: []};
  var replSetServersOptions = {socketOptions: {}};
  // Add server options to final object
  object.server_options = serverOptions;
  object.db_options = dbOptions;
  object.rs_options = replSetServersOptions;
  object.mongos_options = {};

  // Let's check if we are using a domain socket
  if(url.match(/\.sock/)) {
    // Split out the socket part
    var domainSocket = url.substring(
        url.indexOf("mongodb://") + "mongodb://".length
      , url.lastIndexOf(".sock") + ".sock".length);
    // Clean out any auth stuff if any
    if(domainSocket.indexOf("@") != -1) domainSocket = domainSocket.split("@")[1];
    servers = [{domain_socket: domainSocket}];
  } else {
    // Split up the db
    hostPart = connection_part;
    // Parse all server results
    servers = hostPart.split(',').map(function(h) {
      var hostPort = h.split(':', 2);
      var _host = hostPort[0] || 'localhost';
      var _port = hostPort[1] != null ? parseInt(hostPort[1], 10) : 27017;
      // Check for localhost?safe=true style case
      if(_host.indexOf("?") != -1) _host = _host.split(/\?/)[0];

      // Return the mapped object
      return {host: _host, port: _port};
    });
  }

  // Get the db name
  object.dbName = dbName || 'admin';
  // Split up all the options
  urlOptions = (query_string_part || '').split(/[&;]/);    
  // Ugh, we have to figure out which options go to which constructor manually.
  urlOptions.forEach(function(opt) {
    if(!opt) return;
    var splitOpt = opt.split('='), name = splitOpt[0], value = splitOpt[1];
    // Options implementations
    switch(name) {
      case 'slaveOk':
      case 'slave_ok':
        serverOptions.slave_ok = (value == 'true');
        dbOptions.slaveOk = (value == 'true');
        break;
      case 'maxPoolSize':
      case 'poolSize':
        serverOptions.poolSize = parseInt(value, 10);
        replSetServersOptions.poolSize = parseInt(value, 10);
        break;
      case 'autoReconnect':
      case 'auto_reconnect':
        serverOptions.auto_reconnect = (value == 'true');
        break;
      case 'minPoolSize':
        throw new Error("minPoolSize not supported");
      case 'maxIdleTimeMS':
        throw new Error("maxIdleTimeMS not supported");
      case 'waitQueueMultiple':
        throw new Error("waitQueueMultiple not supported");
      case 'waitQueueTimeoutMS':
        throw new Error("waitQueueTimeoutMS not supported");
      case 'uuidRepresentation':
        throw new Error("uuidRepresentation not supported");
      case 'ssl':
        if(value == 'prefer') {
          serverOptions.ssl = value;
          replSetServersOptions.ssl = value;
          break;
        }
        serverOptions.ssl = (value == 'true');
        replSetServersOptions.ssl = (value == 'true');
        break;
      case 'replicaSet':
      case 'rs_name':
        replSetServersOptions.rs_name = value;
        break;
      case 'reconnectWait':
        replSetServersOptions.reconnectWait = parseInt(value, 10);
        break;
      case 'retries':
        replSetServersOptions.retries = parseInt(value, 10);
        break;
      case 'readSecondary':
      case 'read_secondary':
        replSetServersOptions.read_secondary = (value == 'true');
        break;
      case 'fsync':
        dbOptions.fsync = (value == 'true');
        break;
      case 'journal':
        dbOptions.journal = (value == 'true');
        break;
      case 'safe':
        dbOptions.safe = (value == 'true');
        break;
      case 'nativeParser':
      case 'native_parser':
        dbOptions.native_parser = (value == 'true');
        break;
      case 'connectTimeoutMS':
        serverOptions.socketOptions.connectTimeoutMS = parseInt(value, 10);
        replSetServersOptions.socketOptions.connectTimeoutMS = parseInt(value, 10);
        break;
      case 'socketTimeoutMS':
        serverOptions.socketOptions.socketTimeoutMS = parseInt(value, 10);
        replSetServersOptions.socketOptions.socketTimeoutMS = parseInt(value, 10);
        break;
      case 'w':
        dbOptions.w = parseInt(value, 10);
        break;
      case 'authSource':
        dbOptions.authSource = value;
        break;
      case 'gssapiServiceName':
        dbOptions.gssapiServiceName = value;
        break;
      case 'authMechanism':
        if(value == 'GSSAPI') {
          // If no password provided decode only the principal
          if(object.auth == null) {
            var urlDecodeAuthPart = decodeURIComponent(authPart);
            if(urlDecodeAuthPart.indexOf("@") == -1) throw new Error("GSSAPI requires a provided principal");
            object.auth = {user: urlDecodeAuthPart, password: null};
          } else {
            object.auth.user = decodeURIComponent(object.auth.user);
          }
        }
        
        // Only support GSSAPI or MONGODB-CR for now
        if(value != 'GSSAPI' 
          && value != 'MONGODB-CR'
          && value != 'PLAIN') 
            throw new Error("only GSSAPI, PLAIN or MONGODB-CR is supported by authMechanism");
        
        // Authentication mechanism
        dbOptions.authMechanism = value;
        break;
      case 'wtimeoutMS':
        dbOptions.wtimeoutMS = parseInt(value, 10);
        break;
      case 'readPreference':
        if(!ReadPreference.isValid(value)) throw new Error("readPreference must be either primary/primaryPreferred/secondary/secondaryPreferred/nearest");
        dbOptions.read_preference = value;
        break;
      case 'readPreferenceTags':
        // Contains the tag object
        var tagObject = {};
        if(value == null || value == '') {
          dbOptions.read_preference_tags.push(tagObject);
          break;
        }

        // Split up the tags
        var tags = value.split(/\,/);
        for(var i = 0; i < tags.length; i++) {
          var parts = tags[i].trim().split(/\:/);
          tagObject[parts[0]] = parts[1];
        }

        // Set the preferences tags
        dbOptions.read_preference_tags.push(tagObject);
        break;
      default:
        break;
    }
  });

  // No tags: should be null (not [])
  if(dbOptions.read_preference_tags.length === 0) {
    dbOptions.read_preference_tags = null;
  }

  // Validate if there are an invalid write concern combinations
  if((dbOptions.w == -1 || dbOptions.w == 0) && (
      dbOptions.journal == true
      || dbOptions.fsync == true
      || dbOptions.safe == true)) throw new Error("w set to -1 or 0 cannot be combined with safe/w/journal/fsync")

  // If no read preference set it to primary
  if(!dbOptions.read_preference) dbOptions.read_preference = 'primary';

  // Add servers to result
  object.servers = servers;
  // Returned parsed object
  return object;
}
