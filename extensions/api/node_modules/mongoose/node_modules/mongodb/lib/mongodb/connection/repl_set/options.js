var PingStrategy = require('./strategies/ping_strategy').PingStrategy
  , StatisticsStrategy = require('./strategies/statistics_strategy').StatisticsStrategy
  , ReadPreference = require('../read_preference').ReadPreference;

var Options = function(options) {
  options = options || {};
  this._options = options;
  this.ha = options.ha || true;
  this.haInterval = options.haInterval || 2000;
  this.reconnectWait = options.reconnectWait || 1000;
  this.retries = options.retries || 30;
  this.rs_name = options.rs_name;
  this.socketOptions = options.socketOptions || {};
  this.readPreference = options.readPreference;
  this.readSecondary = options.read_secondary;
  this.poolSize = options.poolSize == null ? 5 : options.poolSize;
  this.strategy = options.strategy || 'ping';
  this.secondaryAcceptableLatencyMS = options.secondaryAcceptableLatencyMS || 15;
  this.connectArbiter = options.connectArbiter || false;
  this.connectWithNoPrimary = options.connectWithNoPrimary || false;
  this.logger = options.logger;
  this.ssl = options.ssl || false;
  this.sslValidate = options.sslValidate || false;
  this.sslCA = options.sslCA;
  this.sslCert = options.sslCert;
  this.sslKey = options.sslKey;
  this.sslPass = options.sslPass;
  this.emitOpen = options.emitOpen || true;
}

Options.prototype.init = function() {
  if(this.sslValidate && (!Array.isArray(this.sslCA) || this.sslCA.length == 0)) {
    throw new Error("The driver expects an Array of CA certificates in the sslCA parameter when enabling sslValidate");
  }  

  // Make sure strategy is one of the two allowed
  if(this.strategy != null && (this.strategy != 'ping' && this.strategy != 'statistical' && this.strategy != 'none')) 
      throw new Error("Only ping or statistical strategies allowed");    
  
  if(this.strategy == null) this.strategy = 'ping';
  
  // Set logger if strategy exists
  if(this.strategyInstance) this.strategyInstance.logger = this.logger;

  // Unpack read Preference
  var readPreference = this.readPreference;
  // Validate correctness of Read preferences
  if(readPreference != null) {
    if(readPreference != ReadPreference.PRIMARY && readPreference != ReadPreference.PRIMARY_PREFERRED
      && readPreference != ReadPreference.SECONDARY && readPreference != ReadPreference.SECONDARY_PREFERRED
      && readPreference != ReadPreference.NEAREST && typeof readPreference != 'object' && readPreference['_type'] != 'ReadPreference') {
      throw new Error("Illegal readPreference mode specified, " + readPreference);
    }

    this.readPreference = readPreference;
  } else {
    this.readPreference = null;
  } 

     // Ensure read_secondary is set correctly
  if(this.readSecondary != null)
    this.readSecondary = this.readPreference == ReadPreference.PRIMARY 
        || this.readPreference == false  
        || this.readPreference == null ? false : true;

  // Ensure correct slave set
  if(this.readSecondary) this.slaveOk = true;

  // Set up logger if any set
  this.logger = this.logger != null
    && (typeof this.logger.debug == 'function')
    && (typeof this.logger.error == 'function')
    && (typeof this.logger.debug == 'function')
      ? this.logger : {error:function(message, object) {}, log:function(message, object) {}, debug:function(message, object) {}};  

  // Connection timeout
  this.connectTimeoutMS = this.socketOptions.connectTimeoutMS
    ? this.socketOptions.connectTimeoutMS
    : 1000;

  // Socket connection timeout
  this.socketTimeoutMS = this.socketOptions.socketTimeoutMS
    ? this.socketOptions.socketTimeoutMS
    : 30000;
}

Options.prototype.decorateAndClean = function(servers, callBackStore) {
  var self = this;

  // var de duplicate list
  var uniqueServers = {};
  // De-duplicate any servers in the seed list
  for(var i = 0; i < servers.length; i++) {
    var server = servers[i];
    // If server does not exist set it
    if(uniqueServers[server.host + ":" + server.port] == null) {
      uniqueServers[server.host + ":" + server.port] = server;
    }
  }

  // Let's set the deduplicated list of servers
  var finalServers = [];
  // Add the servers
  for(var key in uniqueServers) {
    finalServers.push(uniqueServers[key]);
  }

  finalServers.forEach(function(server) {
    // Ensure no server has reconnect on
    server.options.auto_reconnect = false;
    // Set up ssl options
    server.ssl = self.ssl;
    server.sslValidate = self.sslValidate;
    server.sslCA = self.sslCA;
    server.sslCert = self.sslCert;
    server.sslKey = self.sslKey;
    server.sslPass = self.sslPass;
    server.poolSize = self.poolSize;
    // Set callback store
    server._callBackStore = callBackStore;
  });

  return finalServers;
}

exports.Options = Options;
