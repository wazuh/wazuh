/**
 * Interval state object constructor
 *
 * @ignore
 */
var ReplSetState = function ReplSetState () {
  this.errorMessages = [];
  this.secondaries = {};
  this.addresses = {};
  this.arbiters = {};
  this.passives = {};
  this.members = [];
  this.errors = {};
  this.setName = null;
  this.master = null;
}

ReplSetState.prototype.hasValidServers = function() {
  var validServers = [];
  if(this.master && this.master.isConnected()) return true;

  if(this.secondaries) {
    var keys = Object.keys(this.secondaries)
    for(var i = 0; i < keys.length; i++) {
      if(this.secondaries[keys[i]].isConnected())
        return true;
    }
  }

  return false;
}

ReplSetState.prototype.getAllReadServers = function() {
  var candidate_servers = [];
  for(var name in this.addresses) {
    candidate_servers.push(this.addresses[name]);
  }

  // Return all possible read candidates
  return candidate_servers;
}

ReplSetState.prototype.addServer = function(server, master) {
  server.name = master.me;

  if(master.ismaster) {
    this.master = server;
    this.addresses[server.name] = server;
  } else if(master.secondary) {
    this.secondaries[server.name] = server;
    this.addresses[server.name] = server;
  } else if(master.arbiters) {
    this.arbiters[server.name] = server;
    this.addresses[server.name] = server;
  }
}

ReplSetState.prototype.contains = function(host) {
  return this.addresses[host] != null;
}

ReplSetState.prototype.isPrimary = function(server) {
  return this.master && this.master.name == server.name;
}

ReplSetState.prototype.isSecondary = function(server) {
  return this.secondaries[server.name] != null;
}

exports.ReplSetState = ReplSetState;
