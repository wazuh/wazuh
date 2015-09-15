/**
  Base object used for common functionality
**/
var BaseCommand = exports.BaseCommand = function BaseCommand() {
};

var id = 1;
BaseCommand.prototype.getRequestId = function getRequestId() {
  if (!this.requestId) this.requestId = id++;
  return this.requestId;
};

BaseCommand.prototype.setMongosReadPreference = function setMongosReadPreference(readPreference, tags) {}

BaseCommand.prototype.updateRequestId = function() {
  this.requestId = id++;
  return this.requestId;
};

// OpCodes
BaseCommand.OP_REPLY = 1;
BaseCommand.OP_MSG = 1000;
BaseCommand.OP_UPDATE = 2001;
BaseCommand.OP_INSERT =	2002;
BaseCommand.OP_GET_BY_OID = 2003;
BaseCommand.OP_QUERY = 2004;
BaseCommand.OP_GET_MORE = 2005;
BaseCommand.OP_DELETE =	2006;
BaseCommand.OP_KILL_CURSORS =	2007;