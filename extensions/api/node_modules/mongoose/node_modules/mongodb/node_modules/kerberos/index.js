// Get the Kerberos library
module.exports = require('./lib/kerberos');
// Set up the auth processes
module.exports['processes'] = {
  MongoAuthProcess: require('./lib/auth_processes/mongodb').MongoAuthProcess
}