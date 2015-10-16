# Request library.
request = require 'request'

# HTTPS library.
https = require 'https'

# File system library.
fs = require 'fs'

# Authentication library.
auth = require '../gensrc/http-auth'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    basic = auth.basic { # Configure authentication.
      realm: "Private Area.",
      file: __dirname + "/../data/users.htpasswd"
    }

    # HTTPS server options.
    options = {
      key: fs.readFileSync(__dirname + "/../data/key.pem"),
      cert: fs.readFileSync(__dirname + "/../data/cert.pem")
    }

    # Creating new HTTPS server.
    @server = https.createServer basic, options, (req, res) ->
      res.end "Welcome to private area - #{req.user}!"    
    # Start server.
    @server.listen 1337    
    callback()
  
  # After each test.
  tearDown: (callback) ->
    @server.close() # Stop server.    
    callback()
  
  # Correct encrypted details.
  testSuccess: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Welcome to private area - gevorg!"
      test.done()
      
    # Test request.    
    (request.get {uri: 'https://127.0.0.1:1337', strictSSL: false}, callback).auth 'gevorg', 'gpass'
  
  # Correct plain details.
  testSuccessPlain: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Welcome to private area - Sarah!"
      test.done()
      
    # Test request.    
    (request.get {uri: 'https://127.0.0.1:1337', strictSSL: false}, callback).auth 'Sarah', 'testpass'
    
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get {uri: 'https://127.0.0.1:1337', strictSSL: false}, callback).auth 'gevorg', 'duck'
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get {uri: 'https://127.0.0.1:1337', strictSSL: false}, callback).auth 'solomon', 'gpass'