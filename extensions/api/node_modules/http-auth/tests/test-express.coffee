# Request library.
request = require 'request'

# express library.
express = require 'express'

# Authentication library.
auth = require '../gensrc/http-auth'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    basic = auth.basic { # Configure authentication.
      realm: "Private Area.",
      file: __dirname + "/../data/users.htpasswd"
    }

    # Creating new HTTP server.
    app = express()
    app.use(auth.connect basic)
    
    # Setup route.
    app.get '/', (req, res) ->
      res.send "Hello from express - #{req.user}!"
    # Start server.
    @server = app.listen 1337
    callback()
  
  # After each test.
  tearDown: (callback) ->
    @server.close() # Stop server.    
    callback()
  
  # Correct encrypted details.
  testSuccess: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Hello from express - gevorg!"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'gevorg', 'gpass'
  
  # Correct plain details.
  testSuccessPlain: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Hello from express - Sarah!"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'Sarah', 'testpass'
    
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'gevorg', 'duck'
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'solomon', 'gpass'