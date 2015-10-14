# Request library.
request = require 'request'

# HTTP library.
http = require 'http'

# Authentication library.
auth = require '../gensrc/http-auth'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    digest = auth.digest { # Configure authentication.
      algorithm: 'MD5-sess',
      realm: "Simon Area.",
      file: __dirname + "/../data/users.htdigest"
    }

    # Creating new HTTP server.
    @server = http.createServer digest, (req, res) ->
      res.end "Welcome to private area - #{req.user}!"    
    # Start server.
    @server.listen 1337    
    callback()
  
  # After each test.
  tearDown: (callback) ->
    @server.close() # Stop server.    
    callback()
  
  # Correct details.
  testSuccess: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Welcome to private area - vivi!"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'vivi', 'anna', false
      
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'vivi', 'goose', false
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'brad', 'anna', false