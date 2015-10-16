# Request library.
request = require 'request'

# HTTP library.
http = require 'http'

# Authentication library.
auth = require '../gensrc/http-auth'

# Utility library.
utils = require '../gensrc/auth/utils'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    digest = auth.digest { # Configure authentication.
        realm: "Simon Area.",
        file: __dirname + "/../data/users.htdigest"
      }, 
      (username, callback) -> # Expecting md5(username:realm:password) in callback.   
        if username is "simon"
          callback (utils.md5 "simon:Simon Area.:smart")
        else
          callback()

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
      test.equals body, "Welcome to private area - simon!"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'simon', 'smart', false

  # Correct with comma URI details.
  testSuccessCommaURI: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Welcome to private area - simon!"
      test.done()

    # Test request.
    (request.get 'http://127.0.0.1:1337/comma,/', callback).auth 'simon', 'smart', false
      
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'simon', 'woolf', false
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'virgina', 'smart', false