# Request library.
request = require 'request'

# HTTP library.
http = require 'http'

# Authentication library.
auth = require '../gensrc/http-auth'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    basic = auth.basic { # Configure authentication.
        realm: "Private Area."
      }, 
      (username, password, callback) =>
        success = (username is "mia" and password is "supergirl") or
                  (username is "ColonUser" and password is "apasswordwith:acolon")
        callback.apply this, [success]

    # Creating new HTTP server.
    @server = http.createServer basic, (req, res) ->
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
      test.equals body, "Welcome to private area - mia!"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'mia', 'supergirl'
      
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'mia', 'cute'
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "401 Unauthorized"
      test.done()
      
    # Test request.    
    (request.get 'http://127.0.0.1:1337', callback).auth 'Tina', 'supergirl'

  # Passwords containing colons
  testColonPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Welcome to private area - ColonUser!"
      test.done()

    # Test request.
    (request.get 'http://127.0.0.1:1337', callback).auth 'ColonUser', 'apasswordwith:acolon'