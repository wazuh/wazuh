# Request library.
request = require 'request'

# HTTP library.
http = require 'http'

# Proxy library.
httpProxy = require 'http-proxy'

# Authentication library.
auth = require '../gensrc/http-auth'

module.exports =
  
  # Before each test.
  setUp: (callback) ->
    basic = auth.basic { # Configure authentication.
      realm: "Private Area.",
      file: __dirname + "/../data/users.htpasswd"
    }

    # Create your proxy server.
    @proxy = (httpProxy.createServer basic, { target: 'http://localhost:1338' }).listen 1337

    # Create your target server.
    @server = http.createServer (req, res) ->
      res.end "Request successfully proxied!"
    # Start server.
    @server.listen 1338
    
    callback()
  
  # After each test.
  tearDown: (callback) ->
    @proxy.close() # Stop proxy.    
    @server.close() # Stop server.    
    callback()
  
  # Correct encrypted details.
  testSuccess: (test) ->
    callback = (error, response, body) -> # Callback.      
      test.equals body, "Request successfully proxied!"
      test.done()
      
    # Test request.    
    (request.get {proxy: 'http://gevorg:gpass@127.0.0.1:1337', uri: 'http://127.0.0.1:1337'}, callback)
  
  # Correct plain details.
  testSuccessPlain: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "Request successfully proxied!"
      test.done()
      
    # Test request.    
    (request.get {proxy: 'http://Sarah:testpass@127.0.0.1:1337', uri: 'http://127.0.0.1:1337'}, callback)
    
  # Wrong password.
  testWrongPassword: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "407 Proxy authentication required"
      test.done()
      
    # Test request.    
    (request.get {proxy: 'http://gevorg:duck@127.0.0.1:1337', uri: 'http://127.0.0.1:1337'}, callback)
    
  # Wrong user.
  testWrongUser: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "407 Proxy authentication required"
      test.done()
      
    # Test request.    
    (request.get {proxy: 'http://solomon:gpass@127.0.0.1:1337', uri: 'http://127.0.0.1:1337'}, callback)