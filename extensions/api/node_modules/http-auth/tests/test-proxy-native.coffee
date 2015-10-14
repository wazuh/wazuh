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
    # Create your proxy server.
    @proxy = (httpProxy.createServer { target: 'http://localhost:1338' }).listen 1337

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
    (request.get {proxy: 'http://127.0.0.1:1337', uri: 'http://127.0.0.1:1337'}, callback)