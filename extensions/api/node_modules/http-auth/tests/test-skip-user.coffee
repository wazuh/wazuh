# Request library.
request = require 'request'

# HTTP library.
http = require 'http'

# Authentication library.
auth = require '../gensrc/http-auth'

# htpasswd verification is reused.
htpasswd = require 'htpasswd'

module.exports =

  # Before each test.
  setUp: (callback) ->
    basic = auth.basic { # Configure authentication.
      realm: "Private Area.",
      file: __dirname + "/../data/users.htpasswd",
      skipUser: true
    }

    # Creating new HTTP server.
    @server = http.createServer basic, (req, res) ->
      res.end "req.user is #{req.user}!"

    # Start server.
    @server.listen 1337
    callback()

  # After each test.
  tearDown: (callback) ->
    @server.close() # Stop server.
    callback()


  # Correct plain details.
  testSuccessPlain: (test) ->
    callback = (error, response, body) -> # Callback.
      test.equals body, "req.user is undefined!"
      test.done()

    # Test request.
    (request.get 'http://127.0.0.1:1337', callback).auth 'Sarah', 'testpass'
