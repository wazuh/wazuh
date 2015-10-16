# HTTP module.
http = require 'http'

# Base module.
Base = require '../auth/base'

# Backup old server creation.
oldCreateServer = http.createServer

# Add authentication method.
http.createServer = () ->
  if arguments[0] instanceof Base # Mutated mode.
    authentication = arguments[0]
        
    if arguments[1] # With listener.
      listener = arguments[1]
      newListener = (req, res) ->
        authentication.check req, res, listener
      
      server = oldCreateServer.apply http, [newListener]
    else # Without.
      server = oldCreateServer.apply http, []
      server.on 'request', (req, res) ->
        authentication.check req, res                 
  else # Normal mode.
    server = oldCreateServer.apply http, arguments
        
  # Return server.   
  return server