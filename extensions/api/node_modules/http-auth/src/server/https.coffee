# HTTPS module.
https = require 'https'

# Base module.
Base = require '../auth/base'

# Backup old server creation.
oldCreateServer = https.createServer

# Add authentication method.
https.createServer = () ->
  if arguments[0] instanceof Base # Mutated mode.
    authentication = arguments[0]
        
    if arguments[2] # With listener.
      listener = arguments[2]
      newListener = (req, res) ->
        authentication.check req, res, listener        
        
      # HTTPS options and listener.
      server = oldCreateServer.apply https, [arguments[1], newListener]      
    else # Without.
      server = oldCreateServer.apply(https, [arguments[1]]) # Only HTTPS options.
      server.on 'request', (req, res) ->
        authentication.check req, res                 
  else # Normal mode.
    server = oldCreateServer.apply https, arguments
        
  # Return server.   
  return server