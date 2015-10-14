# File system module.
fs = require 'fs'

# Base authentication module.
class Base
  # Constructor.  
  constructor: (@options, @checker) ->
    @options.msg401 = "401 Unauthorized" if not @options.msg401
    @options.msg407 = "407 Proxy authentication required" if not @options.msg407
    @options.contentType = "text/plain" if not @options.contentType

    # Loading users from file, if file is set.
    @options.users = []    
    @loadUsers() if not @checker and @options.file    
    
  # Is authenticated method.
  isAuthenticated: (req, callback) ->
    try # Processing client's data, dangerous! 
      if @proxy
        header = req.headers["proxy-authorization"]
      else  
        header = req.headers["authorization"]
       
      if header # If header is sent.
        clientOptions = @parseAuthorization header
  
        if clientOptions # If client options are good.
          searching = true # Searching...
          @findUser req, clientOptions, (result) =>
            callback.apply this, [result]
    catch error
      console.error error.message
                    
    # Only if not searching call callback.
    (callback.apply this, [{}]) if not searching
      
  # Loading files with user details.
  loadUsers: () ->
    lines = ((fs.readFileSync @options.file, 'UTF-8').replace /\r\n/g, "\n").split "\n"
    
    for line in lines  
      if line # If line is not empty, process it.
        @processLine line

  # Ask for authentication.
  ask: (res, result) ->
	
    header = @generateHeader result

    res.setHeader "Content-Type", @options.contentType

    if @proxy # Proxy authentication.
      res.setHeader "Proxy-Authenticate", header
      res.writeHead 407
      res.end @options.msg407
    else # Normal authentication. 
      res.setHeader "WWW-Authenticate", header
      res.writeHead 401
      res.end @options.msg401

  # Checking if user is authenticated.
  check: (req, res, callback) ->  
    @isAuthenticated req, (result) =>            
      if not result.user # Asking for authentication.
        @ask res, result
      else # Apply default listener.
        req.user = result.user if not @options.skipUser
        (callback.apply this, [req, res]) if callback
            
# Exporting.
module.exports = Base