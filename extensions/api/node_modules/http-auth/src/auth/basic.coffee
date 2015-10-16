# Base authentication module.
Base = require './base'

# Utility module.
utils = require './utils'

# htpasswd verification is reused.
htpasswd = require 'htpasswd'

# Basic authentication class.
class Basic extends Base    
  # Constructor.
  constructor: (@options, @checker) ->
    super @options, @checker
  
  # Processes line from authentication file.
  processLine: (line) ->
    lineSplit = line.split ":"
    username = lineSplit.shift()
    hash = lineSplit.join ":"
    
    @options.users.push {username: username, hash: hash}
  
  # Searching for user.
  findUser: (req, hash, callback) ->
    # Decode base64.
    splitHash = (utils.decodeBase64 hash).split ":"
    username = splitHash.shift()
    password = splitHash.join ":"

    if @checker # Custom authentication.
      @checker.apply this, [username, password, (success) =>
        callback.apply this, [{user: username if success}]
      ]
    else # File based.
      for user in @options.users # Loop users to find the matching one.
        if user.username is username and htpasswd.verify user.hash, password
          found = true
          break # Stop searching, we found him.
          
      callback.apply this, [{user: username if found}]
      
  # Parsing authorization header.
  parseAuthorization: (header) ->
    [type, hash] = header.split " " # Split it.    
    if type is "Basic" # Only if type is basic.
      return hash # Return hash.
  
  # Generates request header.
  generateHeader: () ->     
    return "Basic realm=\"#{@options.realm}\""
           
# Exporting.
module.exports = (options, checker) ->
  new Basic options, checker
  
