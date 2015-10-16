# Base authentication module.
Base = require './base'

# Utility module.
utils = require './utils'

# UUID module.
uuid = require 'node-uuid'

# Digest authentication class.
class Digest extends Base    
  # Constructor.
  constructor: (@options, @checker) ->
    super @options, @checker
    # Array of random strings sent to clients.
    @nonces = []    
    # Algorithm of encryption, could be MD5 or MD5-sess, default is MD5.
    @options.algorithm = if @options.algorithm is 'MD5-sess' then 'MD5-sess' else 'MD5'
    # Quality of protection is by default auth.
    @options.qop = if @options.qop is 'none' then '' else 'auth'

  # Processes line from authentication file.
  processLine: (line) ->
    [username, realm, hash] = line.split ":"
    if realm is @options.realm # We need only users for given realm.
      @options.users.push {username: username, hash: hash}

  # Parse authorization header.
  parseAuthorization: (header) ->
    opts = {}
    parts = header.split(' ')
    params = parts.slice(1).join(' ')
    tokens = params.split(/,(?=(?:[^"]|"[^"]*")*$)/) # Split the parameters by comma.

    if (parts[0].substr 0, 6) is "Digest" # is Digest.
      # Parse parameters.
      i = 0
      len = tokens.length
      while i < len
        param = /(\w+)=["]?([^"]*)["]?$/.exec(tokens[i]) # Strip quotes and whitespace.
        if param
          opts[param[1]] = param[2]
        i++

    opts
  
  # Validating hash.
  validate: (ha2, co, hash) ->
    ha1 = hash
    if co.algorithm is 'MD5-sess' # Algorithm.
      ha1 = utils.md5 "#{ha1}:#{co.nonce}:#{co.cnonce}"

    if co.qop # Quality of protection.
      response = utils.md5 "#{ha1}:#{co.nonce}:#{co.nc}:#{co.cnonce}:#{co.qop}:#{ha2}"
    else 
      response = utils.md5 "#{ha1}:#{co.nonce}:#{ha2}"
    # Returning result.      
    response is co.response
  
  # Searching for user.
  findUser: (req, co, callback) ->        
    if @validateNonce co.nonce
      ha2 = utils.md5 "#{req.method}:#{co.uri}"
      
      if @checker # Custom authentication.
        @checker.apply this, [co.username, (hash) =>
          callback.apply this, [{user: co.username if (@validate ha2, co, hash)}]
        ]
      else # File based.
        for user in @options.users # Loop users to find the matching one.
          if user.username is co.username and @validate ha2, co, user.hash
            found = true
            break # Stop searching, we found him.
            
        callback.apply this, [{user: co.username if found}]      
    else
      callback.apply this, [{stale: true}]
    
  # Remove nonces.
  removeNonces: (noncesToRemove) ->
    for nonce in noncesToRemove
      index = @nonces.indexOf nonce
      
      if index != -1 # Nonce found.
        @nonces.splice index, 1 # Remove it from array.
      
  # Validate nonce.
  validateNonce: (nonce) ->
    now = Date.now() # Current time.       
    noncesToRemove = [] # Nonces for removal.

    for serverNonce in @nonces # Searching for not expired ones.
      if (serverNonce[1] + 3600000) > now # Not expired ones (1 hour lifetime). 
        if serverNonce[0] is nonce
          found = true
      else # Removing expired ones.
        noncesToRemove.push serverNonce 

    @removeNonces noncesToRemove
                  
    return found
        
  # Generates and returns new random nonce.
  askNonce: () ->
    nonce = utils.md5 uuid.v4() # Random nonce.
    @nonces.push [nonce, Date.now()] # Push into nonces.    

    return nonce # Return it.
  
  # Generates request header.
  generateHeader: (result) ->
    nonce = @askNonce()
    stale = if result.stale then true else false
    
    # Returning it.
    return "Digest realm=\"#{@options.realm}\", qop=\"#{@options.qop}\", nonce=\"#{nonce}\", algorithm=\"#{@options.algorithm}\", stale=\"#{stale}\""
    
# Exporting.
module.exports = (options, checker) ->
  new Digest options, checker
  
