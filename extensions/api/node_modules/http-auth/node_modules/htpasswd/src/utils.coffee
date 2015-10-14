# Importing crypto module.
crypto = require 'crypto'

# Importing apache-md5 module.
md5 = require 'apache-md5'

# Importing apache-crypt module.
crypt = require 'apache-crypt'

#  Module for utility functionalities.
module.exports =

  # Crypt method.
  crypt3: (password, hash) ->
    crypt password, hash

  # Generates sha1 hash of password.
  sha1: (password) ->
    hash = crypto.createHash 'sha1'
    hash.update password
    hash.digest 'base64'

  # Verifies if password is correct.
  verify: (hash, password) ->
    if (hash.substr 0, 5) is '{SHA}'
      hash = hash.substr 5
      hash is module.exports.sha1 password
    else if (hash.substr 0, 6) is '$apr1$'
      hash is md5(password, hash)
    else
      (hash is password) or ((module.exports.crypt3 password, hash) is hash)

  # Encodes password hash for output.
  encode: (program) ->
    if not program.delete
      # Get username and password.
      password = program.args[program.args.length - 1]
      # Encode.
      if not program.plaintext
        if program.crypt
          password = (module.exports.crypt3 password)
        else if program.sha
          password = '{SHA}' + module.exports.sha1 password
        else
          password = md5(password)
      # Return result.
      password