# Importing crypto module.
crypto = require 'crypto'

#  Module for utility functionalities.
module.exports =

  # Generates md5 hash of input.
  md5: (input) ->
    hash = crypto.createHash 'md5'
    hash.update input
    hash.digest 'hex'

  # Generates sha1 hash of input.
  sha1: (input) ->
    hash = crypto.createHash 'sha1'
    hash.update input
    hash.digest 'base64'
  
  # Encode to base64 string.
  base64: (input) ->
    (new Buffer input, 'utf8').toString 'base64'
  
  # Decodes base64 string.
  decodeBase64: (encoded) ->
    (new Buffer encoded, 'base64').toString 'utf8'
  
  # Check if module is available.
  isAvailable: (path) ->
    try
      return not not require.resolve path
    catch
      return false