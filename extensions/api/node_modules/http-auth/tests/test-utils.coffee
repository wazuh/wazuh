# Importing module.
utils = require '../gensrc/auth/utils'

module.exports = 
  
  # Test for MD5 function.
  testMD5: (test) ->
    test.equal (utils.md5 "apple of my eye"), "bda53a1c77224ede7cb14e756c1d0142", "MD5 is wrong!"
    test.done()

  # Test for SHA1 function.
  testSHA1: (test) ->
    test.equal (utils.sha1 "forbidden fruit"), "E1Kr19KXvaYQPcLo2MvSpGjoAYU=", "SHA1 is wrong!"
    test.done()

  # Test for base64 function, with ASCII input.
  testBase64ASCII: (test) ->
    test.equal (utils.base64 "crocodile"), "Y3JvY29kaWxl", "base64 is wrong!"
    test.done()

  # Test for base64 function, with unicode input.
  testBase64Unicode: (test) ->
    test.equal (utils.base64 "Գևորգ"), "1LPWh9W41oDVow==", "base64 is wrong!"
    test.done()

  # Test for base64 decode function, from ASCII.
  testDecodeBase64ASCII: (test) ->
    test.equal (utils.decodeBase64 "c21pbGU="), "smile", "decoded string is wrong!"
    test.done()
    
  # Test for base64 decode function, from unicode.
  testDecodeBase64Unicode: (test) ->
    test.equal (utils.decodeBase64 "0J3RgyDRgtGLIQ=="), "Ну ты!", "decoded string is wrong!"
    test.done()

  # Test isAvailable for existing module.
  testIsAvailableExisting: (test) ->
    test.ok utils.isAvailable 'http-proxy'
    test.done()
    
  # Test isAvailable for not existing module.
  testIsAvailableNotExisting: (test) ->
    test.ok not utils.isAvailable 'stupid-name'
    test.done()
