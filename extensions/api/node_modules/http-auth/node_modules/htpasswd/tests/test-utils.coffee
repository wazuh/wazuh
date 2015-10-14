# Importing module.
utils = require '../gensrc/utils'

# Importing apache-md5 module.
md5 = require 'apache-md5'

module.exports =

  # Test for SHA1 function.
  testSHA1: (test) ->
    test.equal (utils.sha1 "devochka"), "deWaCTR7rOMysgZN3EgtgAaTzPs=", "SHA1 is wrong!"
    test.done()
    
  # Test for encode with delete option. 
  testEncodeDelete: (test) ->
    test.ok (not utils.encode {'delete': true}), "Should be empty!"
    test.done()
    
  # Test for encode with plain option.  
  testEncodePlain: (test) ->
    encoded = utils.encode {'plaintext': true, 'args': ["olga", "chexova111"]}
    test.equal encoded, "chexova111", "Should be plaintext!"
    test.done()

  # Test for encode with sha1 option.
  testEncodeSHA1: (test) ->
    encoded = utils.encode {'sha': true, 'args': ["olga", "chexova111"]}
    test.equal encoded, "{SHA}Iv8c5zqtbvxiwFTxcEI6CteSx48=", "Should be sha1!"
    test.done()

  # Test for crypt3 option.
  testEncodeCrypt3: (test) ->
    encoded = utils.encode {'crypt': true, 'args': ["olga", "chexova111"]}
    test.equal (utils.crypt3 "chexova111", encoded), encoded, "Password is wrong!"

    test.done()

  # Test for MD5 option.
  testEncodeMD5: (test) ->
    encoded = utils.encode {'args': ["kia", "siara"]}
    test.equal (md5 "siara", encoded), encoded, "Password is wrong!"
    test.done()

# Test for verify with correct plain pass.
  testVerifyPlainOk: (test) ->
    test.ok utils.verify "plainPassword", "plainPassword"
    test.done()

  # Test for verify with wrong plain pass.
  testVerifyPlainFailed: (test) ->
    test.ok not utils.verify "plainWrongPassword", "plainPassword"
    test.done()

  # Test for verify with correct sha1 pass.
  testVerifySHA1Ok: (test) ->
    test.ok utils.verify "{SHA}hGJRiZy8gBpNMHvs1UOTqIrRU20=", "hanna"
    test.done()

  # Test for verify with wrong sha1 pass.
  testVerifySHA1Failed: (test) ->
    test.ok not utils.verify "{SHA}hGJRiZy8gBpNMHvs1UOTqIrRU20=", "bannana"
    test.done()

  # Test for verify with correct crypt pass.
  testVerifyCryptOk: (test) ->
    test.ok utils.verify "hVmhA.naUQQ3I", "raya"
    test.done()

  # Test for verify with wrong crypt pass.
  testVerifyCryptFailed: (test) ->
    test.ok not utils.verify "hVmhA.naUQQ3I", "serob"
    test.done()

  # Test for verify with correct MD5 pass.
  testVerifyMD5Ok: (test) ->
    test.ok utils.verify "$apr1$Ny3hkBdz$UReNPq7yEH6Y/D/FXUPwI/", "mia"
    test.done()

  # Test for verify with wrong MD5 pass.
  testVerifyMD5Failed: (test) ->
    test.ok not utils.verify "$apr1$Ny3hkBdz$UReNPq7yEH6Y/D/FXUPwI/", "leo"
    test.done()
