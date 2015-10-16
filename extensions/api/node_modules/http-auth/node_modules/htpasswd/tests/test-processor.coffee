# Importing module.
processor = require '../gensrc/processor'

module.exports = 
  
  # Test for validate only username.
  testValidateUsername: (test) ->
    valid = processor.validate {'nofile': true, 'args': ["natalya"]}
    test.ok valid, "Should be valid!"
    test.done()
    
  # Test for validate only username, password.
  testValidateUsernamePass: (test) ->
    program = {'nofile': true, 'batch': true, 'args': ["kiara", "superPass"]} 
    test.ok processor.validate program, "Should be valid!"
    test.done()
    
  # Test for validate only username, password, file. 
  testValidateUsernamePassFile: (test) ->
    program = {'batch': true, 'args': ["pass.txt", "anna", "userPass"]} 
    test.ok processor.validate program, "Should be valid!"
    test.done()
    
  # Test for validate only missing password.
  testValidateInvalidPass: (test) ->
    program = {'batch': true, 'args': ["super.txt", "rita"]}
    test.ok not processor.validate program, "Should be invalid!"
    test.done()

  # Test for validate only missing file. 
  testValidateInvalidFile: (test) ->
    valid = processor.validate {'args': ["rita"]}
    test.ok not valid, "Should be invalid!"
    test.done()

  # Test for process password function.
  testProcessPassword: (test) ->
    processor.readPassword = () -> test.done()
    program = {'nofile': true, 'args': ["lianna"]}  
    processor.process program
    
  # Test for process help function.
  testProcessHelp: (test) ->
    program = {'args': ["klara"], 'help': () -> test.done()}   
    processor.process program