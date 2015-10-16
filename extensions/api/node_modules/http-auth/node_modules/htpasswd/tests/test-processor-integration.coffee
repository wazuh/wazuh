# Importing module.
processor = require '../gensrc/processor'

# FS module.
fs = require 'fs'

module.exports =
  
  # After each test.
  tearDown: (callback) ->
    fs.unlinkSync "password.txt" if fs.existsSync "password.txt"
    callback()
  
  # Test for process with console output. 
  testProcessConsole: (test) ->
    program = {'batch': true, 'nofile': true, 'sha': true, 'args': ["mary", "pass12"]}
    preservedLog = console.log 

    console.log = () ->
      console.log = preservedLog
      console.log.apply console, arguments

      test.equals arguments[0], "mary:{SHA}TgXU+mQ5o9ryuFPj3xhY1C6GHfE=", "Output is wrong!"
  
    processor.process program   
    test.done()

# Test for process with successful password verification.
  testProcessVerifyOk: (test) ->
    fs.writeFileSync "password.txt", "detka:milaya\n", 'UTF-8'
    program = {'batch': true, 'verify': true, plain: true, 'args': ["password.txt", "detka", "milaya"]}
    preservedLog = console.log

    console.log = () ->
      console.log = preservedLog
      console.log.apply console, arguments

      test.equals arguments[0], "Password for user detka correct.", "Output is wrong!"

    processor.process program
    test.done()

  # Test for process with failed password verification.
  testProcessVerifyFailed: (test) ->
    fs.writeFileSync "password.txt", "detka:nemilaya\n", 'UTF-8'
    program = {'batch': true, 'verify': true, plain: true, 'args': ["password.txt", "detka", "milaya"]}
    preservedLog = console.log

    console.log = () ->
      console.log = preservedLog
      console.log.apply console, arguments

      test.equals arguments[0], "Password verification failed.", "Output is wrong!"

    processor.process program
    test.done()

  # Test for process with file create.
  testProcessFileCreate: (test) ->
    program = {'batch': true, 'sha': true, 'create': true, 'args': ["password.txt", "gevorg", "sho"]}
    processor.process program
  
    fileData = fs.readFileSync "password.txt", 'UTF-8'
    test.equal fileData, "gevorg:{SHA}NSjjR5VzkksaQNgdEKs0MqPtStI=\n", "File data is wrong!"
  
    test.done()
    
  # Test for process with file update.
  testProcessFileUpdate: (test) ->
    fs.writeFileSync "password.txt", "mihrdat:{SHA}NSjjR5VzkksaQNgdEKs0MqPtStI=\n", 'UTF-8'
    program = {'batch': true, 'sha': true, 'args': ["password.txt", "mihrdat", "king"]}
    processor.process program
  
    fileData = fs.readFileSync "password.txt", 'UTF-8'
    test.equal fileData, "mihrdat:{SHA}SBkC7BTq8/z+xr6CvWpjuXKsUX8=\n", "File data is wrong!"
  
    test.done()

  # Test for process with file delete.
  testProcessFileDelete: (test) ->
    fs.writeFileSync "password.txt", "urmia:{SHA}NSjjR5VzkksaQNgdEKs0MqPtStI=\n", 'UTF-8'
    program = {'delete': true, 'args': ["password.txt", "urmia"]}  
    processor.process program
    
    fileData = fs.readFileSync "password.txt", 'UTF-8'
    test.equal fileData, "\n", "File data is wrong!"
    
    test.done()

  # Test for process with file delete not existing.
  testProcessFileDeleteNotExisting: (test) ->
    fs.writeFileSync "password.txt", "urmia:{SHA}NSjjR5VzkksaQNgdEKs0MqPtStI=\n", 'UTF-8'
    program = {'delete': true, 'args': ["password.txt", "sonya"]}
  
    preservedLog = console.log
    console.error = () ->
      console.error = preservedLog 
      console.error.apply console, arguments

      test.equals arguments[0], "User sonya not found.", "Output is wrong!"
  
    processor.process(program)

    test.done()

  # Test for process with file add.
  testProcessFileAdd: (test) ->
    initData = "mihrdat:{SHA}NSjjR5VzkksaQNgdEKs0MqPtStI=\n"
    fs.writeFileSync "password.txt", initData, 'UTF-8'
  
    program = {'sha': true, 'batch': true, 'args': ["password.txt", "tigran", "thegreat"]}
    processor.process program
  
    fileData = fs.readFileSync "password.txt", 'UTF-8'
    test.equal fileData, "#{initData}tigran:{SHA}1cYTTawbHcKifj2Yn6MC8bDq7Dc=\n", "File data is wrong!" 
    test.done()

  # Test for process with file add, not existing.
  testProcessFileAddNotExisting: (test) ->
    program = {'batch': true, 'args': ["password.txt", "tigran", "thegreat"]} 

    preservedLog = console.log; 
    console.error = () ->
      console.error = preservedLog 
      console.error.apply console, arguments

      test.equals arguments[0], "Cannot modify file password.txt; use '-c' to create it.", "Output is wrong!"
        
    processor.process program
    test.done()