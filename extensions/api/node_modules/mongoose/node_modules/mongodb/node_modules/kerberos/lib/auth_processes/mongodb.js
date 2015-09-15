var format = require('util').format;

var MongoAuthProcess = function(host, port, service_name) {  
  // Check what system we are on
  if(process.platform == 'win32') {
    this._processor = new Win32MongoProcessor(host, port, service_name);
  } else {
    this._processor = new UnixMongoProcessor(host, port, service_name);
  }
}

MongoAuthProcess.prototype.init = function(username, password, callback) {
  this._processor.init(username, password, callback);
}

MongoAuthProcess.prototype.transition = function(payload, callback) {
  this._processor.transition(payload, callback);
}

/*******************************************************************
 *
 * Win32 SSIP Processor for MongoDB
 *
 *******************************************************************/
var Win32MongoProcessor = function(host, port, service_name) {
  this.host = host;
  this.port = port  
  // SSIP classes
  this.ssip = require("../kerberos").SSIP;
  // Set up first transition
  this._transition = Win32MongoProcessor.first_transition(this);
  // Set up service name
  service_name = service_name || "mongodb";
  // Set up target
  this.target = format("%s/%s", service_name, host);
  // Number of retries
  this.retries = 10;
}

Win32MongoProcessor.prototype.init = function(username, password, callback) {
  var self = this;
  // Save the values used later
  this.username = username;
  this.password = password;
  // Aquire credentials
  this.ssip.SecurityCredentials.aquire_kerberos(username, password, function(err, security_credentials) {
    if(err) return callback(err);
    // Save credentials
    self.security_credentials = security_credentials;
    // Callback with success
    callback(null);
  });
}

Win32MongoProcessor.prototype.transition = function(payload, callback) {
  if(this._transition == null) return callback(new Error("Transition finished"));
  this._transition(payload, callback);
}

Win32MongoProcessor.first_transition = function(self) {
  return function(payload, callback) {    
    self.ssip.SecurityContext.initialize(
      self.security_credentials, 
      self.target, 
      payload, function(err, security_context) {   
        if(err) return callback(err);
        
        // If no context try again until we have no more retries
        if(!security_context.hasContext) {
          if(self.retries == 0) return callback(new Error("Failed to initialize security context"));
          // Update the number of retries
          self.retries = self.retries - 1;
          // Set next transition
          return self.transition(payload, callback);
        }

        // Set next transition
        self._transition = Win32MongoProcessor.second_transition(self);
        self.security_context = security_context;
        // Return the payload
        callback(null, security_context.payload);
    });
  }
}

Win32MongoProcessor.second_transition = function(self) {
  return function(payload, callback) {    
    // Perform a step
    self.security_context.initialize(self.target, payload, function(err, security_context) {
      if(err) return callback(err);

      // If no context try again until we have no more retries
      if(!security_context.hasContext) {
        if(self.retries == 0) return callback(new Error("Failed to initialize security context"));
        // Update the number of retries
        self.retries = self.retries - 1;
        // Set next transition
        self._transition = Win32MongoProcessor.first_transition(self);
        // Retry
        return self.transition(payload, callback);
      }

      // Set next transition
      self._transition = Win32MongoProcessor.third_transition(self);
      // Return the payload
      callback(null, security_context.payload);
    });
  }  
}

Win32MongoProcessor.third_transition = function(self) {
  return function(payload, callback) {   
    var messageLength = 0;
    // Get the raw bytes
    var encryptedBytes = new Buffer(payload, 'base64');
    var encryptedMessage = new Buffer(messageLength);
    // Copy first byte
    encryptedBytes.copy(encryptedMessage, 0, 0, messageLength);
    // Set up trailer
    var securityTrailerLength = encryptedBytes.length - messageLength;
    var securityTrailer = new Buffer(securityTrailerLength);
    // Copy the bytes
    encryptedBytes.copy(securityTrailer, 0, messageLength, securityTrailerLength);

    // Types used
    var SecurityBuffer = self.ssip.SecurityBuffer;
    var SecurityBufferDescriptor = self.ssip.SecurityBufferDescriptor;

    // Set up security buffers
    var buffers = [
        new SecurityBuffer(SecurityBuffer.DATA, encryptedBytes)
      , new SecurityBuffer(SecurityBuffer.STREAM, securityTrailer)
    ];

    // Set up the descriptor
    var descriptor = new SecurityBufferDescriptor(buffers);

    // Decrypt the data
    self.security_context.decryptMessage(descriptor, function(err, security_context) {
      if(err) return callback(err);

      var length = 4;
      if(self.username != null) {
        length += self.username.length;          
      }

      var bytesReceivedFromServer = new Buffer(length);
      bytesReceivedFromServer[0] = 0x01;  // NO_PROTECTION
      bytesReceivedFromServer[1] = 0x00;  // NO_PROTECTION
      bytesReceivedFromServer[2] = 0x00;  // NO_PROTECTION
      bytesReceivedFromServer[3] = 0x00;  // NO_PROTECTION        

      if(self.username != null) {
        var authorization_id_bytes = new Buffer(self.username, 'utf8');
        authorization_id_bytes.copy(bytesReceivedFromServer, 4, 0);
      }

      self.security_context.queryContextAttributes(0x00, function(err, sizes) {
        if(err) return callback(err);

        var buffers = [
            new SecurityBuffer(SecurityBuffer.TOKEN, new Buffer(sizes.securityTrailer))
          , new SecurityBuffer(SecurityBuffer.DATA, bytesReceivedFromServer)
          , new SecurityBuffer(SecurityBuffer.PADDING, new Buffer(sizes.blockSize))
        ]

        var descriptor = new SecurityBufferDescriptor(buffers);

        self.security_context.encryptMessage(descriptor, 0x80000001, function(err, security_context) {
          if(err) return callback(err);
          callback(null, security_context.payload);
        });
      });
    });
  }  
}

/*******************************************************************
 *
 * UNIX MIT Kerberos processor
 *
 *******************************************************************/
var UnixMongoProcessor = function(host, port, service_name) {
  this.host = host;
  this.port = port  
  // SSIP classes
  this.Kerberos = require("../kerberos").Kerberos;
  this.kerberos = new this.Kerberos();
  service_name = service_name || "mongodb";
  // Set up first transition
  this._transition = UnixMongoProcessor.first_transition(this);
  // Set up target
  this.target = format("%s@%s", service_name, host);
  // Number of retries
  this.retries = 10;
}

UnixMongoProcessor.prototype.init = function(username, password, callback) {
  var self = this;
  this.username = username;
  this.password = password;
  // Call client initiate
  this.kerberos.authGSSClientInit(
      self.target
    , this.Kerberos.GSS_C_MUTUAL_FLAG, function(err, context) {
      self.context = context;
      // Return the context
      callback(null, context);
  });
}

UnixMongoProcessor.prototype.transition = function(payload, callback) {
  if(this._transition == null) return callback(new Error("Transition finished"));
  this._transition(payload, callback);
}

UnixMongoProcessor.first_transition = function(self) {
  return function(payload, callback) {    
    self.kerberos.authGSSClientStep(self.context, '', function(err, result) {
      if(err) return callback(err);
      // Set up the next step
      self._transition = UnixMongoProcessor.second_transition(self);
      // Return the payload
      callback(null, self.context.response);
    })
  }
}

UnixMongoProcessor.second_transition = function(self) {
  return function(payload, callback) {    
    self.kerberos.authGSSClientStep(self.context, payload, function(err, result) {
      if(err && self.retries == 0) return callback(err);
      // Attempt to re-establish a context
      if(err) {
        // Adjust the number of retries
        self.retries = self.retries - 1;
        // Call same step again
        return self.transition(payload, callback);
      }
      
      // Set up the next step
      self._transition = UnixMongoProcessor.third_transition(self);
      // Return the payload
      callback(null, self.context.response || '');
    });
  }
}

UnixMongoProcessor.third_transition = function(self) {
  return function(payload, callback) {    
    // GSS Client Unwrap
    self.kerberos.authGSSClientUnwrap(self.context, payload, function(err, result) {
      if(err) return callback(err, false);
      
      // Wrap the response
      self.kerberos.authGSSClientWrap(self.context, self.context.response, self.username, function(err, result) {
        if(err) return callback(err, false);
        // Set up the next step
        self._transition = UnixMongoProcessor.fourth_transition(self);
        // Return the payload
        callback(null, self.context.response);
      });
    });
  }
}

UnixMongoProcessor.fourth_transition = function(self) {
  return function(payload, callback) {    
    // Clean up context
    self.kerberos.authGSSClientClean(self.context, function(err, result) {
      if(err) return callback(err, false);
      // Set the transition to null
      self._transition = null;
      // Callback with valid authentication
      callback(null, true);
    });
  }
}

// Set the process
exports.MongoAuthProcess = MongoAuthProcess;