//********************//
// OSSEC-API RESTful
// Wazuh, Inc. 2015-2016
//********************//

// SETTINGS
var port = process.env.PORT || 8080;        // set our port

// BASE SETUP
// =============================================================================

// call the packages we need
var express    = require('express');        // call express
var app        = express();                 // define our app using express
var bodyParser = require('body-parser');
var fs = require('fs');
var http = require('http');
var https = require('https');


// Authentication module. 
var auth = require('http-auth');
var basic = auth.basic({
    realm: "Simon Area.",
    file: __dirname + "/htpasswd" // gevorg:gpass, Sarah:testpass ... 
});
 
// Application setup. 
var app = express();
app.use(auth.connect(basic));
 
// Setup route. 
app.get('/', function(req, res){
  res.send("Hello from express - " + req.user + "!");
});
// Creating new HTTP server. 
http.createServer(basic, function(req, res) {
    res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);
