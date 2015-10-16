// Express module.
var express = require('express');

// Authentication module.
var auth = require('../gensrc/http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// Application setup.
var app = express();
app.use(auth.connect(basic));

// Setup route.
app.get('/', function(req, res){
  res.send("Hello from express - " + req.user + "!");
});

// Start server.
app.listen(1337);

// Log URL.
console.log("Server running at http://127.0.0.1:1337/");