// HTTP module
var http = require('http');

// Authentication module.
var auth = require('../gensrc/http-auth');
var basic = auth.basic({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htpasswd" // gevorg:gpass, Sarah:testpass ...
});

// Creating new HTTP server.
http.createServer(basic, function(req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);

// Log URL.
console.log("Server running at http://127.0.0.1:1337/");