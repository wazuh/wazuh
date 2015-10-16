// HTTP module
var http = require('http');

// Authentication module.
var auth = require('../gensrc/http-auth');
var digest = auth.digest({
	realm: "Simon Area.",
	file: __dirname + "/../data/users.htdigest" // vivi:anna, sona:testpass
});

// Creating new HTTP server.
http.createServer(digest, function(req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);

// Log URL.
console.log("Server running at http://127.0.0.1:1337/");