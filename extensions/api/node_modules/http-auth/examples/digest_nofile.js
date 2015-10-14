// Using CoffeeScript, needed for utility module.
require('coffee-script');

// Utility module.
var utils = require('../gensrc/auth/utils');

// HTTP module
var http = require('http');

// Authentication module.
var auth = require('../gensrc/http-auth');
var digest = auth.digest({
		realm: "Simon Area."
	}, function (username, callback) { // Expecting md5(username:realm:password) in callback.		
		if (username === "simon") {
			callback(utils.md5("simon:Simon Area.:smart"));
		} else if(username === "tigran") {
			callback(utils.md5("tigran:Simon Area.:great"));
		} else {
			callback();			
		}
	}
);

// Creating new HTTP server.
http.createServer(digest, function(req, res) {
	res.end("Welcome to private area - " + req.user + "!");
}).listen(1337);

// Log URL.
console.log("Server running at http://127.0.0.1:1337/");