//********************//
// OSSEC-API RESTful
// Wazuh, Inc. 2015-2016
//********************//


// BASE SETUP
// =============================================================================

// call the packages we need
var express    = require('express');        // call express
var app        = express();                 // define our app using express
var bodyParser = require('body-parser');

// configure app to use bodyParser()
// this will let us get the data from a POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

var port = process.env.PORT || 8080;        // set our port





// Extra functions
// =============================================================================

var padding_zero = function(x, n) {
	var zeros = Array(n+1).join("0")
	return String(zeros + x).slice(-1 * n)
} 
 


// ROUTES FOR OUR API
// =============================================================================
var router = express.Router();              // get an instance of the express Router

// middleware to use for all requests
router.use(function(req, res, next) {
res.setHeader('Access-Control-Allow-Origin', '*');
    // do logging
    console.log('Something is happening.');
    next(); // make sure we go to the next routes and don't stop here
});

// (accessed at GET http://localhost:8080)
router.get('/', function(req, res) {
    res.json({ message: 'OSSEC-API' });   
});

// Getting agents list
router.route('/agents')
	.get(function(req, res) {
		var exec = require('child_process').exec;
		exec('/var/ossec/bin/agent_control -lj', function(error, stdout, stderr) {
			console.log('stdout: ' + stdout);
			console.log('stderr: ' + stderr);
			try {
				var response = JSON.parse(stdout);
			} catch (e) {
				res.status(500).send("600: JSON parse error");
			}
			res.status(200).json(response);
			if (error !== null) {
				console.log('exec error: ' + error);
			}
		});
	});
	


// Getting agent info
router.route('/agents/:agent_id')
	.get(function(req, res) {
		in_agent_id = req.params.agent_id;
		agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
		var exec = require('child_process').exec;
		exec('/var/ossec/bin/agent_control -j -i '+ agent_id, function(error, stdout, stderr) {
			console.log('stdout: ' + stdout);
			console.log('stderr: ' + stderr);
			try {
				var response = JSON.parse(stdout);
			} catch (e) {
				res.status(500).send("600: JSON parse error");
			}
			res.status(200).json(response);
			if (error !== null) {
				console.log('exec error: ' + error);
			}
		});
	});

// Getting agent info
router.route('/agents/:agent_id/restart')
	.get(function(req, res) {
		in_agent_id = req.params.agent_id;
		agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
		var exec = require('child_process').exec;
		exec('/var/ossec/bin/agent_control -j -R '+ agent_id, function(error, stdout, stderr) {
			console.log('stdout: ' + stdout);
			console.log('stderr: ' + stderr);
			try {
				var response = JSON.parse(stdout);
			} catch (e) {
				res.status(500).send("600: JSON parse error");
			}
			res.status(200).json(response);
			if (error !== null) {
				console.log('exec error: ' + error);
			}
		});
	});	

// REGISTER OUR ROUTES -------------------------------
// all of our routes will be prefixed with /api
app.use('/', router);

// START THE SERVER
// =============================================================================
app.listen(port);
console.log('Magic happens on port ' + port);


