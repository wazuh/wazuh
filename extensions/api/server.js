//********************//
// API RESTful for OSSEC
// Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
//********************//
/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
//*******************//



// SETTINGS
var port = process.env.PORT || 55000;        // set our port
var debug = false; // Debug mode, printing stdout to log.

// BASE SETUP
// =============================================================================

// Call the packages we need
var express    = require('express');        // call express
var app        = express();                 // define our app using express
var bodyParser = require('body-parser');
var fs = require('fs'); // To open certs files
var http = require('http');
var https = require('https'); // Secure HTTP
var auth = require("http-auth"); // Password HTTP protection
var _moment = require('moment'); // Log timestamps

// Basic HTTP authentication
var auth = require('http-auth');
var auth_secure = auth.basic({
    realm: "OSSEC API",
    file: __dirname + "/htpasswd" // Reading htpassword from the folder where server.js is.
});

// CERTS
var options = {
  key: fs.readFileSync(__dirname + '/server.key'), // Reading key from the folder where server.js is.
  cert: fs.readFileSync(__dirname + '/server.crt') // Reading crt from the folder where server.js is.
}; 
 

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(auth.connect(auth_secure));

// Extra functions
// =============================================================================

// Padding agents ID
var padding_zero = function(x, n) {
	var zeros = Array(n+1).join("0")
	return String(zeros + x).slice(-1 * n)
}

function logWrite(error, stdout, stderr) {
	var now = _moment()
	var timestamp = now.format('YYYY-MM-DD HH:mm:ss')

	if(error != null){
		console.error(timestamp + " exec_error:" + error);
		return true;
	}
	if(stderr != ""){
		console.error(timestamp + " stderr:" + stderr);
		return true;
	}
	if(debug)
		console.log(timestamp + " stdout:" + stdout);

	return false;
}

// ROUTES FOR OUR API
// =============================================================================
var router = express.Router();              // get an instance of the express Router

// middleware to use for all requests
// Allow petitions from outside of the API URL
router.use(function(req, res, next) {
res.setHeader('Access-Control-Allow-Origin', '*');
    // do logging
    next(); // make sure we go to the next routes and don't stop here
});

// Initial Message
router.get('/',function(req, res) {
    res.json({ message: 'OSSEC-API' });   
});

// Getting agents list
router.route('/agents').get(function(req, res) {
	var exec = require('child_process').exec;
	exec('/var/ossec/bin/agent_control -lj', function(error, stdout, stderr) {
console.log(stderr);
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
		try {
			var response = JSON.parse(stdout);
		} catch (e) {
			res.status(600).send("JSON parse error");
		}
		res.status(200).json(response);
	});
});

// Add agent, returns ID
router.route('/agents/add/:agent_name').get(function(req, res) {
    agent_name = req.params.agent_name;
    var exec = require('child_process').exec;
    exec('bin/api_add_agent.sh ' + agent_name, function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
        try {
                var response = JSON.parse(stdout);
        } catch (e) {
                res.status(600).send("JSON parse error");
        }
        res.status(200).json(response);
    });
});


	
// Restart syscheck/rootcheck in all agents
router.route('/agents/sysrootcheck/restart').get(function(req, res) {
	var exec = require('child_process').exec;
	exec('/var/ossec/bin/agent_control -j -r -a', function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
		try {
			var response = JSON.parse(stdout);
		} catch (e) {
			res.status(600).send("JSON parse error");
		}
		res.status(200).json(response);
	});
});	

// Getting agent info
router.route('/agents/:agent_id').get(function(req, res) {
	in_agent_id = req.params.agent_id;
	agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
	var exec = require('child_process').exec;
	exec('/var/ossec/bin/agent_control -j -e -i '+ agent_id, function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
		try {
			var response = JSON.parse(stdout);
		} catch (e) {
			res.status(600).send("JSON parse error");
		}
		res.status(200).json(response);
	});
});

// Restart agent
router.route('/agents/:agent_id/restart').get(function(req, res) {
	in_agent_id = req.params.agent_id;
	agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
	var exec = require('child_process').exec;
	exec('/var/ossec/bin/agent_control -j -R '+ agent_id, function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
		try {
			var response = JSON.parse(stdout);
		} catch (e) {
			res.status(600).send("JSON parse error");
		}
		res.status(200).json(response);
	});
});	

// Get Agent KEY
router.route('/agents/:agent_id/key').get(function(req, res) {
    in_agent_id = req.params.agent_id;
    agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
    var exec = require('child_process').exec;
    exec('sh bin/api_getkey_agent.sh ' + agent_id, function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
        try {
            var response = JSON.parse(stdout);
        } catch (e) {
            res.status(600).send("JSON parse error");
        }
        res.status(200).json(response);
    });
});

// Restart syscheck/rootcheck in one agents
router.route('/agents/:agent_id/sysrootcheck/restart').get(function(req, res) {
	in_agent_id = req.params.agent_id;
	agent_id = padding_zero(parseInt(in_agent_id), in_agent_id.length);
	var exec = require('child_process').exec;
	exec('/var/ossec/bin/agent_control -j -r -u '+ agent_id, function(error, stdout, stderr) {
		var errorAPI = logWrite(error, stdout, stderr);
		if(errorAPI)
			res.status(500).send("Some error ocurred");	
		try {
			var response = JSON.parse(stdout);
		} catch (e) {
			res.status(600).send("JSON parse error");
		}
		res.status(200).json(response);
	});
});	

// REGISTER OUR ROUTES -------------------------------
// all of our routes will be prefixed with /api
app.use('/', router);
// START THE SERVER
// =============================================================================
https.createServer(options, app).listen(port);
