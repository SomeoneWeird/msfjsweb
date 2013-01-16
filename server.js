var config = require('./config.js'),

		express = require('express'),
		ejs 		= require('ejs'),
		async 	= require('async'),
		msfjs 	= require('msfjs')({
			path: config.metasploitpath 
		});

var app = express();

// Configure app

app.use(express.static('files/public'));
app.set('views', 'files/views');
app.use(express.bodyParser());
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

app.get('/payloads', function(request, response) {

		response.render('payloads.ejs', {
			layout: false,
			payloads: msfjs.Payloads.payloads
		});
	
});

app.listen(config.server.port, config.server.host, function() {
	console.log("Listening on " + [ config.server.host, config.server.port ].join(":"));
});