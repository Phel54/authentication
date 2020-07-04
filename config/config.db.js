//require database URL from properties file
require('dotenv').config();

//require mongoose module
var mongoose = require('mongoose');

//require chalk module to give colors to console text
var chalk = require('chalk');


// Remote DB
const mainDB = process.env.DATABASE;

var connected = chalk.bold.cyan;
var error = chalk.bold.yellow;
var disconnected = chalk.bold.red;
var termination = chalk.bold.magenta;

//export this function and imported by server.js
module.exports = function () {
	mongoose.connect(mainDB, {
		useCreateIndex: true,
		useNewUrlParser: true,
		useFindAndModify: false,
		useUnifiedTopology: true,
		socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
		poolSize: 10, // Maintain up to 10 socket connections
		autoIndex: false, // Don't build indexes
	});

	mongoose.connection.on('connected', function () {
		console.log(connected('Mongoose default connection is open'));
	});

	mongoose.connection.on('error', function (err) {
		console.log(
			error('Mongoose default connection has occured ' + err + ' error')
		);
	});

	mongoose.connection.on('disconnected', function () {
		console.log(disconnected('Mongoose default connection is disconnected'));
	});

	process.on('SIGINT', function () {
		mongoose.connection.close(function () {
			console.log(
				termination(
					'Mongoose default connection is disconnected due to application termination'
				)
			);
			process.exit(0);
		});
	});
};
