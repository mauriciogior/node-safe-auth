/*
 * EXTENSIONS
 */
var express = require('express'),
		nodeSafeAuth = require('../node-safe-auth');

var constants = nodeSafeAuth.Constants();

var safeAuth = nodeSafeAuth.Auth(
{
    // Which algorithm should be utilized
    algorithm : constants.HmacSHA256, // HmacSHA256

    // The output of the generated token
    output : constants.Base64, // Base64

    // If I should print dev logs
    dev : true,

    // If the token should expire and in how much time
    validation : {
        expires : true,
        duration : 30,
        oneTimeUse : false
    },

    // Unique header for user identification
    // Can be a username or an email also (or anything you would use to retrieve the secret)
    idHeader : "X-AUTH-ID",

    // Time header
    timeHeader : "X-AUTH-TIME",

    // Token header
    tokenHeader : "X-AUTH-TOKEN"
});

var users = [
	{
		secret: "123456"
	},
	{
		secret: "654321"
	}
];

/*
 * DECLARE APP
 */
var app = express();

/*
 * CONFIGURING THE APP
 */
app.configure(function()
{
	app.use(express.logger('dev'));

	/**
	 * If you want to use the multipart middleware, pay attention on
	 * the size of the content you are sending to avoid possible collisions.
	 */
	app.use(express.json());
  app.use(express.urlencoded());
});

app.get('/', function(req, res)
{
	var id = req.body.id;

	safeAuth.init(users[id].secret);

	if(safeAuth.validate(req))
	{
		res.status(200).send('OK');
	}
	else
	{
		res.status(401).send('Unauthorized');
	}
});

app.listen(3000);
console.log('OK');