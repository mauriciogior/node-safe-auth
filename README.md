node-safe-auth
==============

Node.js module for safe authentication.

This module is based on Amazon AWS authentication. For more information, please visit: http://www.thebuzzmedia.com/designing-a-secure-rest-api-without-oauth-authentication/

**NOTE: Lib not tested yet! Do not use on production!**

## How it works
* We encrypt a blob of data:
	* Path (ie. "/api/user")
	* Method (ie. "post")
	* Post and Get (ie. "user=123")
* We grab that encrypted data and update with the current timestamp, generating a new encrypted data.
* We grab the last encrypted data, update with the secret and digest in any forms.

## Getting started
```javascript
npm install node-safe-auth
```

```javascript
var nodeSafeAuth = require('node-safe-auth');

var constants = nodeSafeAuth.Constants();

var safeAuth = nodeSafeAuth.Auth(
{
	// Which algorithm should be utilized
	algorithm : constants.HmacSHA1, // HmacSHA1

	// The output of the generated token
	output : constants.Hex, // Hex

	// If I should print dev logs
	dev : false,

	// If the token should expire and in how much time
	validation : {
		expires : true,
		duration : 10000,
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

// ... //

// On a route sample

app.post('/user/auth', function(req, res)
{

	// Sample Secret
	// This secret can be obtained through the idHeader.
	var secret = "42118f812f44fe0378701c37726fc974";

	// Init safeAuth with the user secret
	safeAuth.init(secret);

	// Validate the provided token (SafeAuth retrieve it from the header with name provided on tokenHeader)
	if(safeAuth.validate(req))
	{
		// Do something;
	}
});

```

## What about it?
With this method, you don't need to worry about *man-in-the-middle* attacks (since we provide a different token for every second), *side-jacking* (since we don't have sessions stored), *replay attempts* (since every token only works for a specific request, and only one time), etc.

## Concerns
If you want to send huge amount of data in *x-www-form-urlencoded* (forget about *form-data*), please use **SHA512**. (note: the higher the data is, chances of collisions increase).

## Client approach
Here we will provide some samples in Java and Objective-C.

*Soon...*