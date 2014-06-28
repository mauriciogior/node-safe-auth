(function()
{
	/**
	 * Authentication system creation based on this article:
	 * http://www.thebuzzmedia.com/designing-a-secure-rest-api-without-oauth-authentication/
	 */
	var SafeAuth = function(config)
	{
		// Used for hash algorithms
		this.crypto = require('crypto');

		// Will store old tokens (if oneTimeUse is true)
		this.pastTokens = [];

		// Will store the base token so we don't need to generate it everytime
		this.baseToken;

		// Will store the generated token to compare
		this.token;

		// Will retrieve all the needed constants
		this.constants = new AuthConstants();

		// SafeAuth configurations
		this.config =
		{
			// Which algorithm should be utilized
			algorithm : 0x7, // HmacSHA1

			// The output of the generated token
			output : 0x10, // Hex

			// If the token should expire and in how much time
			validation : {
				expires : true,
				duration : 10000,
				oneTimeUse : false
			},

			// Unique header for identification
			idHeader : "X-AUTH-ID",

			// Time header
			timeHeader : "X-AUTH-TIME",

			// Token header
			tokenHeader : "X-AUTH-TOKEN"
		}

		// If is given a configuration object
		if(config instanceof Object)
		{
			if(config.algorithm !== undefined)
				this.config.algorithm = config.algorithm;
			if(config.output !== undefined)
				this.config.output = config.output;
			if(config.validation !== undefined)
			{
				if(config.validation.expires !== undefined)
					this.config.validation.expires = config.validation.expires;
				if(config.validation.duration !== undefined)
					this.config.validation.duration = config.validation.duration;
				if(config.validation.oneTimeUse !== undefined)
					this.config.validation.oneTimeUse = config.validation.oneTimeUse;
			}
			if(config.idHeader !== undefined)
				this.config.idHeader = config.idHeader;
			if(config.timeHeader !== undefined)
				this.config.timeHeader = config.timeHeader;
			if(config.tokenHeader !== undefined)
				this.config.tokenHeader = config.tokenHeader;
		}
	}

	SafeAuth.prototype =
	{
		/**
		 * Will initialize the SafeAuth
		 * @param  {[String]} secret
		 * @return {[void]}
		 */
		init : function(secret)
		{
			switch(this.config.algorithm)
			{
				case this.constants.HmacSHA1:
					this.baseToken = crypto.createHmac('sha1', secret);
					break;
			}
		},

		/**
		 * Check if the given token has already been used
		 * @param  {[String]}  token
		 * @return {Boolean}
		 */
		isTokenAlreadyUsed : function(token)
		{
			for(var it in this.pastTokens)
			{
				if(this.pastTokens[it].token == token)
				{
					return true;
				}
			}

			return false;
		},

		/**
		 * Since the tokens expires, it will recycle them.
		 * @return {[void]}
		 */
		recycleUsedTokens : function()
		{
			var currTime = timestamp();

			for(var i=0; i<this.pastTokens.length; i++)
			{
				if(currTime - this.pastTokens[i].time > this.config.validation.duration)
				{
					this.pastTokens.splice(i--, 1);
				}
			}
		},

		/**
		 * Will generate the server token for comparasion
		 * @param  {[Express Request Object]} req
		 * @return {[void]}
		 */
		generateToken : function(req)
		{
			this.token = this.baseToken;
			this.token.update(req.route.path);
			this.token.update(req.header(this.config.idHeader));

			if(this.config.validation.expires)
				this.token.update(req.header(this.config.timeHeader));

			this.token.update(req.header(this.config.tokenHeader));

			for(var key in req.body)
			{
				this.token.update(key + ":" + get[key]);
			}
		},

		/**
		 * Will validate the given token
		 * @param  {[Express Request Object]} req
		 * @param  {[String]} token
		 * @return {[boolean]}
		 */
		validate : function(req, token)
		{
			if(this.config.validation.expires)
			{
				var toCompareWith = req.header(this.config.timeHeader);
				toCompareWith = parseInt(toCompareWith);

				if(this.timestamp() - toCompareWith > this.config.validation.duration)
				{
					return false;
				}
				else
				{
					if(this.config.validation.oneTimeUse)
					{
						recycleUsedTokens();

						if(isTokenAlreadyUsed(token))
						{
							return false;
						}
					}
				}
			}

			generateToken(req);

			switch(this.config.output)
			{
				case this.constants.Hex:
					this.token = this.token.digest('hex');
					break;
			}

			return (this.token == token);
		},

		/**
		 * Will generate the current timestamp (in seconds, for Unix)
		 * @return {[Number]}
		 */
		timestamp : function()
		{
			// Why the fuck should we use timestamp in milliseconds?
			return parseInt(new Date().getTime()/1000);
		}
	}

	/**
	 * Stores all constants that we need
	 */
	var AuthConstants = function()
	{
		// Algorithms

		/*
		this.MD5 = 0x0;
		this.SHA1 = 0x1;
		this.SHA3 = 0x2;
		this.SHA256 = 0x3;
		this.SHA512 = 0x4;
		this.RIPEMD160 = 0x5;

		this.HmacMD5 = 0x6
		*/
		this.HmacSHA1 = 0x7;
		/*
		this.HmacSHA256 = 0x8;
		this.HmacSHA512 = 0x9;

		// Digests
		*/
		this.Hex = 0x10;
		/*
		this.Base64 = 0x11;
		this.Default = 0x12;
		*/
	}

	/**
	 * Exports the constants to the developer
	 */
	exports.Constants = function()
	{
		return new AuthConstants();
	}

	/**
	 * Exports the SafeAuth instance
	 * @param {[Object]} config
	 */
	exports.Auth = function(config)
	{
		return new SafeAuth(config);
	}
})();
