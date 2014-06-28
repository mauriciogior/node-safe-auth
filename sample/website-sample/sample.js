var Sample = function()
{
	this.baseToken;
	this.token;

	this.id;

	this.time;
}

Sample.prototype =
{
	init : function(id, secret)
	{
		this.id = id;
		this.baseToken = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, secret);
	},

	generateToken : function(path, data)
	{
		this.token = this.baseToken;
		this.token.update(path);
		this.token.update(this.id);

		this.token.update(this.time);

		/**
		 * We are skipping this step because we are using SHA1.
		 *
		for(var key in data)
		{
			this.token.update(key + ":" + data[key]);
		}
		*/
	
		this.token = this.token.finalize().toString();
	},

	prepareData : function(data)
	{
		var query = [];

		for (var key in data)
		{
			query.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
		}

		return query.join('&');
	},

	doRequest : function(url, path, method, data)
	{
		var request = new XMLHttpRequest();

		var dataToSend = this.prepareData(data);

		request.open(this.method, url, true);

		request.onreadystatechange = function()
		{
			if(request.readyState == 4)
			{
				console.log(request.status);
				console.log(request.responseText);
			}
		}

		if(method == 'post')
		{
			request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
		}
		else if(method == 'get')
		{
			request.setRequestHeader('Content-type', 'text/plain');
		}

		this.time = this.timestamp();

		request.setRequestHeader('X-AUTH-TIME', this.time);
		request.setRequestHeader('X-AUTH-TOKEN', this.generateToken(path, data));
		request.setRequestHeader('X-AUTH-ID', this.id);

		request.send(dataToSend);
	},

	timestamp : function()
	{
		// Why the fuck should we use timestamp in milliseconds?
		return parseInt(new Date().getTime()/1000);
	}
}

var sample = new Sample();

sample.init("0", "123454124124146");

var data = { username : "test" };
var url = "http://localhost:3000/";
var path = "/";
var method = "get";

sample.doRequest(url, path, method, data);
