using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ApiTester
{
	class Program
	{
		static void Main(string[] args)
		{
			var uri = "http://avenger.com:12345";
			var redirectUri = "http://www.google.com";
			var code = "code";
			var apiKey = "ABC";
			var secret =
				"55/qGG7xjYt0yJ/LOCr49wFv8noA+twwLsoVElS6Q393P0CK87n1bsd5EWHBkjn/51tvtUPOGxjxcCWg5/OV048PssYPRs3yYIntZaK2BVHTCJBSzbAHkfYYmgUWTSYTjHOvHfdlgdXMwAK6WlbXbKZXJVQvXyOXua1UCZENlk4=";
			var verifier = $"{apiKey}::{DateTime.UtcNow}";
			var signature = GetSignature(secret, verifier);
			var requestUri = $"{uri}/oauth/authorization?apiKey={apiKey}&signature={signature}&response_type={code}&redirect_uri={redirectUri}&verifier={verifier}";

			var request = (HttpWebRequest) WebRequest.Create(requestUri);

			request.Method = "GET";
			request.ServicePoint.Expect100Continue = false;
			request.ContentType = "x-www-form-urlencoded";

			var response = (HttpWebResponse) request.GetResponse();

			Console.WriteLine(response.ResponseUri);
		}

		private static string GetSignature(string secret, string verifier)
		{
			var encoding = new ASCIIEncoding();
			var originalData = encoding.GetBytes(verifier);
			var keyBytes = encoding.GetBytes(secret);

			using (var hmacsha256 = new HMACSHA256(keyBytes))
			{
				try
				{
					var signedBytes = hmacsha256.ComputeHash(originalData);
					return WebUtility.UrlEncode(Convert.ToBase64String(signedBytes));
				}
				catch (CryptographicException)
				{
					throw new UnauthorizedAccessException();
				}
			}
		}
	}
}
