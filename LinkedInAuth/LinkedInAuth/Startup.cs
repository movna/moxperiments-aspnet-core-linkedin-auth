using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace LinkedInAuth
{
	public class Startup
	{
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddAuthentication(sharedOptions => {
				// Registers the cookie auth as the default scheme
				sharedOptions.SignInScheme =
					CookieAuthenticationDefaults.AuthenticationScheme;
			});
			services.AddMvc();
		}

		public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
		{
			loggerFactory.AddConsole();

			if (env.IsDevelopment())
				app.UseDeveloperExceptionPage();

			// Configures cookie auth pipeline
			app.UseCookieAuthentication(
				new CookieAuthenticationOptions
				{
					AutomaticAuthenticate = true,
					ExpireTimeSpan = TimeSpan.FromDays(4),
					SlidingExpiration = false
				});

			// Configures LinkedIn OAuth pipeline
			app.UseOAuthAuthentication(new OAuthOptions
			{
				ClientId = "<CLIENT-ID>",
				ClientSecret = "<CLIENT-SECRET>",
				AuthenticationScheme = "linkedin",
				AutomaticAuthenticate = true,
				// If an unauthorized user tries to access an [Authorized]
				// action and if there is an auth pipeline configured to
				// accept AutomaticChallenge, that particular pipeline is
				// picked up for the challenge
				AutomaticChallenge = true,
				// This is used as the return url parameter in
				// OAuth request and the pipeline listens on this endpoint
				// to handle response from LinkedIn
				CallbackPath = new PathString("/signin-linkedin"),
				// Long story short on OAuth 2.0, the below endpoint
				// is where user gets redirected and after authorizes the app
				// an Authorization code is given
				AuthorizationEndpoint =
					"https://www.linkedin.com/oauth/v2/authorization",
				// Passing the Authorization code with ClientId and
				// ClientSecret to the below endpoint will give
				// an user access token
				TokenEndpoint =
					"https://www.linkedin.com/oauth/v2/accessToken",
				// Passing the access token to the below endpoint will
				// give unique 'id' for the user, specific to the app,
				// 'email-address' and 'formatted-name'
				// For more fields you can check docs at -
				// https://developer.linkedin.com/docs/fields/basic-profile
				UserInformationEndpoint =
					"https://api.linkedin.com/v1/people/~:(id,email-address,formatted-name)",
				Scope = { "r_basicprofile", "r_emailaddress" },
				Events = new OAuthEvents
				{
					// 
					OnCreatingTicket = async context =>
					{
						var claimsRequest = new HttpRequestMessage(HttpMethod.Get,
							new Uri(context.Options.UserInformationEndpoint));
						// Add the token we received from LinkedIn
						claimsRequest.Headers.Authorization =
							new AuthenticationHeaderValue("Bearer", context.AccessToken);
						// Ask for JSON format
						claimsRequest.Headers.Add("x-li-format", "json");

						// Use the back channel already available to make the request
						var claimsResponse = await context.Backchannel
							.SendAsync(claimsRequest, context.HttpContext.RequestAborted)
							.ConfigureAwait(false);
						claimsResponse.EnsureSuccessStatusCode();

						// Deserialize the response
						var linkedInClaims = JsonConvert.DeserializeObject<LinkedInClaims>
						(await claimsResponse.Content.ReadAsStringAsync()
							.ConfigureAwait(false));

						// Add it to claims
						context.Identity.AddClaim(new Claim(
							ClaimTypes.NameIdentifier, linkedInClaims.Id));
						context.Identity.AddClaim(new Claim(
							ClaimTypes.Email, linkedInClaims.EmailAddress));
						context.Identity.AddClaim(new Claim(
							ClaimTypes.Name, linkedInClaims.FormattedName));
					}
				}
			});

			app.UseMvc();
		}
	}

	public class LinkedInClaims
	{
		public string Id { get; set; }
		public string EmailAddress { get; set; }
		public string FormattedName { get; set; }
	}
}