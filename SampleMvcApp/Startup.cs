﻿using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Auth0.AuthenticationApi;

namespace SampleMvcApp
{
    using System;

    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add authentication services
            services.AddAuthentication(
                options => options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

            // Add framework services.
            services.AddMvc();

            // Add functionality to inject IOptions<T>
            services.AddOptions();

            // Add the Auth0 Settings object so it can be injected
            services.Configure<Auth0Settings>(Configuration.GetSection("Auth0"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, IOptions<Auth0Settings> auth0Settings)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            // Add the cookie middleware
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                ExpireTimeSpan = new TimeSpan(7,0,0,0),
                SlidingExpiration = true,
                Events = new CookieAuthenticationEvents()
                             {
                                OnValidatePrincipal = TokenExpirationValidation.ValidateExpirationAndTryRefresh,
                             }
                
                
            });

            // Add the OIDC middleware
            var options = new OpenIdConnectOptions("Auth0")
            {
                // Set the authority to your Auth0 domain
                Authority = $"https://{auth0Settings.Value.Domain}",

                // Configure the Auth0 Client ID and Client Secret
                ClientId = auth0Settings.Value.ClientId,
                ClientSecret = auth0Settings.Value.ClientSecret,

                // Do not automatically authenticate and challenge
                AutomaticAuthenticate = false,
                AutomaticChallenge = false,

                // Set response type to code
                ResponseType = "code",

                // Set the callback path, so Auth0 will call back to http://localhost:5000/signin-auth0 
                // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard 
                CallbackPath = new PathString("/signin-auth0"),

                // Configure the Claims Issuer to be Auth0
                ClaimsIssuer = "Auth0",
                Events = new OpenIdConnectEvents()
                {
                    // add device name, required to get a refresh_token
                    OnRedirectToIdentityProvider = context =>
                        {
                            // add device for refresh token request
                            context.ProtocolMessage.SetParameter("device","web app");
                            return Task.FromResult(0);
                        },
                    
                    // save tokens as claims, we are going to need them later.
                    OnTicketReceived = context =>
                    {
                        // Get the ClaimsIdentity
                        var identity = context.Principal.Identity as ClaimsIdentity;
                        if (identity != null)
                        {
                            // Check if token names are stored in Properties
                            if (context.Properties.Items.ContainsKey(".TokenNames"))
                            {
                                // Token names a semicolon separated
                                string[] tokenNames = context.Properties.Items[".TokenNames"].Split(';');

                                // Add each token value as Claim
                                foreach (var tokenName in tokenNames)
                                {
                                    // Tokens are stored in a Dictionary with the Key ".Token.<token name>"
                                    string tokenValue = context.Properties.Items[$".Token.{tokenName}"];

                                    identity.AddClaim(new Claim(tokenName, tokenValue));
                                }
                            }
                        }

                        return Task.FromResult(0);
                    }
                },
                SaveTokens = true
            };
            options.Scope.Clear();
            options.Scope.Add("openid");
            // request a refresh token
            // "device" value is also needed, see OpenIdConnectionOptions.Events.OnRedirectToIdentityProvider to
            // add this value to the authentication request.
            // If using Lock, additional scope and device param would go in Lock's configuration
            options.Scope.Add("offline_access");

            app.UseOpenIdConnectAuthentication(options);

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

    }
}
