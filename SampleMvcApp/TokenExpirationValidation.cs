namespace SampleMvcApp
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Auth0.AuthenticationApi;
    using Auth0.AuthenticationApi.Models;

    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;

    public static class TokenExpirationValidation
    {
        public static async Task ValidateExpirationAndTryRefresh(CookieValidatePrincipalContext context)
        {
            var auth0Settings = context.HttpContext.RequestServices.GetRequiredService<IOptions<Auth0Settings>>();
            var shouldReject = true;

            var expClaim = context.Principal.FindFirst(c => c.Type == "exp" && c.OriginalIssuer == $"https://{auth0Settings.Value.Domain}/");

            // Unix timestamp is seconds past epoch
            var validTo = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(int.Parse(expClaim.Value));

            if (validTo > DateTimeOffset.UtcNow)
            {
                shouldReject = false;
            }
            else
            {
                var refreshToken = context.Principal.FindFirst("refresh_token")?.Value;
                if (refreshToken != null)
                {
                    // Try to get a new id_token from auth0 using refresh token
                    var authClient = new AuthenticationApiClient(new Uri($"https://{auth0Settings.Value.Domain}"));
                    var newIdToken =
                        await
                        authClient.GetDelegationTokenAsync(
                            new RefreshTokenDelegationRequest(
                            auth0Settings.Value.ClientId,
                            auth0Settings.Value.ClientId,
                            refreshToken));

                    if (!string.IsNullOrWhiteSpace(newIdToken.IdToken))
                    {
                        var newPrincipal = ValidateJwt(newIdToken.IdToken, auth0Settings);
                        var identity = expClaim.Subject;
                        identity.RemoveClaim(expClaim);
                        identity.AddClaim(newPrincipal.FindFirst("exp"));

                        // Remove existing id_token claim
                        var tokenClaim = identity.FindFirst("id_token");
                        if (tokenClaim != null)
                        {
                            identity.RemoveClaim(tokenClaim);
                        }

                        // Add the new token claim
                        identity.AddClaim(new Claim("id_token", newIdToken.IdToken));

                        // TODO: if required, refresh identity with updated claims inside the new token
                        // or calling the /api/v2/user/{id}?

                        // How to reuse OpenIdConnectHandler's code to get the new profile
                        // and create the new Identity?
                        // see GetUserInformationAsync() in 
                        // https://github.com/aspnet/Security/blob/master/src/Microsoft.AspNetCore.Authentication.OpenIdConnect/OpenIdConnectHandler.cs

                        // now issue a new cookie
                        context.ShouldRenew = true;
                        shouldReject = false;
                    }
                }
            }

            if (shouldReject)
            {
                context.RejectPrincipal();

                // optionally clear cookie
                await context.HttpContext.Authentication.SignOutAsync("Auth0");
            }
        }

        private static ClaimsPrincipal ValidateJwt(string encodedJwt, IOptions<Auth0Settings> auth0Settings)
        {
            var tokenValidationParameters = new TokenValidationParameters
                                                {
                                                    //IssuerSigningKey = new SymmetricSecurityKey(Base64UrlEncoder.DecodeBytes(auth0Settings.Value.ClientSecret)),
                                                    ValidIssuer = $"https://{auth0Settings.Value.Domain}/",
                                                    ValidAudience = auth0Settings.Value.ClientId,
                                                    // no real signature validation, we are trusting the delegation endpoint here.
                                                    // Is that correct?
                                                    SignatureValidator =
                                                        (token, parameters) =>
                                                        new JwtSecurityTokenHandler().ReadJwtToken(token)
                                                };

            SecurityToken securityToken;

            var newPrincipal = new JwtSecurityTokenHandler().ValidateToken(
                encodedJwt,
                tokenValidationParameters,
                out securityToken);

            return newPrincipal;
        }
    }
}