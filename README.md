# Refresh token - server side

This example shows how to use a `refresh_token` on the server side, 
to periodically re-authenticate the user and get a refreshed `id_token` (and 
possibly refreshed claims).


## How it works


The basic idea is to use a session cookie lifetime that is longer than the `id_token` issued by the Identity Provider,
and try to obtain a refreshened `id_token` every time it expires. 

Since we need the `refresh_token` to obtain a new `id_token`, the `refresh_token` that is obtained
on the user's first authentication is stored alongside the user's claims. 

Every time the session cookie is validated,
the `exp` (**expiration**) claim (that came from the last `id_token`) is checked. 
If expired, we try to get a new `id_token` from the Identity Provider by using the refresh token.
The old `exp` claim is replaced with the new one, and at this time it would
also be possible to retrieve updated information about the user (by using either
the `/userinfo` endpoint, or the `/api/v2/users/{id}` endpoint).

The code adds a hook on the `OnValidatePrincipal` event on the CookieAuthenticationOptions.
The logic for handling the event is on the `TokenExpirationValidation` class.

## Getting a refresh_token

For this to work, we need to ask the Identity Provider for a `refresh_token` when a user
authenticates. If using Lock, it means adding the `offline_access` scope, and the `device` authentication 
parameter, like this:

```
<script>
  var lock = new Auth0Lock(clientId, auth0Domain, {
    auth: {
      redirectUrl: 'xxxx',
      responseType: 'code',
      params: {
        scope: 'openid offline_access',
        device: 'Web App'
      }
    }
  });
</script>
```


This example, however, is based on the [hosted login page sample](https://github.com/auth0-samples/auth0-aspnetcore-sample/tree/master/01-Login) for handling `/Account/Login`.
This means that the OpenIdConnect handler will redirect to Auth0's authorize endpoint
when an authentication is requested (to the `/authorize` endpoint). 

Thus, we need to add the scope when setting the OpenIdConnectOptions:

    options.Scope.Add("offline_access");

and handle the `OnRedirectToIdentityProvider` event to add the `device` parameter:

    Events = new OpenIdConnectEvents()
    {
        // add device name, required to get a refresh_token
        OnRedirectToIdentityProvider = context =>
            {
                // add device for refresh token request
                context.ProtocolMessage.SetParameter("device","Web App");
                return Task.FromResult(0);
            },
                    
## Storing the token
Since we are going to need the `refresh_token` to get the refreshed `id_token`, we
will store it as part of the user's claims. To do this, we add a handler to the 
`OnTicketReceived` event in the `OpenIdConnectOptions.Events`:

    OnTicketReceived = context =>
    {
        // store the tokens as claims
        [omitted for brevity]
    }
 
Note that in this code we are storing all tokens, but the only one actually needed is the `refresh_token`.
The code for saving the tokens comes from [this sample](https://github.com/auth0-samples/auth0-aspnetcore-sample/tree/master/04-Storing-Tokens).


## Getting Started

To run this quickstart you can fork and clone this repo.

Be sure to update the `appsettings.json` with your Auth0 settings:

```json
{
  "Auth0": {
    "Domain": "Your Auth0 domain",
    "ClientId": "Your Auth0 Client Id",
    "ClientSecret": "Your Auth0 Client Secret",
    "CallbackUrl": "http://localhost:5000/signin-auth0"
  } 
}
```

Then restore the NuGet packages and run the application:

```bash
# Install the dependencies
dotnet restore

# Run
dotnet run
```

You can shut down the web server manually by pressing Ctrl-C.

