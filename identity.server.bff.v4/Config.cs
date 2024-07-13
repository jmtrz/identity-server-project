using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace identity.server.bff.v4
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId()
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
                { 
                    new ApiScope("open","email")
                };

        public static IEnumerable<Client> Clients =>
            new Client[]
                {
                    new Client
                    {
                        ClientId = "web",
                        ClientSecrets = { new Secret("secret".Sha256())},
                        AllowedGrantTypes = GrantTypes.Code,
                        RedirectUris = { "https://localhost:5173/signin-oidc" },
                        PostLogoutRedirectUris = { "https://localhost:5173/signout-callback-oidc" },
                        AllowedScopes = new List<string>
                        {
                            IdentityServerConstants.StandardScopes.OpenId,
                            IdentityServerConstants.StandardScopes.Profile,
                            "verification"
                        }
                    }
                };
    }
}