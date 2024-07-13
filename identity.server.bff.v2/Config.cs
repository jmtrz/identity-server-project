
using Duende.IdentityServer.Models;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace identity.server.bff.v2;

public static class Config
{
    private static List<string> AllIdentityScopes => IdentityResources.Select(s => s.Name).ToList();
    private static List<string> AllApiScopes => ApiScopes.Select(s => s.Name).ToList();
    private static List<string> AllScopes => AllApiScopes.Concat(AllIdentityScopes).ToList();
    public static IEnumerable<IdentityResource> IdentityResources =>
           new List<IdentityResource>
           {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
           };
    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        {
                // backward compat
                new ApiScope("api"),
                
                // resource specific scopes
                new ApiScope("resource1.scope1"),
                new ApiScope("resource1.scope2"),

                new ApiScope("resource2.scope1"),
                new ApiScope("resource2.scope2"),

                new ApiScope("resource3.scope1"),
                new ApiScope("resource3.scope2"),
                
                // a scope without resource association
                new ApiScope("scope3"),
                new ApiScope("scope4"),
                
                // a scope shared by multiple resources
                new ApiScope("shared.scope"),

                // a parameterized scope
                new ApiScope("transaction", "Transaction")
                {
                    Description = "Some Transaction"
                }
        };
    public static IEnumerable<Client> Clients => new Client[] 
    {
       new Client
                {
                    ClientId = "interactive.public",
                    ClientName = "Interactive client (Code with PKCE)",

                    RedirectUris = { "https://notused" },
                    PostLogoutRedirectUris = { "https://notused" },

                    RequireClientSecret = false,

                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = AllScopes,

                    AllowOfflineAccess = true,
                },

    };
}
