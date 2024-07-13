using Microsoft.AspNetCore.Identity;

namespace identity.server.bff.v2.Models;

public class ApplicationUser :  IdentityUser
{
    public string? GivenName { get; set; }

    public string? FamilyName { get; set; }
}

