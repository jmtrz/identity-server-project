using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using System.Net.Http.Headers;
using System.Security.Claims;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<TokenDatabase>()
    .AddHttpClient()
    .AddDataProtection();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(tCtx =>
    {
        tCtx.AddRequestTransform(rc =>
        {
            if ((rc.HttpContext.User.Identity?.IsAuthenticated ?? false) && rc.DestinationPrefix == "https://googleapis.com")
            { 
                var tokenDb = rc.HttpContext.RequestServices.GetRequiredService<TokenDatabase>();
                var userId = rc.HttpContext.User.FindFirst("id")?.Value;
                var token = tokenDb.GetToken(userId);

                rc.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            }
            return ValueTask.CompletedTask;
        });
    });


builder.Services
    .AddAuthentication("auth-cookie")
    .AddOAuth("youtube", o =>
    {
        o.SignInScheme = "auth-cookie";

        o.SaveTokens = false;

        o.Scope.Clear();
        o.Scope.Add("https://www.googleapis.com/auth/youtube.readonly");

        o.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        o.TokenEndpoint = "https://oauth2.googleapis.com/token";
        o.CallbackPath = "/oauth/yt-cb";

        o.Events.OnCreatingTicket = async ctx =>
        {
            var tokenDatabase = ctx.HttpContext.RequestServices.GetRequiredService<TokenDatabase>();
            var authenticationHandlerProvider = ctx.HttpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();

            var handler = await authenticationHandlerProvider.GetHandlerAsync(ctx.HttpContext, "auth-cookie");
            var authResult = await handler.AuthenticateAsync();
            
            if(!authResult.Succeeded)
            {
                ctx.Fail("failed authentication");
                return;
            }

            var cp = authResult.Principal;
            var userId = cp.FindFirstValue("id");
            tokenDatabase.StoreToken(userId!, ctx.AccessToken ?? "");

            ctx.Principal = cp.Clone();
            var identity = ctx.Principal.Identities.First(x => x.AuthenticationType == "auth-cookie");
            identity.AddClaim(new Claim("yt-token", "y"));
        };

    });

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("youtube-enabled", pb =>
    {
        pb.AddAuthenticationSchemes("auth-cookie")
               .RequireClaim("yt-token", "y")
               .RequireAuthenticatedUser();
    });
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.MapGet("/api/login", (TokenDatabase tDb) =>
{
    var userId = "user_identifier";
    List<Claim> claim = new() { new Claim("id", userId) };

    if(!string.IsNullOrEmpty(tDb.GetToken(userId)))
    {
        claim.Add(new Claim("yt-token", "y"));
    }

    return Results.SignIn(
        new(new ClaimsIdentity(claim, "auth-coookie")),
        authenticationScheme: "auth-cookie"
    );
});

app.MapGet("/api/user", (ClaimsPrincipal user) => new
{
    Id = user.FindFirst("id")?.Value,
    YtEnabled = user.FindFirst("yt-token")?.Value == "y"
}).RequireAuthorization();

app.MapGet("/api/youtube-connect", () => Results.Challenge(
    new AuthenticationProperties()
    {
        RedirectUri = "/"
    },
    authenticationSchemes: new List<string>() { "youtube" }
));

//app.MapGet("/api-yt", async (
//    IHttpClientFactory clientFactory, 
//    ClaimsPrincipal user,
//    TokenDatabase tDb) =>
//{
//    var userId = user.FindFirst("id")?.Value;
//    var token = tDb.GetToken(userId);
//    var client = clientFactory.CreateClient();

//    using var req = new HttpRequestMessage(HttpMethod.Get, 
//        "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true");
//    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

//    using var response = await client.SendAsync(req);
//    return await response.Content.ReadAsStringAsync();

//}).RequireAuthorization("youtube-enabled");

app.MapReverseProxy();

app.MapForwarder("/{**rest}", "http://127.0.0.1:7151");

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public class TokenDatabase
{
    private readonly IDataProtectionProvider _dataProtection;
    public Dictionary<string, string> _database = new();

    public TokenDatabase(IDataProtectionProvider dataProtection)
    {
        _dataProtection = dataProtection;
    }

    public string? GetToken(string userId)
    {
        if(_database.TryGetValue(userId, out var token))
        {
            var protector = _dataProtection.CreateProtector(userId);
            return protector.Unprotect(token);
        }
        return null;
    }

    public void StoreToken(string id, string token)
    {
        var protector = _dataProtection.CreateProtector(id + "token");
        _database[id] = protector.Protect(token);
    }
}