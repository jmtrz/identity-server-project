using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle

builder.Services
    .AddHttpClient()
    .AddDataProtection();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddTransforms(tCtx =>
    {
        tCtx.AddRequestTransform(async rc =>
        {
            if ((rc.HttpContext.User.Identity?.IsAuthenticated ?? false ) && rc.DestinationPrefix == "https://googleapis.com")
            {
                var accessToken = await rc.HttpContext.GetTokenAsync("access_token");
                rc.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer",accessToken);

            }
        });
    });

builder.Services.AddAuthentication("auth-cookie")
     .AddCookie("auth-cookie")
     .AddOAuth("google", o =>
     {
         o.SignInScheme = "auth-cookie";

         o.SaveTokens = true;

         o.Scope.Clear();
         o.Scope.Add("https://www.googleapis.com/auth/youtube.readonly");

         o.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
         o.TokenEndpoint = "https://oauth2.googleapis.com/token";
         o.CallbackPath = "/oauth/yt-cb";
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

app.MapGet("/login", () => Results.Challenge(
    new AuthenticationProperties()
    {
        RedirectUri = "/"
    },
    authenticationSchemes: new List<string>() { "google" }
));

app.MapReverseProxy();

//app.MapGet("/api-yt", async (IHttpClientFactory clientFactory, HttpContext ctx) =>
//{
//    var accessToken = await ctx.GetTokenAsync("access_token");
//    var client = clientFactory.CreateClient();

//    using var req = new HttpRequestMessage(HttpMethod.Get, "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true");
//    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

//    using var response = await client.SendAsync(req);
//    return await response.Content.ReadAsStringAsync();

//}).RequireAuthorization();

app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
