using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;


public sealed class CookiePathDefenseTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string MainCookieName = ".AspNetCore.Identity.Application";

    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task MainCookie_IsIssuedWithSafeAttributes()
    {

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        using var login = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "bob", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

        var attributes = MainCookieAttributes(login);

        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);


        Assert.Contains(attributes, attribute => attribute.StartsWith("path=/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Bob_CookieReachesOnlyEndpointsUnderItsPath()
    {

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var login = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "bob", password = Password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);

        var path = MainCookieAttributes(login)
            .Single(attribute => attribute.StartsWith("path=", StringComparison.Ordinal))
            ["path=".Length..];


        using var me = await client.GetAsync("/api/me");
        using var sessionCheck = await client.GetAsync("/api/auth/session-check");


        var (expectedMe, expectedSession) = path switch
        {
            "/" => (HttpStatusCode.OK, HttpStatusCode.NoContent),
            "/api/auth" => (HttpStatusCode.Unauthorized, HttpStatusCode.NoContent),       // А
            "/api/incidents" => (HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized), // Б
            "/api/me" => (HttpStatusCode.OK, HttpStatusCode.Unauthorized),                 // В
            _ => throw new InvalidOperationException($"Немає прогнозу для Path={path}")
        };

        Assert.True(me.StatusCode == expectedMe,
            $"Path={path}: /api/me очікувано {(int)expectedMe}, фактично {(int)me.StatusCode}");
        Assert.True(sessionCheck.StatusCode == expectedSession,
            $"Path={path}: session-check очікувано {(int)expectedSession}, фактично {(int)sessionCheck.StatusCode}");
    }

  
    private static string[] MainCookieAttributes(HttpResponseMessage response)
    {
        var header = response.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith(MainCookieName + "=", StringComparison.Ordinal));

        return header.Split(';')
            .Skip(1)                                          
            .Select(attribute => attribute.Trim().ToLowerInvariant())
            .ToArray();
    }
}
