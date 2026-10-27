using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationSecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01: анонімний POST до справжнього захищеного endpoint -> 401, не 302 і не HTML.
    [Fact]
    public async Task A01_AnonymousCreateIncident_Returns401_NotRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", new
        {
            title = "A01 anonymous " + Guid.NewGuid().ToString("N")[..8],
            description = "anonymous create must be rejected",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: login -> /api/me повертає поточного користувача з principal і лише безпечні поля.
    [Fact]
    public async Task A02_LoginThenMe_ReturnsCurrentUserWithSafeFieldsOnly()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;

        Assert.Equal(DbSeeder.AliceId, root.GetProperty("userId").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());

        foreach (var forbidden in new[]
        {
            "password", "confirmPassword", "passwordHash", "securityStamp", "token", "cookie"
        })
        {
            Assert.False(
                root.EnumerateObject().Any(p => string.Equals(p.Name, forbidden, StringComparison.OrdinalIgnoreCase)),
                $"/api/me must not expose '{forbidden}'.");
        }
    }

    // A-05: Bob створює запис і додає чужий ownerUserId Alice -> фактичний власник лишається Bob.
    [Fact]
    public async Task A05_CreateWithForgedOwner_KeepsOwnerFromPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var title = "A05 forged owner " + Guid.NewGuid().ToString("N")[..8];

        using var response = await bob.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "owner must come from the principal",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5),
            ownerUserId = DbSeeder.AliceId   // підроблене поле, якого немає в request DTO
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var createdId = json.RootElement.GetProperty("id").GetGuid();

        // Перевіряємо фактичний стан БД, а не лише статус відповіді.
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == createdId);

        Assert.Equal(DbSeeder.BobId, incident.OwnerUserId);
        Assert.NotEqual(DbSeeder.AliceId, incident.OwnerUserId);
    }
}