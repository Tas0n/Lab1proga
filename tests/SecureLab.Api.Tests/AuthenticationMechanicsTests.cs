using System.Net;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task RealCookie_ReachesSessionCheck()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        using var client = await factory.LoginAsync("alice", password);
        using var response = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }
}
