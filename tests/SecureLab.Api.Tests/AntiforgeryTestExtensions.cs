using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

/// <summary>ЛР 6: отримати request token тим самим cookie-клієнтом і додати його в header.</summary>
public static class AntiforgeryTestExtensions
{
    public const string TokenRoute = "/api/antiforgery/token";
    public const string HeaderName = "X-CSRF-TOKEN";

    private sealed record TokenResponse(string Token);

    public static async Task UseAntiforgeryTokenAsync(this HttpClient client)
    {
        client.DefaultRequestHeaders.Remove(HeaderName);
        using var response = await client.GetAsync(TokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
        {
            throw new InvalidOperationException("Missing request token.");
        }
        client.DefaultRequestHeaders.Add(HeaderName, body.Token);
    }
}