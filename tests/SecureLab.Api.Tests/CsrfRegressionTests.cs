using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;

namespace SecureLab.Api.Tests;

/// <summary>
/// REG-CSRF-01 (ЛР 6): PUT /api/incidents/{id} з чинною cookie входу,
/// але без або з невалідним request token → 400 і інцидент не змінився;
/// з валідною парою токенів → 204 і саме очікувана зміна.
/// Працює з власним тимчасовим інцидентом, seed не змінює.
/// </summary>
public sealed class CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task REG_CSRF_01_Update_WithoutValidToken_IsRejected_StateUnchanged_ThenValidPairSucceeds()
    {
        using var alice = await factory.LoginAsync("alice", Password);

        // Підготовка: власний інцидент тесту (створюється з валідним токеном).
        await alice.UseAntiforgeryTokenAsync();
        using var created = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title = "REG-CSRF-01 before",
            description = "Тимчасовий інцидент REG-CSRF-01",
            severity = "Low",
            occurredAtUtc = "2026-08-04T09:00:00+00:00"
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonObject>())!["id"]!.GetValue<string>();
        var url = $"/api/incidents/{id}";
        var change = new
        {
            title = "REG-CSRF-01 after",
            description = "Тимчасовий інцидент REG-CSRF-01",
            occurredAtUtc = (DateTimeOffset?)null
        };

        try
        {
            var before = await alice.GetFromJsonAsync<JsonObject>(url);
            Assert.Equal("REG-CSRF-01 before", before!["title"]!.GetValue<string>());

            // 1. Та сама cookie входу, але БЕЗ request token → 400, стан не змінився.
            alice.DefaultRequestHeaders.Remove(AntiforgeryTestExtensions.HeaderName);
            using var noToken = await alice.PutAsJsonAsync(url, change);
            Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
            var problem = await noToken.Content.ReadFromJsonAsync<JsonObject>();
            Assert.Equal("Antiforgery token is missing or invalid.", problem!["title"]!.GetValue<string>());
            Assert.True(JsonNode.DeepEquals(before, await alice.GetFromJsonAsync<JsonObject>(url)));

            // 2. НЕВАЛІДНИЙ request token → 400, стан не змінився.
            using var invalidRequest = new HttpRequestMessage(HttpMethod.Put, url)
            {
                Content = JsonContent.Create(change)
            };
            invalidRequest.Headers.Add(AntiforgeryTestExtensions.HeaderName, "invalid-test-value");
            using var invalid = await alice.SendAsync(invalidRequest);
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
            Assert.True(JsonNode.DeepEquals(before, await alice.GetFromJsonAsync<JsonObject>(url)));

            // 3. ВАЛІДНА пара токенів → 204 і саме очікувана зміна.
            await alice.UseAntiforgeryTokenAsync();
            using var accepted = await alice.PutAsJsonAsync(url, change);
            Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
            var after = await alice.GetFromJsonAsync<JsonObject>(url);
            Assert.Equal("REG-CSRF-01 after", after!["title"]!.GetValue<string>());
        }
        finally
        {
            // Прибирання: видаляємо власний тимчасовий інцидент.
            await alice.UseAntiforgeryTokenAsync();
            using var cleanup = await alice.DeleteAsync(url);
        }
    }
}