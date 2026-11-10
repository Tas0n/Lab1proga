using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

/// <summary>
/// ЛР 4: authorization test matrix (A-01 … A-12, добрий рівень).
/// Правила:
/// • один користувач — один HttpClient зі своєю cookie;
/// • негативні mutation-тести читають стан до і після дозволеним клієнтом;
/// • позитивні mutation-тести працюють лише з власноруч створеним інцидентом
///   і прибирають його у finally, тому seed не змінюється і тести повторювані.
/// Перед повним запуском: зупинити API, виконати --reset-database.
/// </summary>
public sealed class IncidentAuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Сталі seed-ідентифікатори baseline 2-A, яких немає в DbSeeder.
    public static readonly Guid AliceNewIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000003");
    public static readonly Guid BobNewIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid CommentOnAliceId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid CommentOnBobId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private const string BobUserId = "10000000-0000-0000-0000-000000000002";

    private static string Password =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private Task<HttpClient> LoginAsync(string userName) => factory.LoginAsync(userName, Password);

    // ---------- A-01: анонім ----------

    [Fact]
    public async Task A01_Details_AsAnonymous_Returns401WithoutRedirect()
    {
        using var anonymous = factory.CreateClient(
            new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
            });

        using var response = await anonymous.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);                         // без HTML redirect
    }

    // ---------- A-02 / A-03 / A-10: details ----------

    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(DbSeeder.AliceIncidentId.ToString(), body!["id"]!.GetValue<string>());
        Assert.Equal("Аліса Коваль", body["ownerDisplayName"]!.GetValue<string>());
    }

    [Fact]
    public async Task A03_A10_Details_AsNonOwner_ReturnsSame404AsUnknownId_WithoutData()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignText = await foreign.Content.ReadAsStringAsync();
        var foreignBody = JsonNode.Parse(foreignText)!.AsObject();
        var unknownBody = (await unknown.Content.ReadFromJsonAsync<JsonObject>())!;
        foreignBody.Remove("traceId");                                  // єдина дозволена відмінність
        unknownBody.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));

        Assert.DoesNotContain("Боб Мельник", foreignText);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), foreignText);
    }

    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsForeignIncident_WithInternalComments()
    {
        using var morgan = await LoginAsync("morgan");
        using var alice = await LoginAsync("alice");

        var asAnalyst = await morgan.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var asOwner = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(DbSeeder.AliceIncidentId.ToString(), asAnalyst!["id"]!.GetValue<string>());
        // Internal comment бачить лише Analyst, тому коментарів у нього більше.
        Assert.True(asAnalyst["comments"]!.AsArray().Count > asOwner!["comments"]!.AsArray().Count);
    }

    // ---------- A-04: чужий update / delete, стан не змінюється ----------

    [Fact]
    public async Task A04_Update_AsNonOwner_Returns404_AndDoesNotChangeIncident()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        var before = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");

        using var response = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "changed by alice", description = "x", occurredAtUtc = (DateTimeOffset?)null });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var after = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.True(JsonNode.DeepEquals(before, after));
    }

    [Fact]
    public async Task A04_Delete_AsNonOwner_Returns404_AndIncidentStillExists()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");

        using var response = await alice.DeleteAsync($"/api/incidents/{BobNewIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var after = await bob.GetAsync($"/api/incidents/{BobNewIncidentId}");
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
    }

    [Fact]
    public async Task Update_AsAnalyst_Returns403_AndDoesNotChangeIncident()
    {
        using var morgan = await LoginAsync("morgan");
        using var alice = await LoginAsync("alice");
        var before = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");

        using var response = await morgan.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "analyst edit", description = "x", occurredAtUtc = (DateTimeOffset?)null });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.True(JsonNode.DeepEquals(before, after));
    }

    [Fact]
    public async Task Update_And_Delete_AsOwner_OnOwnNewIncident_Succeed()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var update = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = "Оновлено власником", description = "owner update", occurredAtUtc = "2026-08-04T10:00:00+00:00" });
            Assert.Equal(HttpStatusCode.NoContent, update.StatusCode);
            var updated = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
            Assert.Equal("Оновлено власником", updated!["title"]!.GetValue<string>());

            using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
            using var afterDelete = await alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, afterDelete.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-05: list ----------

    [Fact]
    public async Task A05_List_AsReporter_ReturnsOnlyOwnIncidents()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        var aliceIds = await ListIdsAsync(alice);
        var analystIds = await ListIdsAsync(morgan);

        Assert.Contains(DbSeeder.AliceIncidentId, aliceIds);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, aliceIds);
        Assert.DoesNotContain(BobNewIncidentId, aliceIds);
        // Analyst бачить усі — правило матриці.
        Assert.Contains(DbSeeder.AliceIncidentId, analystIds);
        Assert.Contains(DbSeeder.BobIncidentId, analystIds);
    }

    // ---------- A-06 / A-09: privileged transition для Reporter ----------

    [Fact]
    public async Task A06_Triage_AsReporterOwner_Returns403_AndStatusStaysNew()
    {
        using var alice = await LoginAsync("alice");
        var before = await StatusAsync(alice, AliceNewIncidentId);

        using var response = await alice.PostAsync($"/api/incidents/{AliceNewIncidentId}/triage", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("New", before);
        Assert.Equal("New", await StatusAsync(alice, AliceNewIncidentId));
        // traceId у відповіді — той, що потрапляє в audit event (A-09).
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(string.IsNullOrEmpty(problem!["traceId"]?.GetValue<string>()));
    }

    [Fact]
    public async Task A06_Triage_AsOtherReporter_WithForgedBody_Returns403_AndStatusStaysNew()
    {
        using var bob = await LoginAsync("bob");
        using var alice = await LoginAsync("alice");

        using var response = await bob.PostAsJsonAsync(
            $"/api/incidents/{AliceNewIncidentId}/triage",
            new { role = "Analyst", status = "Triaged", isTransitionAllowed = true });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("New", await StatusAsync(alice, AliceNewIncidentId));
    }

    [Fact]
    public async Task A06_Triage_AsReporter_ForUnknownId_Returns403_NotRevealingExistence()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.PostAsync($"/api/incidents/{Guid.NewGuid()}/triage", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---------- A-07: permitted transition ----------

    [Fact]
    public async Task A07_Triage_AsAnalyst_OnNewIncident_Returns204_AndStatusTriaged()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var id = await CreateIncidentAsync(alice);                     // власний ресурс тесту, status New
        try
        {
            Assert.Equal("New", await StatusAsync(morgan, id));

            using var response = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            Assert.Equal("Triaged", await StatusAsync(morgan, id));

            using var again = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);   // уже не New
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-08a: forged owner/role/status у regular update ----------

    [Fact]
    public async Task A08a_Update_WithForgedProtectedFields_IgnoresThem()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            var before = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");

            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = "Forged fields test",
                description = "спроба змінити privileged state",
                occurredAtUtc = "2026-08-04T10:00:00+00:00",
                ownerUserId = BobUserId,
                status = "Closed",
                severity = "Critical",
                role = "Analyst",
                isTransitionAllowed = true
            });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);   // заздалегідь визначений success
            var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
            Assert.Equal("Forged fields test", after!["title"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
            Assert.Equal(before!["severity"]!.GetValue<string>(), after["severity"]!.GetValue<string>());
            Assert.Equal("Аліса Коваль", after["ownerDisplayName"]!.GetValue<string>());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-12: child resource ----------

    [Fact]
    public async Task A12_Comment_OnForeignIncident_Returns404()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incident-comments/{CommentOnBobId}");
        using var own = await alice.GetAsync($"/api/incident-comments/{CommentOnAliceId}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
    }

    [Fact]
    public async Task A12_InternalComment_VisibleOnlyToAnalyst()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        using var asReporter = await alice.GetAsync($"/api/incident-comments/{InternalCommentId}");
        using var asAnalyst = await morgan.GetAsync($"/api/incident-comments/{InternalCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, asReporter.StatusCode);
        Assert.Equal(HttpStatusCode.OK, asAnalyst.StatusCode);
    }

    // ---------- helpers ----------

    private static async Task<string> StatusAsync(HttpClient client, Guid id)
    {
        var body = await client.GetFromJsonAsync<JsonObject>($"/api/incidents/{id}");
        return body!["status"]!.GetValue<string>();
    }

    private static async Task<List<Guid>> ListIdsAsync(HttpClient client)
    {
        var items = await client.GetFromJsonAsync<JsonArray>("/api/incidents");
        return items!.Select(item => Guid.Parse(item!["id"]!.GetValue<string>())).ToList();
    }

    /// <summary>Створює власний інцидент тесту; owner/status/id задає сервер.</summary>
    private static async Task<Guid> CreateIncidentAsync(HttpClient owner)
    {
        using var response = await owner.PostAsJsonAsync("/api/incidents", new
        {
            title = "ЛР4 test fixture",
            description = "Тимчасовий інцидент тесту; видаляється у finally",
            severity = "Low",
            occurredAtUtc = "2026-08-04T09:00:00+00:00"
        });
        Assert.True(response.IsSuccessStatusCode, $"Create failed: {(int)response.StatusCode}");

        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        if (body?["id"] is { } idNode)
        {
            return Guid.Parse(idNode.GetValue<string>());
        }

        var location = response.Headers.Location?.ToString()
            ?? throw new InvalidOperationException("Create returned neither id nor Location.");
        return Guid.Parse(location.TrimEnd('/').Split('/').Last());
    }

    /// <summary>Прибирає лише власний запис тесту разом із дочірніми рядками.</summary>
    private async Task DeleteIncidentAsync(Guid id)
    {
        using var scope = factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await dbContext.Incidents
            .Include(x => x.Comments)
            .SingleOrDefaultAsync(x => x.Id == id);
        if (incident is null)
        {
            return;
        }

        dbContext.RemoveRange(incident.Comments);
        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync();
    }
}
