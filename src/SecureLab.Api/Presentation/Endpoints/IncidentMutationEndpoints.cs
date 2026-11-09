using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;                    // SecureLabDbContext
using SecureLab.Api.Data.Entities;           // IncidentStatus
using SecureLab.Api.Presentation.Contracts;  // IncidentCommentResponse

namespace SecureLab.Api.Presentation.Endpoints;

/// <summary>
/// Контракт звичайного content update. Навмисно НЕ містить OwnerUserId,
/// Status, Severity, Role, Id і службових дат: їх визначає лише сервер.
/// </summary>
public sealed record UpdateIncidentRequest(
    string Title,
    string Description,
    DateTimeOffset? OccurredAtUtc);

/// <summary>
/// ЛР 4, VULNERABLE STATE (крок 4). Mutating perimeter, triage і child endpoint
/// у навмисно найпростішому вигляді: login вимагається, але ресурс шукається
/// ЛИШЕ за id, без ownership/role-рішення. Виправляється у fixed commit (крок 6).
/// </summary>
public static class IncidentMutationEndpoints
{
    public static IEndpointRouteBuilder MapIncidentMutationEndpoints(
        this IEndpointRouteBuilder app)
    {
        var incidents = app.MapGroup("/api/incidents").RequireAuthorization();
        incidents.MapPut("/{id:guid}", UpdateAsync);
        incidents.MapDelete("/{id:guid}", DeleteAsync);
        incidents.MapPost("/{id:guid}/triage", TriageAsync);

        app.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .RequireAuthorization();

        return app;
    }

    // VULNERABLE: будь-який автентифікований користувач змінює будь-який інцидент.
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Title)
            || string.IsNullOrWhiteSpace(request.Description))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["Title і description обов'язкові."]
            });
        }

        var incident = await dbContext.Incidents                 // tracked, без AsNoTracking
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        incident.Title = request.Title.Trim();
        incident.Description = request.Description.Trim();
        if (request.OccurredAtUtc is { } occurred)
        {
            incident.OccurredAtUtc = occurred.ToUniversalTime();
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // VULNERABLE: будь-який автентифікований користувач видаляє будь-який інцидент.
    private static async Task<IResult> DeleteAsync(
        Guid id,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // VULNERABLE: немає перевірки ролі Analyst -> вертикальне підвищення привілеїв.
    private static async Task<IResult> TriageAsync(
        Guid id,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід недоступний для поточного статусу",
                statusCode: StatusCodes.Status409Conflict);
        }

        incident.Status = IncidentStatus.Triaged;                // next status — лише сервер
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // VULNERABLE: child шукається лише за власним id; parent і IsInternal не перевіряються.
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var comment = await dbContext.Incidents
            .AsNoTracking()
            .SelectMany(incident => incident.Comments)
            .Where(comment => comment.Id == id)
            .Select(comment => new IncidentCommentResponse(
                comment.Id,
                comment.Author.DisplayName,
                comment.Text,
                comment.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null ? IncidentNotFound() : Results.Ok(comment);
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);
}
