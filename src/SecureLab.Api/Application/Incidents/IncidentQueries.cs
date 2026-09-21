using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(Guid id, CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }


public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Loading incident severity summary");

        // 1–4. Агрегація з PostgreSQL через EF Core
        var dbGrouped = await dbContext.Incidents
            .AsNoTracking()
            .GroupBy(x => x.Severity)
            .Select(g => new
            {
                Severity = g.Key.ToString(),
                Count = g.Count()
            })
            .ToListAsync(cancellationToken);

        // 5. Політика нульових груп: заповнюємо всі значення Enum IncidentSeverity
        var allSeverities = Enum.GetNames<IncidentSeverity>();

        var summaryWithZeros = allSeverities
            .Select(sev => new IncidentSeveritySummaryResponse(
                severity: sev,
                count: dbGrouped.FirstOrDefault(x => string.Equals(x.Severity, sev, StringComparison.OrdinalIgnoreCase))?.Count ?? 0
            ));

        // 6. Порядок сортування за критичністю
        var priorityOrder = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "Critical", 1 },
            { "High", 2 },
            { "Medium", 3 },
            { "Low", 4 }
        };

        return summaryWithZeros
            .OrderBy(x => priorityOrder.GetValueOrDefault(x.Severity, 99))
            .ToList();
    }
}
