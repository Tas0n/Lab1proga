# Власна карта source-to-sink

Поле: Incident.Description. Рівень: достатній («Задовільно»).
Стан/commit: <VULNERABLE_HASH> (scaffold lab-05-start-v1 поверх v0.4.0).
Вхід: alice через /auth-lab.html, сторінка /browser-lab.html. Guid запису: <GUID marker-запису — заповнимо в етапі 2>.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | src/SecureLab.Api/Client/browser-lab.html, форма `#edit`, `<textarea name="description">` | текст, який ввів користувач | контрольоване користувачем |
| Request | src/SecureLab.Api/Client/browser-lab.js, обробник `submit` форми `#edit` → `fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" } })`, тіло `JSON.stringify({ title, description, severity, occurredAtUtc })` → endpoint src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs:58 `app.MapPost("/api/incidents", …)` | JSON field `description` (Network → POST /api/incidents → Payload); відповідь 201 `CreatedIncidentResponse` поля description не містить | контрольоване користувачем; JSON-серіалізація не очищує HTML |
| Validation/mapping | src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs: `CreateIncidentRequest(string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc)` (ряд. 130); перевірки ряд. 74 (порожнє) і 76 (`Length > 4000`); ряд. 94 `request.Description?.Trim() ?? ""`; ряд. 102 `Description = description` у новій entity `Incident` | те саме значення, лише обрізані крайові пробіли | validation перевіряє наявність і довжину, але не робить текст безпечним HTML; `<`, `>` і лапки дозволені |
| Storage | src/SecureLab.Api/Data/Entities/Incident.cs:8 `Incident.Description`; SecureLabDbContext.cs:37 → PostgreSQL таблиця `incidents`, колонка `description`, `varchar(4000)` | збережене значення | збережене значення користувача; запис у БД не робить його trusted |
| Response | src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs:21 `group.MapGet("/{id:guid}", GetDetailsAsync)` → src/SecureLab.Api/Application/Incidents/IncidentQueries.cs ‹GetDetailsAsync›: фільтр `IncidentAccessRules.VisibleTo(userId, isAnalyst)`, ряд. 54 `incident.Description` → src/SecureLab.Api/Presentation/Contracts/IncidentResponses.cs `IncidentDetailsResponse.Description`; GET /api/incidents/{id} | JSON field `description` (Network → GET → Preview) | недовірене для відображення; `VisibleTo` перевіряє право на читання (ЛР4), а не безпечність тексту; projection без HTML-очищення; JSON-escape (`\"`) не захищає HTML sink |
| Client transform | src/SecureLab.Api/Client/browser-lab.js, функція `load()`: `current = await response.json()` → `current.description` | значення без змін | жодного очищення чи екранування на клієнті |
| Sink/context | src/SecureLab.Api/Client/browser-lab.js:10, `load()`: `document.querySelector("#description").innerHTML = current.description` | елемент `<div id="description">` | ❌ НЕБЕЗПЕЧНО: HTML parser context, розмітка і inline event handlers (`onerror`) стають DOM-елементами і виконуваним кодом |

## Інвентаризація DOM sinks

Пошук: `grep -nE "innerHTML|outerHTML|insertAdjacentHTML|eval\(|new Function|on[a-z]+=" src/SecureLab.Api/Client/*.js src/SecureLab.Api/Client/*.html`.
Результат: 2 небезпечні збіги в browser-lab.js (рядки 10, 14) і 1 хибний збіг у index.html:5 (`content=` у `<meta name="viewport">`, це не event handler). В app.js збігів немає: дані виводяться через `createTextElement` → `textContent`.

Детально по browser-lab.js:

| Місце (функція) | Дані у sink | Категорія даних | Контекст | Рішення |
|---|---|---|---|---|
| `load()`: `status.textContent = \`GET: ${response.status}\`` | HTTP status | server-generated | text node | безпечно |
| `load()`: `#title.textContent = current.title` | title | збережене значення користувача | text node | безпечно |
| `load()` ряд. 10: `#description.innerHTML = current.description` | description | збережене значення користувача | HTML parser | ❌ уразливо → замінити на `textContent` |
| `load()`: `#comments.replaceChildren()` | — | — | очищення контейнера | безпечно |
| `load()`: `document.createElement("p")` | — | trusted constant (структуру задає код) | — | безпечно |
| `load()` ряд. 14: `paragraph.innerHTML = comment.text` | comments[].text | збережене значення користувача | HTML parser | ❌ уразливо → замінити на `textContent` (на «Задовільно» без окремого seed-досліду) |
| `load()`: `#edit.elements.description.value = current.description` | description | збережене значення користувача | властивість `value` поля форми, не HTML | безпечно |
| submit: `#incident-id.value = created.id` | id | server-generated | властивість `value` | безпечно |
| `fetch(\`/api/incidents/${id()}\`)`, `id()` робить `encodeURIComponent` | Guid з поля | контрольоване користувачем | шлях URL запиту (не DOM sink) | прийнятно: значення закодоване, маршрут `{id:guid}` |

Поза flow: `IncidentMutationEndpoints.cs` (оновлення, ряд. 90/100) записує те саме поле `Description`, тому той самий sink показав би й оновлений текст. Виправлення у sink покриває обидва шляхи запису.
Сторонні бібліотеки у flow: немає.