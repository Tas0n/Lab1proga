# Модель загроз SecureLab, ЛР 6

Заповніть фактами свого проєкту. Приклади формулювань — у PDF, етап 1, п. 2; не переносьте їх дослівно.

**Версія та середовище.** Review-start: 1765d7425574fc64a549bbc49ccc505c046f9307. SDK 10.0.401. Windows + Visual Studio 2026 + Git Bash + Chrome. Профілі: Development (`http://localhost:5080`) і production-like (Production, `--no-launch-profile`). Відомий стан — команда `--reset-database` у Development. Лише штучні акаунти й дані.

**Компоненти в межах огляду.** Браузерний клієнт (`src/SecureLab.Api/Client`: index, auth-lab, browser-lab, register-check); API на ASP.NET Core (`src/SecureLab.Api`) з Identity і cookie; PostgreSQL у Docker (`infra/compose.yaml`, 127.0.0.1:54329); конфігурація (`appsettings*.json`, `launchSettings.json`, змінні середовища); журнал у консолі API. Redis немає.

**Активи.** Облікові записи alice, bob (Reporter), morgan (Analyst), admin (Administrator) та їхні cookie входу; інциденти — Reporter має бачити лише свої; право змінювати й видаляти лише свій інцидент; зміна статусу New → Triaged лише для Analyst; internal-коментарі лише для Analyst; audit-записи `SecureLab.Audit`; connection string і пароль seed.

**Суб’єкти.** Анонімний відвідувач; Reporter; Analyst; Administrator; стороння вебсторінка в тому самому браузері (може спробувати CSRF); локальний розробник.

**Entry points.**
Без входу: `GET /health`, `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout` (заглушка 501), `GET /api/incidents/search`, статичні сторінки клієнта; у Development також `/openapi/v1.json` і `/scalar/v1`.
З cookie: `GET /api/me`, `GET /api/auth/session-check`, `GET /api/incidents/`, `GET /api/incidents/{id}`, `GET /api/incidents/severity-summary`, `GET /api/incident-comments/{id}`, `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`.
Інше: змінні середовища й `appsettings*.json` при старті, аргумент `--reset-database`, `dotnet restore`, журнал.

**Межі довіри.** browser→API (усе, що приходить від браузера, недовірене; браузер сам додає cookie входу); API→PostgreSQL; repository→build ; environment→configuration.

**Наявні захисти.**
- Перевірка вводу: `Scaffolding/Lab02Endpoints.cs`, `IncidentEndpoints.cs`; сценарії T-01, T-02, T-05.
- Захист від SQL injection: EF Core з параметрами та `EscapeLike`; сценарії S-02, T-04.
- Вхід: Identity, cookie HttpOnly, SameSite=Lax, Secure поза Development (`Scaffolding/Lab03Identity.cs`); тести A01, A02, A05, CookiePathDefenseTests.
- Права доступу: `IncidentAuthorizationHandler`, `IncidentAccessRules`; тести A-01…A-12.
- XSS: показ тексту через `textContent`; REG-XSS-01.
- CORS: лише в Development, лише origin `http://localhost:4173`; REG-CORS-01.
- Заголовки: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (`Program.cs`).
- Помилки: `AddProblemDetails` + `UseExceptionHandler`.
- Audit: запис `authorization.denied` при відмові triage.
- Секрети: `.gitignore`, пароль і connection string задаються змінними поза Git.
- Antiforgery: немає, додається в ЛР 6. CSP: немає (N/A). Обмеження спроб входу (rate limit): немає (gap).

**Виключення.** Справжній сервер, HTTPS і HSTS ; зовнішній pentest; вся історія Git ; тека `starter-project/`  лише пошук паролів. CORS-регресія, rate limit для пошуку, аудит пакетів, повний огляд логів — не входять до обраного рівня.

## Схема меж довіри

браузер (недовірений ввід, сам додає cookie входу)
      │  HTTP http://localhost:5080
      
API ASP.NET Core (перевірка вводу, вхід, права, обробка помилок, заголовки)
      │  EF Core, connection string
      
PostgreSQL (Docker, 127.0.0.1:54329)

файли в Git + пакети NuGet ──> збирання (restore/build)
змінні середовища ──────────> запуск API
API ──> журнал у консолі

## Очікувані властивості на межах

| Межа | Очікувана властивість (усі рівні) | Конкретний test або перевірка (добрий і відмінний) |
|---|---|---|
| browser→API | Запит, що змінює дані, з cookie, але без antiforgery-токена, відхиляється і нічого не змінює. Текст користувача не виконується як код.| Не входить до обраного рівня|
| API→PostgreSQL | Текст пошуку q не змінює SQL-запит | Не входить до обраного рівня |
| repository→build | У файлах Git немає справжніх паролів; навчальний пароль працює лише для локальної БД | Не входить до обраного рівня |
| environment→configuration | У Production не працюють Development-налаштування: немає OpenAPI, reset заборонено | Не входить до обраного рівня |

Примітка: у `Scaffolding/Lab02Endpoints.cs` маршрут `GET /api/incidents/search` не має `RequireAuthorization()`. Можливо, анонім бачить інциденти всіх користувачів. 

Відмінний рівень: у `docs/security-review.md` простежте для ключових активів зв’язок «актив → загроза → control → перевірка».
