# Security review SecureLab, ЛР 6

Рівень: **достатній («Задовільно»)**. Пункти доброго й відмінного рівнів позначено
«Не входить до обраного рівня».

Commit початку огляду (review-start): 1765d7425574fc64a549bbc49ccc505c046f9307
Дата: 2026-11-16
SDK: 10.0.401
Профілі: Development (`http://localhost:5080`) і production-like (`--no-launch-profile`, Production)
Клієнти: Chrome, curl у Git Bash

## 1. Executive summary
Огляд охопив локальний SecureLab (baseline 2-A) від стану `v0.5.0`: браузерний клієнт, API, PostgreSQL, конфігурацію й журнал. Секретів у файлах Git не знайдено; у режимі Production сервер не показує внутрішніх деталей помилок, а traceId відповіді збігається із записом у журналі. Додано захист від CSRF (antiforgery) для всіх п’яти змінювальних маршрутів, що спираються на cookie входу, і виправлено одну знахідку — F-01 (заголовки безпеки зникали на відповідях 500). Мінімальний набір регресійних перевірок (SQL injection, вхід, права доступу, XSS, CSRF) пройшов на фінальному стані. Головні залишкові ризики: немає обмеження спроб входу, HTTPS на справжньому сервері не перевірено (анонімний пошук розкриває інциденти всіх користувачів).
## 2. Scope та exclusions
Поточні відстежувані Git файли — обов’язково. Історія Git: лише фактично переглянуті файли, refs або проміжок дат; інакше напишіть «не перевірено».
## 3. System overview і trust boundaries
Для всіх: див. threat-model.md. Добрий/відмінний: кожна межа → конкретний test; відмінний: asset → threat → control → verification.
## 4. Methodology та test environment
Review-start commit: 1765d7425574fc64a549bbc49ccc505c046f9307, гілка `lab/6-hardening-review` від `v0.5.0`.
Стенд: Windows, Visual Studio 2026, Git Bash, Docker Desktop, Chrome.
БД: локальний PostgreSQL з `infra/compose.yaml`, порт 127.0.0.1:54329, лише навчальні дані.
Відомий стан: `dotnet run --project src/SecureLab.Api -- --reset-database` у Development; пароль seed задано змінною `SeedUsers__Password` поза Git.
Стартова перевірка (`startup.sh`): build — 0 warnings, 0 errors; PostgreSQL Healthy;  /health → 200.
## 5. Findings summary
| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Повторна перевірка |
|---|---|---|---|---|---|---|
| F-01 | заголовки безпеки на відповідях 500 | низький | середня (анонім, будь-яка неочікувана помилка) | P3 | Fixed | ручний retest (`production.sh broken` + curl), розділ 8.4; regression pack  |

**Порядок дій.** F-01 виправлено одразу: зміна мала, не змінює контрактів API, а позитивна регресія тривіальна.
**Тимчасово прийняті ризики (не виправлялися в межах достатнього рівня):**

| Ризик | Пріоритет | Compensating control | Відповідальний / follow-up |
|---|---|---|---|
| немає обмеження спроб входу (rate limit і lockout) | P2 | Identity: мінімальна довжина пароля 10; лише локальний стенд і штучні акаунти | автор роботи; додати partitioned limiter на `POST /api/auth/login` у наступній ітерації |
| анонімний GET /api/incidents/search повертає назви й описи інцидентів усіх користувачів (спостережено локально: …0001 і …0002 без входу) | P1 | лише локальний стенд і штучні дані | автор роботи; додати `RequireAuthorization()` і `IncidentAccessRules.VisibleTo` до `GET /api/incidents/search` у наступній ітерації |
## 6. Detailed findings
F-01 — `docs/findings/F-01-error-response-headers.md` (Fixed, P3).
## 7. Regression results
Рівень: достатній — мінімальний regression pack (SQLi, authentication, authorization/IDOR, XSS, CSRF).
Відомий стан: `dotnet run --project src/SecureLab.Api -- --reset-database` (Development), потім запуск API. 
Автоматичні тести: `dotnet test SecureLab.sln -c Release --logger "console;verbosity=normal"` → Passed: 28, Failed: 0.

| ID у проєкті | Property | Передумови | Негативна перевірка | Позитивна перевірка | Команда / тест |
|---|---|---|---|---|---|---|
| S-02 (ЛР 2) | текст пошуку не змінює SQL | seed після reset | `q=zz-no-match' OR TRUE -- ` → 200, `[]` (не всі записи) | — | `curl ".../api/incidents/search?q=zz-no-match%27%20OR%20TRUE%20--%20"`; `tests/http/lab-02-checks.http` (C) | 
| T-04 (ЛР 2) | легітимний апостроф | seed | — | `q=O'Brien` → 200 (не 500); `q=USB` → 200 зі збігом | `curl ".../search?q=O%27Brien"`, `curl ".../search?q=USB"` | 
| A01, A02 (ЛР 3) | identity lifecycle | test account alice | анонімне створення → 401 без redirect; неправильний пароль → 401; анонімний `/api/me` → 401 | login 204 → `/api/me` 200 лише з безпечними полями → logout (з токеном) 204 → `/api/me` 401 | `A01_AnonymousCreateIncident_Returns401_NotRedirect`, `A02_LoginThenMe_ReturnsCurrentUserWithSafeFieldsOnly`, `RealCookie_ReachesSessionCheck`, `MainCookie_IsIssuedWithSafeAttributes`; curl-послідовність login/me/logout | 
| A-02, A-07 (ЛР 4) | дозволена дія власника/ролі | seed | — | alice читає свій інцидент 200; власник змінює й видаляє свій 204; morgan робить triage 204 | `A02_Details_AsOwner…`, `Update_And_Delete_AsOwner…`, `A07_Triage_AsAnalyst…`; curl alice → `…0001` = 200 | 
| REG-XSS-01 (ЛР 5) | текст не виконується як код | local marker, alice і morgan | marker у description: перевірка `data-lab05-marker` → `null` у сесіях alice і morgan, `<img>` не створюється | складний текст (апостроф, лапки, `<`, Unicode, `<b>`) показано буквально | ручна процедура в Chrome (`browser-lab.html`, DevTools Console); `ClientScript_DoesNotUseDangerousInnerHtmlSink` | 
| REG-CSRF-01 (ЛР 6) | потрібна пара antiforgery-токенів | auth-cookie alice, reset | PUT без токена → 400 і інцидент не змінився; з невалідним токеном → 400 і не змінився; logout без токена → 400 і сеанс активний | з валідною парою → 204 і title змінився; у браузері створення 201 і logout 204 з header `X-CSRF-TOKEN` | `REG_CSRF_01_Update_WithoutValidToken_IsRejected_StateUnchanged_ThenValidPairSucceeds`; ручна перевірка (розділ 8.6) | 
| T-02 (validation) | — | — | — | — | — | Не входить до обраного рівня |
| REG-CORS-01 | — | — | — | — | — | Не входить до обраного рівня |
| Rate limiting | — | — | — | — | — | Не входить до обраного рівня (limiter відсутній, див. 8.3) |
## 8. Hardening controls

| Control | Ризик | Перевірка | Межа висновку |
|---|---|---|---|
| Antiforgery (`AntiforgeryFilter`, header `X-CSRF-TOKEN`) на SC-01…SC-05 | чужа сторінка змінює дані з cookie користувача (CSRF) | REG-CSRF-01 (`dotnet test`), ручна перевірка 8.6 | не захищає від XSS на нашому origin; login/register поза периметром |
| ProblemDetails + ExceptionHandler у Production | розкриття stack trace, SQL, connection string | `production.sh broken` + curl, traceId ↔ журнал (8.2) | перевірено одну неочікувану помилку на локальному стенді |
| `X-Content-Type-Options`, `Referrer-Policy` (після F-01 — на всіх класах) | MIME sniffing, витік адреси через Referer | curl на 5 класах відповідей (8.4) | не замінюють правильного Content-Type і CSP |
| Production-конфігурація (без OpenAPI, reset заборонено) | доступ до службових функцій розробника | `production.sh normal`, `/openapi/v1.json` → 404, reset → відмова (8.1) | локальний процес, не справжній deployment |
| Секрети поза Git (`.gitignore`, змінні середовища) | витік credentials через репозиторій | `git ls-files`, `git check-ignore`, `git grep` (розділ 9) | поточні tracked files і 4 конфігураційні файли в історії |

### 8.1. Режим Production 
Запуск: `bash ../lr06-resources/commands/production.sh normal`, клієнт curl , дата 17.11.2026.

| Що перевіряли | Результат | Що це доводить / межа |
|---|---|---|
| Режим | `Hosting environment: Production`, `Now listening on: http://localhost:5080` | застосунок справді в Production |
| `GET /openapi/v1.json` | 404 | документацію API вимкнено поза Development |
| `GET /scalar/v1` | 200 `text/html`, тіло — головна сторінка клієнта | це fallback на index.html, а не документація |
| Запуск з `--reset-database` | `InvalidOperationException: Reset даних дозволено лише в явно налаштованому Development environment.` | очищення БД у Production заборонено; дані не змінено |
| Connection string | задано змінною `ConnectionStrings__SecureLab`, `Include Error Detail=false` | `appsettings.Development.json` у Production не читається |
| Автоміграції | `ApplyMigrationsOnStartup=false`, `AllowReset=false` (`appsettings.json`) | — |
| `AllowedHosts` | `"*"` (`appsettings.json`) | для локального стенда допустимо; для справжнього сервера треба обмежити |
| HTTPS/HSTS | у `Program.cs` немає `UseHttpsRedirection`/`UseHsts`, профіль лише http | безпеку HTTPS локально не доведено |

### 8.2. Навмисна помилка 500 
Запуск: `production.sh broken`, один запит `POST /api/auth/login` з вигаданим паролем.

| Канал | Що побачили | Чого немає |
|---|---|---|
| Відповідь клієнту | 500, `application/problem+json`, title «An error occurred while processing your request.», traceId 274bbed0d489cf58d01f2c592d3c828e | stack trace, SQL, шляхів до файлів, connection string |
| Журнал сервера | `fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]`, `TraceId:274bbed0d489cf58d01f2c592d3c828e, `RequestPath:/api/auth/login` | пароля, cookie, токенів |
| Зв’язок | середня частина traceId у відповіді = TraceId у журналі | — |

Відновлення в Development: health 200, login 204, список 200; помилки працюють правильно: неправильний status → 400, неіснуючий id → 404.

### 8.3. Інші захисти
- Обмеження спроб входу (login rate limit): відсутнє в проєкті → **gap**: перебір паролів не обмежено. Для достатнього рівня не додається.
- CSP: не було в ЛР 5 → N/A.

### 8.4. Заголовки на п’яти типах відповідей 
Клієнт: curl. Сеанс: alice. Заголовки ставить `app.Use` у `Program.cs`.

| Тип | Профіль | Запит | Статус | X-Content-Type-Options | Referrer-Policy |
|---|---|---|---|---|---|
| Статична сторінка | Development, анонім | `GET /` | 200 | nosniff | no-referrer |
| Успішний API | Development, alice | `GET /api/incidents/20000000-…-0001` | 200 | nosniff | no-referrer |
| Помилка вводу | Development, alice | `GET /api/incidents?status=Unknown` | 400 | nosniff | no-referrer |
| Не знайдено | Development, alice | `GET /api/incidents/99999999-…` | 404 | nosniff | no-referrer |
| Помилка сервера (до виправлення) | Production, анонім | `POST /api/auth/login`, БД недоступна | 500 | **немає** | **немає** |
| Помилка сервера (після F-01) | Production, анонім | те саме | 500 | nosniff | no-referrer |

Ризики: `nosniff` — браузер не вгадує тип файлу (MIME sniffing); `Referrer-Policy: no-referrer` — адреса сторінки не передається іншим сайтам. Межа: ці заголовки не замінюють правильного Content-Type і не захищають від XSS.
CSP і frame-ancestors: не було в ЛР 5 → N/A для достатнього рівня.
Cookie входу: HttpOnly, SameSite=Lax, Secure поза Development (`Scaffolding/Lab03Identity.cs`).

### 8.5. Периметр змінювальних маршрутів 
Джерела: `git grep "\.Map(Post|Put|Patch|Delete)\("` (сервер), `git grep "method: *.(POST|…)"` (клієнт), `/openapi/v1.json` у Development, `docs/access-matrix.md`.
Antiforgery header: **`X-CSRF-TOKEN`**. Видача токена: `GET /api/antiforgery/token` (лише після входу).

| ID | Метод + маршрут | Джерело / розбіжність | Що змінює | Cookie входу | З браузера | Antiforgery | Перевірка |
|---|---|---|---|---|---|---|---|
| SC-01 | `POST /api/incidents` | `Lab02Endpoints.cs`; клієнт `browser-lab.js` | створює інцидент | так | так | explicit (`AntiforgeryFilter`) | A05, ручна перевірка |
| SC-02 | `PUT /api/incidents/{id}` | `IncidentMutationEndpoints.cs`, ЛР 4. DISCREPANCY: у клієнті немає виклику — маршрут доступний лише через API/тести, задокументований у `access-matrix.md` | змінює title/description | так | так (запит можна надіслати з браузера) | explicit | **REG-CSRF-01**, A04, A08a |
| SC-03 | `DELETE /api/incidents/{id}` | те саме, DISCREPANCY як SC-02 | видаляє інцидент | так | так | explicit | A04 |
| SC-04 | `POST /api/incidents/{id}/triage` | те саме, DISCREPANCY як SC-02 | статус New → Triaged | так | так | explicit | A06, A07 |
| SC-05 | `POST /api/auth/logout` | `Lab03Identity.cs`; клієнт `auth-lab.js` | завершує сеанс | так | так | explicit, перевірка до `SignOutAsync` | ручна перевірка |
| SC-06 | `POST /api/auth/login` | `Lab03Identity.cs`; клієнт `auth-lab.js` | створює сеанс | ні | так | absent — рішення нижче | — |
| SC-07 | `POST /api/auth/register` | `Lab03Identity.cs`; клієнт `register-check.js` | створює акаунт | ні | так | absent — рішення нижче | — |

**Рішення щодо login/register.** Вони не довіряють уже наявній cookie, тому до cookie-периметра не входять. Ризик login-CSRF (чужий сайт входить у ваш браузер під своїм акаунтом) залишено як residual risk. Його зменшують дві речі: маршрути приймають лише JSON (HTML-форма з чужого сайту отримає 415), а JSON-запит з чужого origin потребує CORS preflight, якого API не дозволяє.
GET-маршрутів, що змінюють стан, не знайдено. `GET /api/antiforgery/token` лише видає токен і даних не змінює.

### 8.6. Antiforgery flow 
- Сервіс: `AddAntiforgery`, header `X-CSRF-TOKEN`, cookie `securelab-af` (`Program.cs`).
- Видача: `GET /api/antiforgery/token` (лише після входу) → `GetAndStoreTokens`; cookie-частина в Set-Cookie, request token у JSON.
- Перевірка: один клас `Security/AntiforgeryFilter.cs` (`ValidateRequestAsync`; помилка → 400 Problem Details «Antiforgery token is missing or invalid.»; handler не викликається). Підключено до SC-01…SC-05. На GET-маршрути не ставиться.
- Клієнт: `Client/csrf.js` (токен лише в пам’яті сторінки, отримується перед першою зміною, скидається після login/logout/400/401 і при `pageshow`); підключено перед скриптом на `auth-lab.html` і `browser-lab.html`.
- Старі тести: `IncidentAuthorizationTests.LoginAsync` і A05 отримують чинний токен, тому й далі перевіряють саме 403/404/409.
- **REG-CSRF-01** (`CsrfRegressionTests`, `dotnet test`): без токена → 400 і інцидент не змінився; невалідний токен → 400 і не змінився; валідна пара → 204 і title змінився. Результат: Passed.
- Ручна перевірка в Chrome (інкогніто): login 204 → створення 201 (у Network є header `X-CSRF-TOKEN`) → F5 → створення 201 → logout 204 → /api/me 401 → login bob → створення 201. Logout без токена (curl) → 400, а `/api/me` після нього → 200 (сеанс не завершено).
- Залишковий ризик: код, що виконається на нашому origin через XSS, може отримати токен так само, як helper.

### 8.7. HTTPS і HSTS 
`Properties/launchSettings.json` має лише профіль `http` (`http://localhost:5080`). У `Program.cs` немає `UseHttpsRedirection()` і `UseHsts()`. Тому цей стенд не доводить безпеки транспорту для production. HTTPS захищає з’єднання; redirect лише перенаправляє з HTTP на HTTPS (за замовчуванням 307); HSTS — це вказівка браузеру надалі не використовувати HTTP. На localhost HSTS за замовчуванням не додається (ExcludedHosts), і це не дефект. Справжній сервер, TLS і HSTS не тестувалися.

### 8.8. Обмеження спроб входу 
Login limiter у проєкті відсутній -> hardening gap, для достатнього рівня не додається. Rate limiting для search — не входить до обраного рівня.

## 9. Dependency and secret audit
### 9.1. Конфігурація в Git
- `git ls-files …` показав: `infra/.env.example`, `infra/compose.yaml`, `src/SecureLab.Api/appsettings.json`, `src/SecureLab.Api/appsettings.Development.json` (і копії в `starter-project/`).
- `git check-ignore -v`: `infra/.env` ігнорується правилом `.gitignore:15`, `appsettings.Local.json` — правилом `.gitignore:18`. Отже локальні файли з секретами в Git не потраплять.
- `infra/.env.example` містить лише `POSTGRES_PORT=54329` — безпечне значення.
- README (рядок 63) пояснює, що `local-study-password` — відкритий навчальний пароль лише для локальної БД.

### 9.2. Пошук паролів у файлах Git
Команда: `git --no-pager grep -n -I -i -E 'password|passwd|secret|api.?key' -- .` Знайдено 88 збігів. Справжніх паролів серед них немає.

| Файл : рядки | Що там | Рішення |
|---|---|---|
| `infra/compose.yaml:9` | пароль контейнера PostgreSQL `local-study-password`, порт лише 127.0.0.1 | **accepted, study-only** (README:63); не можна використовувати для інших БД |
| `src/SecureLab.Api/appsettings.Development.json:3` | той самий навчальний пароль у connection string для Development | **accepted, study-only** |
| `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` | той самий навчальний пароль для інструментів міграцій | **accepted, study-only** |
| `starter-project/infra/compose.yaml:9`, `starter-project/src/SecureLab.Api/appsettings.Development.json:3`, `starter-project/src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` | копії тих самих навчальних значень у теці starter | **accepted, study-only**; тека не входить у solution |
| `.gitignore:14`, `starter-project/.gitignore:14` | коментар до правил ігнорування секретів | не секрет |
| `README.md:63,138`, `starter-project/README.md:63,138` | пояснення в документації | не секрет |
| `docs/access-matrix.md:71`, `docs/browser-security-evidence.md:121`, `docs/findings/F-01-short-name.md:44`, `docs/git-workflow.md:124`, `starter-project/docs/git-workflow.md:124`, `docs/security-review.md:29` | слово в документації, значення немає | не секрет |
| `src/SecureLab.Api/Client/auth-lab.html:5`, `auth-lab.js:7`, `register-check.html:1`, `register-check.js:3,7` | назва поля форми входу/реєстрації | не секрет |
| `src/SecureLab.Api/Client/register-check.js:15` | перевірка, що у відповіді НЕМАЄ полів password/token | не секрет |
| `src/SecureLab.Api/Data/DbSeeder.cs:39` | код читає налаштування `SeedUsers:Password`, значення задається поза Git | не секрет |
| `src/SecureLab.Api/Data/DbSeeder.cs:42,45,49,51,53,55,168,173,175,176,194` | змінна з паролем, значення в коді немає | не секрет |
| `src/SecureLab.Api/Data/Migrations/…Lab03Identity.Designer.cs:197`, `…Lab03Identity.cs:52,210`, `SecureLabDbContextModelSnapshot.cs:194` | назва колонки `PasswordHash` у базі | не секрет |
| `src/SecureLab.Api/Scaffolding/Lab03Identity.cs:15,55,56,68,70,84,93,113,114` | правила пароля, поле в запиті, передача в Identity | не секрет |
| `src/SecureLab.Api/Presentation/Endpoints/IncidentMutationEndpoints.cs:221` | коментар у коді | не секрет |
| `tests/SecureLab.Api.Tests/packages.lock.json:208,291`, `starter-project/tests/SecureLab.Api.Tests/packages.lock.json:186,269` | назва пакета `UserSecrets` | не секрет |
| `tests/SecureLab.Api.Tests/AuthenticationMechanicsTests.cs:10,11,12`, `AuthenticationSecurityTests.cs:14,15,16,45,72`, `CookieClient.cs:8,14`, `CookiePathDefenseTests.cs:13,14,15,29,54`, `IncidentAuthorizationTests.cs:30,31,32,34`, `IncidentEndpointTests.cs:17,18,19,26,40,51` | тести беруть пароль зі змінної середовища `SeedUsers__Password` | не секрет |
| `tests/SecureLab.Api.Tests/AuthenticationSecurityTests.cs:59` | список назв полів, яких не має бути у відповіді | не секрет |
| `tests/http/lab-04-access.http:18,60,70`, `tests/http/lab04_scenarios.py:4,52,53,54,56` | пароль береться зі змінної середовища | не секрет |

**Чому самого видалення пароля з файла недостатньо.** Якби тут був справжній пароль, видалити його з останнього commit було б мало: він лишився б в історії Git, у копіях репозиторію та в логах. Правильно — одразу змінити цей пароль (rotation), а у файлі залишити лише назву змінної середовища. `local-study-password` — не такий випадок: це відкритий навчальний пароль лише для локальної БД, і його видалення зламало б стенд.

### 9.3. Аудит пакетів
Не входить до обраного рівня.
## 10. Residual risks
Немає обмеження спроб входу (rate limit) і lockout Identity вимкнено → можливий перебір паролів (P2, прийнято тимчасово, розділ 5).
Анонімний GET /api/incidents/search розкриває назви й описи інцидентів усіх користувачів.
HTTPS, HSTS і справжній production host не перевірялися (локальний HTTP-профіль).
`AllowedHosts: "*"` — для реального сервера потрібне окреме обмеження.
Antiforgery не захищає від коду, що виконається на нашому origin через XSS; login-CSRF прийнято як залишковий ризик.
Історія Git переглянута лише для 4 конфігураційних файлів; stash, інші клони, fork і CI — ні.
CSP відсутня (N/A для достатнього рівня); CORS-регресія, аудит пакетів і повний огляд журналів не входять до обраного рівня.
## 11. Conclusion
Для обраного (достатнього) рівня всі обов’язкові пункти виконано: межі огляду й модель загроз, перевірка секретів, безпечна помилка в Production із traceId, antiforgery для всіх змінювальних маршрутів із cookie, REG-CSRF-01, мінімальний regression pack і одна виправлена знахідка (F-01).
## 12. Evidence appendix
| EV-07 | заголовки на 5 класах відповідей, до/після F-01 | curl-команди розділу 8.4; `production.sh broken` | 500 до fix — без заголовків; після — з ними |
| EV-08 | antiforgery: відмова без токена й успіх із токеном | `dotnet test --filter REG_CSRF_01`; ручна перевірка 8.6 | 400 і стан незмінний / 204 і стан змінено |
| EV-09 | мінімальний regression pack | таблиця розділу 7 | усі рядки достатнього рівня — pass |
## Декларація й журнал ШІ
Використовував/ла / не використовував/ла. Назва сервісу, для чого, що перевірено й змінено автором, власна інтерпретація.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| заповнити або не використовував/ла | | | | |
