# F-01. Заголовки безпеки зникали на відповідях 500

**Статус:** Fixed  
**Актив:** захисні властивості відповідей API в браузері (заборона MIME sniffing, нерозкриття Referer) для всіх клієнтів  
**Компонент:** `src/SecureLab.Api/Program.cs` — порядок `UseExceptionHandler()` і middleware із заголовками  
**Пріоритет:** P3

## Передумови і межі огляду


Локальний стенд: Windows, Git Bash, curl. Production-like профіль `bash ../Lab6proga(add)/commands/production.sh broken` (БД на недосяжному порту 54399 — керований спосіб викликати неочікуваний виняток).
Маршрут: `POST /api/auth/login` (анонімний), вигадані дані з `unexpected-error.http`; обліковий запис не потрібен.
Виключення: відповіді 5xx від reverse proxy, справжній production host.

## Відтворення

1. Вікно 1: `bash ../Lab6proga(add)/commands/production.sh broken`, дочекатися `Hosting environment: Production`.
2. Вікно 2: `curl -sS -i -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" -d '{"userName":"alice","password":"NotARealPassword1!"}'`
3. Очікувано: 500 Problem Details **із** `X-Content-Type-Options: nosniff` і `Referrer-Policy: no-referrer`, як на відповідях 200/400/404.
4. Фактично (до fix): 500 `application/problem+json` з `traceId`, але **обох заголовків немає**. На 200/400/404 у Development вони є.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Вплив низький: тіло 500 — JSON Problem Details без даних користувача, прямого розкриття немає. Але control охоплював не всі класи відповідей: на шляху помилки браузер міг виконувати MIME sniffing і надсилати Referer. Якщо надалі відповідь помилки міститиме дані, захист на ній не діятиме.
Ймовірність середня: будь-який анонім отримує 500, коли недоступна залежність (БД) або трапляється неочікуваний виняток; роль і вхід не потрібні.

## Першопричина

У `Program.cs` middleware із заголовками стояв **після** `app.UseExceptionHandler()` і записував заголовки до виклику `next`. Коли endpoint кидав виняток, `ExceptionHandlerMiddleware` очищав відповідь (разом із заголовками) і писав власний Problem Details, тому заголовки, додані раніше, втрачалися.

## Виправлення

Middleware перенесено **перед** `UseExceptionHandler()`, а заголовки встановлюються через `context.Response.OnStarting(...)`, тобто в момент старту відповіді, після будь-якого очищення. Fixed commit  («F-01: keep security headers on error responses»); 

## Retest

Ті самі кроки 1–2 на fixed commit: 500 `application/problem+json` з `traceId` і тепер **із** `X-Content-Type-Options: nosniff` та `Referrer-Policy: no-referrer`. Тіло, як і раніше, без stack trace, SQL і connection string.

## Positive regression

Development, curl : `GET /` → 200, `GET /api/incidents/20000000-0000-0000-0000-000000000001` → 200, `?status=Unknown` → 400, неіснуючий id → 404; заголовки присутні, статуси й тіла не змінилися.
`dotnet test SecureLab.sln -c Release` → Failed: 0; клієнт у браузері працює (вхід, список, створення).

## Залишковий ризик

Заголовки ставить лише цей застосунок: відповіді reverse proxy (502/504) не перевірялися. Автоматичного тесту на заголовки відповіді 500 немає, перевірка ручна. CSP не налаштована (N/A для достатнього рівня).

## Доказ

Команди: кроки 1–2 вище; результати до і після — розділи 8.2 і 8.4 `docs/security-review.md`.
Код: `git show 2d13f78f1f9caa8fcd0e2ea44c7a76f79541c633  -- src/SecureLab.Api/Program.cs`.
Запит анонімний, пароль вигаданий; cookie, токенів і справжніх паролів у доказі немає.