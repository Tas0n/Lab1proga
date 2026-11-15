# Докази безпеки браузера (DEL-01)

Рівень: достатній («Задовільно») 
## Підсумок

| Finding | До | Першопричина | Fix | Retest | Залишковий ризик |
|---|---|---|---|---|---|
| F-05-01 Stored/DOM-based XSS у Description (і коментарях) | marker виконався в сесіях alice і morgan (`data-lab05-marker="executed"`), `<img>` у DOM | `browser-lab.js`, `load()`: `innerHTML = current.description` (ряд. 10) і `innerHTML = comment.text` (ряд. 14) | `textContent` в обох місцях; дані не змінюються | той самий marker → текстовий вузол, `null`; значення 113 = 113; позитивні рядки коректні | майбутній код може знову вжити `innerHTML`; CSP не налаштована (поза рівнем); інші клієнти поза інвентаризацією |
| CORS для навчальних origins | 4173 і 4174 не могли читати відповідь | policy відсутня (очікувано для same-origin застосунку) | `Lab05BrowserProbe`: лише `http://localhost:4173`, GET, лише Development | 4173 → 200 + ACAO; 4174 → CORS error; curl → 200 для обох | CORS не захищає від прямих клієнтів і CSRF; захист даних тримається на authentication/authorization ЛР4 |

Стан Git: vulnerable `<VULNERABLE_HASH>` → XSS fix `<XSS_FIX_HASH>` → CORS `<CORS_HASH>` → фінальні докази, тег `v0.5.0`.

## Стенд і Git-стан (Для всіх)

ОС: Windows ; браузер: Chrome  ; API origin: http://localhost:5080 ;
probes: http://localhost:4173 (дозволений), http://localhost:4174 (контрольний).
Release: lab-05-start-v1 ; base_commit: cd191c286849a7ade05b8ce7043b6ec3ec303225 ; entry_parent: e492072f769932192514b7b7f329da6703e60c11 ;
v0.4.0 → vulnerable commit: 78a07ca ; fixed: ; v0.5.0: 

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: … Гіпотеза source → storage → response → sink/context: … Передумови, локальний користувач, Guid запису, marker із resources/lab05-marker.txt, команди reset/start і create/read: …
Гіпотеза: Значення з поля форми <textarea name="description"> на /browser-lab.html (source) надсилається як JSON field description у POST /api/incidents. Після validation ЛР2 воно зберігається в PostgreSQL у Incident.Description (storage), повертається через response field description у GET /api/incidents/{id} і в функції load() файлу browser-lab.js передається у document.querySelector("#description").innerHTML (sink) як HTML context. Тому, якщо збережене значення містить HTML-розмітку з inline event handler (наприклад, <img onerror=…>), браузер будь-якого глядача з правом читання інциденту (зокрема Morgan, Analyst) інтерпретує дані не як звичайний текст, а як DOM-елементи і JavaScript.

Flow є stored XSS: значення збережене в PostgreSQL і виконується під час пізнішого перегляду іншим користувачем (Morgan). Небезпечне перетворення відбувається на клієнті (innerHTML у browser-lab.js), тому flow має й ознаку DOM-based. Reflected XSS у цьому flow немає: значення не повертається одразу з того самого запиту.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | `description` = marker, довжина 113 | той самий рядок, довжина 113 | Console fetch до/після |
| DOM основного Description | елемент `<img src="x" onerror="…">` у `#description` | один текстовий вузол, `<img>` немає ||
| Дія marker | `data-lab05-marker="executed"`, перевірка → 'executed'; є запит `x` | перевірка → null; запиту `x` немає |  |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | перші три коректні; `<b>` став елементом | усі чотири показані як текст без змін |  |
| Довжина за власними правилами ЛР 2 | 3900 символів, коректно (межа 4000) | 3900 символів, коректно | тест 5 |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan: GET 200, 'executed'; Bob: GET ‹404›, null | Morgan: GET 200, null; Bob: без змін |  |

Finding: актив; передумови; першопричина; safe DOM diff; retest; залишковий ризик: … Повторювана REG-XSS-01, негативний контроль і очікування: …

### Finding F-05-01: stored/DOM-based XSS в описі інциденту

| Частина | Зміст |
|---|---|
| Актив | Браузерна сесія користувача, який переглядає інцидент (зокрема Morgan, Analyst), і дані, доступні від його імені |
| Передумови | Локальний тестовий акаунт з правом створювати інцидент (Alice); контроль над полем «Опис» |
| Першопричина | `src/SecureLab.Api/Client/browser-lab.js`, функція `load()`, рядок 10: `document.querySelector("#description").innerHTML = current.description` передає недовірене збережене значення в HTML parser. Аналогічно рядок 14: `paragraph.innerHTML = comment.text` для коментарів |
| Вплив на стенді | Канонічний marker виконав лише локальну DOM-дію: встановив `data-lab05-marker="executed"` на `#lab05-marker-target` у сесіях Alice та Morgan. Жодних мережевих запитів, крім спроби завантажити `x` з localhost, і жодного читання cookie |
| Виправлення | Safe DOM rendering: `textContent` замість `innerHTML` в обох місцях. Sanitizer не потрібен, бо поле є звичайним текстом, formatted HTML у спільному scope не дозволено |
| Retest | Той самий marker на тому самому записі (MARKER_GUID) після fix відображається як текст, `<img>` не створюється, перевірка повертає `null` |
| Залишковий ризик | Інші клієнти чи майбутні sinks, які можуть знову використати `innerHTML`; третій контекст (URL/атрибути) у цьому flow не використовується; CSP поки не налаштована (поза рівнем «Задовільно») |

За спільним сценарієм 2-A formatted HTML у Description та IncidentComment.Text не дозволено, тому sanitizer не додається: для звичайного тексту достатньо safe DOM API, а sanitizer лише збільшив би поверхню атаки.

### Звичайний текст до виправлення 

| Тест | Guid | Опис (вхід) | Response JSON `description` | Сторінка | Elements `#description` |
|---|---|---|---|---|---|
| 1 | 30d8b6de-b92e-4957-ae8d-779b4d404393 | Користувач O'Brien написав "терміново" | збігається | той самий текст | текстовий вузол |
| 2 | 089378ca-756a-4b79-8b3f-ff04420681cf | 5 < 7 і 9 > 3 | збігається | той самий текст | текстовий вузол |
| 3 | a32c0d81-3e07-4289-923e-55929a35ea63 | Київ — Ω | збігається | той самий текст | текстовий вузол |
| 4 | 5e77dc1f-41f6-4ca8-8d8b-c73f6ab915bb | <b>жирний</b> текст | збігається | «жирний» напівжирне, дужок не видно | ❌ елемент `<b>` |
| 5 | 327d2376-15c9-4d72-8236-0aea0c85a05c | "А" × 3900 | збігається | довгий текст без помилок | текстовий вузол |
| seed | 20000000-…-0003 | Текст <script> має відображатися як текст, а не виконуватися як HTML. | повне речення | видно лише «Текст» | ❌ елемент `<script>` |


## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповніть до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен; діють лише authentication/authorization API |
| simple GET 4173 → API | так | ні без валідної CORS-відповіді; так після policy, що дозволяє 4173 | браузер застосовує SOP/CORS: потрібен Access-Control-Allow-Origin: http://localhost:4173 |
| simple GET 4174 → API | так | ні (4174 не буде в allowlist) | SOP/CORS: заголовка дозволу для 4174 немає |
| curl/.http → API | так | не застосовується | curl не є браузером і не застосовує SOP/CORS |
| preflighted 4173 → API («Добре / Відмінно») | — | — | на рівні «Задовільно» не виконується |

Перевірка порядку: fetch('/api/incidents') з 4173 без cookie → 401, прочитано JavaScript, без CORS-помилки».

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | GET /api/incidents/{id} → 200 (етап 1–2) | без змін | CORS не потрібен; діє authorization ЛР4 |
| Allowed 4173 | Failed to fetch, немає ACAO | {status: 200, body: '{"status":"ready"}'} | ACAO: http://localhost:4173;  |
| Disallowed 4174 | Failed to fetch, немає ACAO | Failed to fetch, немає ACAO; запит надіслано з Origin: http://localhost:4174 |  |
| Direct HTTP / curl | 200 | 200 | curl не застосовує SOP/CORS |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

Кінцевий стан CORS: policy `Lab05BrowserProbe` у `src/SecureLab.Api/Program.cs` реєструється (`AddCors`) і застосовується (`UseCors`, після `UseRouting`, до `UseAuthentication`) лише в Development. Allowlist — один точний origin `http://localhost:4173`, метод GET, без `AllowCredentials()` (рівень «Задовільно»). `http://localhost:4174` — негативний контроль, не дозволений. Це навчальний стенд: штатний клієнт працює same-origin на `http://localhost:5080` і від CORS не залежить. У Production policy не реєструється.

Команди запуску probes:
py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe

### REG-CORS-01: точний allowlist CORS

**Частина 1. Browser evidence.**
1. Термінал 1: `dotnet run --project src/SecureLab.Api` (Development, `http://localhost:5080`).
2. Термінал 2: `py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe` (macOS/Linux: `python3 -m http.server …`).
3. Термінал 3: `py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe`.
4. На `http://localhost:4173/` і `http://localhost:4174/` у DevTools Console виконати:
   `await fetch("http://localhost:5080/health").then(async (response) => ({ status: response.status, body: await response.text() }))`
5. Очікування: 4173 → `{status: 200, body: '{"status":"ready"}'}`, у Network відповідь має `Access-Control-Allow-Origin: http://localhost:4173`. 4174 → `TypeError: Failed to fetch` і `No 'Access-Control-Allow-Origin' header…`; у Network є запит до `http://localhost:5080/health` з `Origin: http://localhost:4174`, без ACAO. Якщо запиту до 5080 немає, це помилка топології стенда, а не доказ CORS.
6. Перевірка порядку: на 4173 `await fetch("http://localhost:5080/api/incidents").then(r => r.status)` → `401` без CORS-помилки.

**Частина 2. HTTP evidence**:

curl -sS -D - -o /dev/null -H "Origin: http://localhost:4173" "http://localhost:5080/health"
curl -sS -D - -o /dev/null -H "Origin: http://localhost:4174" "http://localhost:5080/health"

Очікування: обидві відповіді `HTTP/1.1 200 OK`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; перша містить `Access-Control-Allow-Origin: http://localhost:4173`; друга не містить жодного `Access-Control-*`. Статус 200 для 4174 не є помилкою policy: сервер виконав запит, а читання заборонив би лише браузер. Фактичні відповіді: `docs/evidence/cors-allowed-4173.txt`, `docs/evidence/cors-disallowed-4174.txt`.

## Механізм сеансу
<div id="description">Звичайний опис без розмітки</div>
.AspNetCore.Identity.Application	localhost	/	Session	891	✓		Lax			Mediu

### REG-XSS-01: stored XSS в Incident.Description

| Поле | Вміст |
|---|---|
| Передумови | Fixed state: commit з тегом `v0.5.0` (гілка `lab/5-browser-xss`). Негативний контроль: vulnerable commit `<VULNERABLE_HASH>`. ОС Windows, Git Bash, Chrome. PostgreSQL з `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`. У терміналі задано `SeedUsers__Password` (значення не записується). Reset: `dotnet run --project src/SecureLab.Api -- --reset-database`. Запуск: `dotnet run --project src/SecureLab.Api`. Origin клієнта: `http://localhost:5080`. Акаунти: alice (автор), morgan (Analyst, глядач), bob (контроль) |
| Вхід | Канонічний marker з однорядкового `resources/lab05-marker.txt` (113 символів), копіювання без переносу: `tr -d '\r\n' < resources/lab05-marker.txt \| clip`. Без секретів і зовнішніх hosts |
| Кроки | 1) Chrome, `http://localhost:5080/auth-lab.html`, вхід alice → `Login: 204`. 2) `http://localhost:5080/browser-lab.html`, DevTools (Network: Preserve log, Disable cache), Ctrl+Shift+R. 3) Console: `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` → `null`. 4) Назва `ЛР5 marker`, очистити поле опису, вставити marker, «Створити й прочитати» (`POST /api/incidents` → 201, `GET /api/incidents/{id}` → 200). 6) Elements → `<div id="description">`. 7) Console: `const r = await (await fetch("/api/incidents/<GUID>")).json(); console.log(r.description.length)`. 8) Вікно інкогніто: вхід morgan, `/browser-lab.html`, Ctrl+Shift+R, вставити Guid, «Прочитати», команда з п. 3. 9) Те саме вікно: вхід bob, F5, «Прочитати» той самий Guid. 10) Позитивні рядки: створити описи `Користувач O'Brien написав "терміново"`, `5 < 7 і 9 > 3`, `Київ — Ω`, `<b>жирний</b> текст`, `"А".repeat(3900)`; прочитати seed `20000000-0000-0000-0000-000000000003` |
| Очікуваний результат (fixed) | п. 5 і 8 → `null`; у `#description` один текстовий вузол із видимим текстом marker'а, елемента `<img>` немає; у Network немає запиту `x`; п. 7 → `113` (значення збережене без змін); bob → `GET: <404>`, `null`; усі позитивні рядки показані буквально як текст, Unicode не пошкоджено, у Console немає помилок |
| Негативний контроль | На vulnerable commit `<VULNERABLE_HASH>` той самий marker: у `#description` елемент `<img src="x" onerror="…">`, запит `x` у Network, команда п. 3 → `'executed'` у сесіях alice і morgan; `<b>жирний</b>` ставав елементом `<b>`; seed …0003 показував лише «Текст» |
| Доказ | (Network/Elements/Console до і після); файли: `src/SecureLab.Api/Client/browser-lab.js` (`load()`, рядки 10 і 14), diff `git diff <VULNERABLE_HASH> v0.5.0 -- src/SecureLab.Api/Client/browser-lab.js` |

Виправлено sink, а не дані: `description` у response JSON до fix і після fix однаковий (113 символів, той самий рядок); змінилося лише відображення в DOM (`innerHTML` → `textContent`).

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … safe-url.js / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавайте. Перед поданням повторіть чекліст для свого накопичувального рівня.
