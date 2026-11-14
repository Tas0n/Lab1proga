# Докази безпеки браузера (DEL-01)

Рівень: достатній («Задовільно») 

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

## Механізм сеансу
<div id="description">Звичайний опис без розмітки</div>
.AspNetCore.Identity.Application	localhost	/	Session	891	✓		Lax			Mediu



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
