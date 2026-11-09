# Звіт ЛР04

## Контекст і межа виконання
- Рівень: добрий («Добре»); виконано всі кроки достатнього рівня та кроки 9–12, A-01, A-04–A-10, A-12.
- Власний baseline 2-A, base tag v0.3.0, гілка lab/4-authorization.
- Головна action: details/read; додатково mutation (update, delete), triage, child. Політика для чужого ресурсу: 404 (обґрунтування в docs/access-matrix.md).

Рівні накопичувальні; заповніть свій і всі нижчі. Рядки/розділи вищого рівня позначте «не виконувалось — рівень …». Критерії й маршрут — на початку практичної частини методички.

## Матриця і server-side рішення
Посилання на docs/access-matrix.md; конкретні правила ролей/owner/context.
Місця query scoping, handler, policy, дозволених DTO і server-managed fields.

## Вразливий стан і PoC
Сценарій: `tests/http/lab04_scenarios.py`, `tests/http/lab-04-access.http`.

| Суб'єкт | Дія | Очікувано за матрицею | Фактично (до) |
|---|---|---|---|
| anonymous | GET details Alice | 401 | 200 |
| Alice | GET details Alice | 200 | 200 |
| Alice | GET details Bob | 404 | 200, дані Bob |
| Morgan (Analyst) | GET details Alice | 200 | 200 |
| Alice | PUT Bob incident | 404, стан без змін | 204, title Bob змінено |
| Morgan | PUT Alice incident | 403 | 204 |
| Alice | DELETE Bob incident-4 | 404, стан без змін | 204, інцидент видалено |
| Alice (Reporter) | POST triage incident-3 | 403, status New | 204, status Triaged |
| Alice | GET comment-2 (інцидент Bob) | 404 | 200 |
| Alice | GET comment-3 (internal) | 404 | 200, внутрішній текст |

Першопричина: пошук лише за id без порівняння OwnerUserId з principal і без перевірки ролі для triage; child без перевірки parent та IsInternal.

## Виправлення та retest
Fixed commit hash; ті самі запити до/після; результати потрібних A-сценаріїв.
Для mutation: стан до/після дозволу та стан без змін після deny.
Для read: DTO не розкриває чужі дані/внутрішні owner fields.
Узгодженість 404 для чужого/невідомого — для всіх реалізованих маршрутів; окремий доказ A-10 — з доброго рівня за політики 404.

Як читати докази в таблиці: **mutation perimeter** — усі змінювальні дії (update/delete/transition); **state assertion** — повторне читання й порівняння стану до/після; **contract test** — запит із зайвим полем для обраного A-08a/A-08b. Для audit знайдіть `authorization.denied` у виводі API й збережіть рядок без пароля, cookie, token і повного body. Дозволена привілейована дія потребує ролі й контексту за матрицею (для triage — `Analyst` і `New`).

## Доказова таблиця
Якщо головна action — mutation, доказ owner/non-owner для details запишіть у стовпці «Доказ» рядка A-03R.

Усі рівні: автоматичні HTTP A-02/A-03, A-03R — test або `.http`. Добрий додає A-01, A-04–A-07, одне з A-08a/A-08b, A-09, A-12; A-10 лише для 404. A-06 і A-07 автоматичні. Відмінний додає A-11 (search і severity-summary); A-06/A-08a/b успадковано. Запишіть фактичні результати; рядки вищого рівня позначте з поясненням.

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | protected request | `401`, не HTML redirect | … | integration test / response |
| A-02 | достатній, обов’язковий | Власний ресурс | Alice має власний seed resource | вибрана головна action: details/read або одна mutation | allow | … | автоматичний HTTP test |
| A-03 | достатній, обов’язковий | Чужий ресурс | Alice, Bob resource | та сама головна action з підміненим id | `403` або `404`; для mutation state без змін | … | автоматичний HTTP test; для mutation стан до/після |
| A-03R | достатній, entry-контракт ЛР 5 | Дозволений аналітичний read | Morgan (`Analyst`), ресурс Alice | `GET /api/incidents/{id}` | allow для аналізу; не надає права довільної mutation | … | test / `.http` |
| A-04 | добрий | Чужий ресурс, усі змінювальні дії | Alice, Bob resource | підмінити id в update/delete | deny, state без змін | … | тест + порівняння стану до/після |
| A-05 | добрий | List | Alice | list | лише дозволена множина | … | response / test |
| A-06 | добрий | Вертикальне підвищення привілеїв | звичайний Reporter | privileged transition | deny, status без змін | … | тест + порівняння стану до/після |
| A-07 | добрий | Дозволена привілейована дія | роль і контекст за матрицею | transition за матрицею | allow | … | автоматичний HTTP test |
| A-08a | добрий, альтернатива A-08b | Надлишкове присвоєння (overposting): контракт ігнорує невідоме поле | authenticated user; DTO не містить protected field | forged owner/role/status field у regular update | дозволений content може змінитися, але protected state — ні | … | тест контракту + порівняння стану до/після |
| A-08b | добрий, альтернатива A-08a | Overposting: контракт відхиляє зайве або заборонене поле | authenticated user; контракт явно відхиляє поле | той самий forged request | `400` або `403` за контрактом; весь protected state без змін | … | тест контракту + порівняння стану до/після |
| A-09 | добрий | Аудиторська подія (audit event) | denied privileged request | знайти authorization.denied у виводі API | безпечна подія без секретів | … | доказ із вилученими секретами |
| A-10 | добрий, лише політика `404` | Нерозрізнюваність `404` | той самий authenticated client; identifier чужого й identifier неіснуючого ресурсу | виконати два однакові за структурою запити, змінивши лише id | однакові status, `Content-Type` і тіло після вилучення полів кореляції запиту (`traceId`, `requestId`) | … | integration test + дві збережені відповіді |
| A-11 | відмінний | Власні endpoint-и ЛР 1–2 | Alice; власні endpoint-и з ЛР 1–2 | виконати `severity-summary` і `search` | результат обмежений дозволеною множиною | … | response / test |
| A-12 | добрий | Child resource та internal comment | Alice (`Reporter`); прямий id коментаря Morgan до інциденту Bob (comment-2 у seed-identifiers.json) | запросити `GET /api/incident-comments/{id}` і перевірити details-проєкцію для `Reporter` | direct child access — deny за зафіксованою політикою; internal comment не потрапляє у відповідь `Reporter` | … | integration test + response для details |

## Основний finding і залишковий ризик (усі рівні)
Контекст → гіпотеза → стан до й hash → першопричина → fix і DTO → retest → позитивна регресія → короткий залишковий ризик. CSRF для cookie mutation до ЛР 6 — задокументований навчальний борг.

## Browser flow (усі рівні)
Login на auth-lab.html → головна сторінка → власні details → Bob probe.
Результат UI/HTTP; жодних значень credentials, cookie або повного Set-Cookie.
Знімки обох станів — як рис. 7 методички, без вкладок Application/Network.

## Добрий рівень: роль, transition, child, audit (також для відмінного)
Дозволений/заборонений transition, server next status, контекст New→Triaged.
Morgan до Bob comment; internal до Alice: Reporter deny, Analyst parent-authorized.
Audit subject/action/resource/result/UTC/trace; збіг trace у відповіді і події.

## Відмінний рівень (додатково до всього доброго)
Відокремлений resource-based handler або policy; A-11 для наявних search і severity-summary, дозволена множина; окремий finding додаткової проблеми з доказом до/після.
A-08a/A-08b і A-06 підтверджують захист privilege-related field і вертикальний regression; нових повторних тестів не потрібно.
Обґрунтування видимості ресурсу, прав кожної ролі (least privilege), охоплення і залишкових ризиків.
Batch/export — лише якщо є; concurrent transitions — лише якщо викладач надав відтворюваний сценарій; інакше «не застосовується».

## Перевірки, відтворення і подання (усі рівні)
ОС/.NET/PostgreSQL; точні команди; фактичні counts/status і recovery.
Build/tests output; hash тегу v0.4.0 (= fixed commit; вписується наступним commit після тегу); посилання commit/tag і Moodle.
Окремо: невиконані необов’язкові перевірки/обмеження.

## Використання ШІ (довільна форма; журнал — за бажанням)
Не використовував/ла ШІ / використав/ла дозволеним способом:
| Дата/інструмент | Для чого | Що використано | Що перевірено самостійно |
|---|---|---|---|
| | | | |
Паролі, cookie, реальні персональні дані й приватний репозиторій не надсилайте.
