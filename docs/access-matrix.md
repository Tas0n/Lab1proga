# Матриця доступу — робочий шаблон

У початковому стані ЛР 1 автентифікації та авторизації ще немає. Не трактуйте
цей файл як реалізовану політику. Заповніть і реалізуйте матрицю у ЛР 3–4.

| Дія | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---:|---:|---:|---:|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | allow лише власні (OwnerUserId = principal); чужих у відповіді немає | allow: усі інциденти (потрібні для аналізу й triage) | allow лише власні (прав на чужі не опубліковано) | Так для Reporter і Administrator; для Analyst ні | query scoping в `IncidentQueries.GetListAsync`; A-05 |
| Перегляд деталей `GET /api/incidents/{id}` | достатній; entry-контракт ЛР 5 | deny, 401 | owner — allow, 200; non-owner — deny, 404 (як для неіснуючого) | allow, 200, для будь-якого інциденту; internal comments у відповіді дозволені | власний — allow; чужий — deny, 404 | Так | централізоване рішення в `IncidentQueries`/handler; A-01, A-02, A-03, A-03R, A-10 |
| Створення `POST /api/incidents` | успадкований baseline | deny, 401 | allow for self; owner і status призначає сервер | allow for self | allow for self (успадковано з ЛР 3: будь-який authenticated principal) | Сервер призначає власника з principal | перевірено baseline; A-01, A-08 |
| Update content `PUT /api/incidents/{id}` (лише title, description, occurredAtUtc) | добрий | deny, 401 | owner — allow, 204, змінюються лише ці поля; non-owner — deny, 404 | deny, 403 (ресурс бачить, права змінювати content немає); неіснуючий id — 404 | власний — allow; чужий — deny, 404 | Так | handler + DTO без owner/severity/status; A-04, A-08a |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner — allow лише якщо status = New, інакше deny, 409; non-owner — deny, 404 | deny, 403 | власний — як owner; чужий — deny, 404 | Так | handler; A-04 |
| Зміна severity/status (status лише через `POST /api/incidents/{id}/triage`, New → Triaged) | добрий | deny, 401 | deny, 403 для будь-якого Reporter (включно з owner); роль перевіряється до пошуку ресурсу; audit. Через update severity/status змінити не можна | status: allow лише New → Triaged; status ≠ New — deny, 409; неіснуючий id — 404. Зміни severity немає: deny, 403 | deny, 403 (права не опубліковано); audit | Ні: owner не надає права на зміну severity/status | role gate + handler; next status визначає сервер; A-06, A-07, A-08a, A-09 |
| Перегляд child `GET /api/incident-comments/{id}` та internal comment у details | добрий | deny, 401 | публічний коментар до власного інциденту — allow; internal — deny, 404; коментар до чужого інциденту — deny, 404 | allow, включно з internal, після перевірки доступу до parent incident | deny, 404 (прав не опубліковано) | Ні для internal-правила; доступ до parent перевіряється окремо | та сама видимість у details-проєкції й у child endpoint; A-12 |

