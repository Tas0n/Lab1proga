# F-01. Коротка назва

**Статус:** Fixed / Temporarily accepted  
**Актив:** ...  
**Компонент:** ...  
**Пріоритет:** P1 / P2 / P3

## Передумови і межі огляду

Commit, local environment, test account, reset command, endpoint/route та виключення.

## Відтворення

Нумеровані безпечні local-only кроки, expected та actual result.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально / оцінено за кодом і конфігурацією / не перевірено, з причиною.

Що може статися з asset; за яких умов сценарій доступний. Не вигадуйте CVSS score.

## Першопричина

Точний code/configuration decision, а не лише назва payload або symptom.

## Виправлення

Що змінено, чому це усуває причину; fixed commit або precise diff reference.

## Retest

Повторення початкового негативного сценарію після fix із фактичним результатом.

## Positive regression

Легітимний сценарій, який має лишитися робочим.

## Залишковий ризик

Що control не покриває, що не тестувалося або яка умова лишається.

## Доказ

Sanitized test ID/trace, observation і точний command. Без password, cookie, token, secret або зайвих персональних даних.
