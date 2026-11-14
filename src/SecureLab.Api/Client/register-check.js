document.querySelector('form').addEventListener('submit', async event => {
  event.preventDefault();
  const input = document.querySelector('#password');
  const output = document.querySelector('#result');
  if (!input.value) return;
  const suffix = Date.now().toString(36);
  let body = JSON.stringify({ userName: 'reg' + suffix, email: 'reg' + suffix + '@example.test', displayName: 'Студент 01', password: input.value });
  input.value = ''; output.textContent = '';
  try {
    for (const attempt of ['T-01', 'T-02 повтор']) {
      const reply = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const raw = await reply.text();
      let data;
      try { data = raw ? JSON.parse(raw) : '(порожнє тіло)'; } catch { data = '(тіло не JSON)'; }
      const sensitive = /password|securityStamp|cookie|token/i;
      const hasSensitiveField = value => value !== null && typeof value === 'object' && Object.entries(value).some(([key, child]) => sensitive.test(key) || hasSensitiveField(child));
      const leaks = hasSensitiveField(data);
      if (leaks) { output.textContent += attempt + ': У відповіді є чутливе поле; значення приховано.\n'; continue; }
      output.textContent += attempt + ' ' + reply.status + ' ' + reply.headers.get('content-type') + ' ' + JSON.stringify(data) + '\n';
    }
  } catch { output.textContent += 'Помилка запиту. Перевірте запущений API та той самий origin.\n'; }
  finally { body = ''; input.value = ''; }
});
