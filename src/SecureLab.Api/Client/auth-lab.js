const result = document.querySelector("#result");
document.querySelector("#login").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const response = await fetch("/api/auth/login", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    form.elements.password.value = "";
    // ЛР 6: новий користувач — старий request token забуваємо.
    if (response.ok) SecureLabCsrf.reset();
    result.textContent = `Login: ${response.status}`;
});
document.querySelector("#me").addEventListener("click", async () => {
    const response = await fetch("/api/me");
    result.textContent = `${response.status}: ${await response.text()}`;
});
document.querySelector("#logout").addEventListener("click", async () => {
    try {
        // ЛР 6: logout змінює стан сеансу, тому йде через helper з antiforgery header.
        const response = await SecureLabCsrf.mutate("/api/auth/logout", { method: "POST" });
        if (response.ok) SecureLabCsrf.reset();
        result.textContent = `Logout: ${response.status}`;
    } catch (error) {
        result.textContent = `Logout: ${error.message}`;
    }
});