let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");
async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  status.textContent = `GET: ${response.status}`;
  if (!response.ok) return;
  current = await response.json();
  document.querySelector("#title").textContent = current.title;
    document.querySelector("#description").textContent = current.description;
  document.querySelector("#comments").replaceChildren();
  for (const comment of current.comments ?? []) {
    const paragraph = document.createElement("p");
      paragraph.textContent = comment.text;
    document.querySelector("#comments").append(paragraph);
  }
  document.querySelector("#edit").elements.description.value = current.description;
}
document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
        // ЛР 6: створення змінює стан, тому йде через helper з antiforgery header.
        const response = await SecureLabCsrf.mutate("/api/incidents", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                title: form.elements.title.value, description: form.elements.description.value,
                severity: "Low", occurredAtUtc: new Date().toISOString()
            })
        });
        status.textContent = `POST: ${response.status}`;
        if (response.ok) {
            const created = await response.json();
            document.querySelector("#incident-id").value = created.id;
            await load();
        }
    } catch (error) {
        status.textContent = `POST: ${error.message}`;
    }
});