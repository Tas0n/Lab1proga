document.querySelector("#probe").addEventListener("click", async () => {
  const output = document.querySelector("#result");
  try {
    const response = await fetch(document.querySelector("#url").value, { credentials: "include" });
    output.textContent = `${response.status}: ${await response.text()}`;
  } catch { output.textContent = "Браузер не надав response JavaScript; звірте Network і серверний стан."; }
});
