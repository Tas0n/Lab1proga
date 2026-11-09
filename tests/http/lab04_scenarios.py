"""ЛР 4 SecureLab: повторювані HTTP-сценарії для PoC (до) і retest (після).

Кожен користувач має власний HttpClient-подібний opener і власну cookie-jar
лише в пам'яті процесу. Пароль береться зі змінної SeedUsers__Password і
ніде не друкується; cookie, Set-Cookie і тіло login-запиту також не виводяться.

Запуск із кореня SecureLab (Git Bash, Windows):
    py -3 tests/http/lab04_scenarios.py read
    py -3 tests/http/lab04_scenarios.py update
    py -3 tests/http/lab04_scenarios.py all
"""
import argparse
import http.cookiejar
import json
import os
import urllib.error
import urllib.request

BASE = "http://localhost:5080"

# Сталі seed-ідентифікатори baseline 2-A (resources/seed-identifiers.json).
INC = {
    "alice": "20000000-0000-0000-0000-000000000001",      # Alice, Triaged
    "bob": "20000000-0000-0000-0000-000000000002",        # Bob, InProgress
    "alice_new": "20000000-0000-0000-0000-000000000003",  # Alice, New
    "bob_new": "20000000-0000-0000-0000-000000000004",    # Bob, New
    "alice_new2": "20000000-0000-0000-0000-000000000005", # Alice, New
    "unknown": "20000000-0000-0000-0000-0000000000ff",    # не існує
}
COMMENT = {
    "to_alice": "30000000-0000-0000-0000-000000000001",   # Morgan -> Alice, public
    "to_bob": "30000000-0000-0000-0000-000000000002",     # Morgan -> Bob, public
    "internal": "30000000-0000-0000-0000-000000000003",   # internal, інцидент Alice
}
SHOWN_KEYS = ["id", "title", "description", "status", "ownerDisplayName",
              "authorDisplayName", "text", "detail", "traceId"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Не йдемо за redirect: для A-01 потрібен сирий status, а не HTML login."""
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, user=None):
        self.name = user or "anonymous"
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        if user:
            password = os.environ.get("SeedUsers__Password", "")
            if not password:
                raise SystemExit("Задайте SeedUsers__Password у цьому терміналі.")
            status, _, _ = self.call("POST", "/api/auth/login",
                                     {"userName": user, "password": password},
                                     quiet=True)
            print(f"[{user}] login -> {status}")
            if status != 204:
                raise SystemExit("Login не вдався: перевірте пароль/reset. Тіло не друкується.")

    def call(self, method, path, body=None, label=None, quiet=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            BASE + path, data=data, method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self._opener.open(req, timeout=15) as resp:
                status, raw, ctype = resp.status, resp.read(), resp.headers.get("Content-Type")
        except urllib.error.HTTPError as err:
            status, raw, ctype = err.code, err.read(), err.headers.get("Content-Type")
        except urllib.error.URLError:
            raise SystemExit("API недоступний: запустіть API на http://localhost:5080.")
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = "<не JSON, %d байт>" % len(raw)
        if not quiet:
            _print(label or f"{method} {path}", self.name, status, ctype, parsed)
        return status, parsed, ctype


def _print(label, who, status, ctype, body):
    print(f"  {label} | as={who} | status={status} | content-type={ctype}")
    if isinstance(body, dict):
        short = {k: body[k] for k in SHOWN_KEYS if k in body}
        if "comments" in body:
            short["comments"] = [c.get("text") for c in body["comments"]]
        print("    " + json.dumps(short, ensure_ascii=False))
    elif isinstance(body, list):
        ids = [item.get("id") for item in body if isinstance(item, dict)]
        print(f"    items={len(ids)} ids=" + json.dumps(ids))
    elif body is not None:
        print("    " + str(body))


def header(text):
    print("\n=== " + text + " ===")


def scenario_read():
    header("READ: details (A-01, A-02, A-03, A-03R, A-10)")
    Client().call("GET", f"/api/incidents/{INC['alice']}", label="anonymous -> Alice details")
    alice = Client("alice")
    alice.call("GET", f"/api/incidents/{INC['alice']}", label="Alice -> own details")
    alice.call("GET", f"/api/incidents/{INC['bob']}", label="Alice -> Bob details (IDOR?)")
    alice.call("GET", f"/api/incidents/{INC['unknown']}", label="Alice -> unknown id")
    morgan = Client("morgan")
    morgan.call("GET", f"/api/incidents/{INC['alice']}", label="Morgan(Analyst) -> Alice details")


def scenario_list():
    header("LIST (A-05)")
    alice = Client("alice")
    _, body, _ = alice.call("GET", "/api/incidents", label="Alice -> list")
    if isinstance(body, list):
        foreign = [i.get("id") for i in body
                   if i.get("id") in (INC["bob"], INC["bob_new"])]
        print("    чужі (Bob) у списку Alice: " + json.dumps(foreign))


def scenario_update():
    header("UPDATE: Alice -> Bob incident (A-04, state before/after)")
    bob = Client("bob")
    alice = Client("alice")
    bob.call("GET", f"/api/incidents/{INC['bob']}", label="BEFORE: Bob reads own")
    alice.call("PUT", f"/api/incidents/{INC['bob']}",
               {"title": "Змінено Alice (PoC)", "description": "IDOR update PoC",
                "occurredAtUtc": "2026-08-02T10:00:00+00:00"},
               label="Alice -> PUT Bob incident")
    bob.call("GET", f"/api/incidents/{INC['bob']}", label="AFTER: Bob reads own")
    header("UPDATE: positive regression, Alice -> own incident (A-02 mutation)")
    alice.call("PUT", f"/api/incidents/{INC['alice']}",
               {"title": "Підозрілий лист із вкладенням (оновлено)",
                "description": "Owner update", "occurredAtUtc": "2026-08-01T08:30:00+00:00"},
               label="Alice -> PUT own incident")
    alice.call("GET", f"/api/incidents/{INC['alice']}", label="AFTER: Alice reads own")
    header("UPDATE: Analyst content update (матриця: deny 403)")
    Client("morgan").call("PUT", f"/api/incidents/{INC['alice']}",
                          {"title": "Analyst edit", "description": "x", "occurredAtUtc": None},
                          label="Morgan -> PUT Alice incident")


def scenario_overpost():
    header("OVERPOSTING: forged owner/role/status/severity у regular update (A-08a)")
    alice = Client("alice")
    alice.call("GET", f"/api/incidents/{INC['alice_new2']}", label="BEFORE: Alice reads own")
    alice.call("PUT", f"/api/incidents/{INC['alice_new2']}",
               {"title": "Overposting test", "description": "forged fields",
                "occurredAtUtc": "2026-08-03T10:00:00+00:00",
                "ownerUserId": "10000000-0000-0000-0000-000000000002",
                "status": "Closed", "severity": "Critical", "role": "Analyst",
                "isTransitionAllowed": True},
               label="Alice -> PUT own + forged fields")
    alice.call("GET", f"/api/incidents/{INC['alice_new2']}", label="AFTER: Alice reads own")


def scenario_delete():
    header("DELETE: Alice -> Bob incident (A-04)")
    bob = Client("bob")
    alice = Client("alice")
    bob.call("GET", f"/api/incidents/{INC['bob_new']}", label="BEFORE: Bob reads own")
    alice.call("DELETE", f"/api/incidents/{INC['bob_new']}", label="Alice -> DELETE Bob incident")
    bob.call("GET", f"/api/incidents/{INC['bob_new']}", label="AFTER: Bob reads own")


def scenario_triage():
    header("TRIAGE: вертикальне підвищення привілеїв (A-06, A-07)")
    alice = Client("alice")
    alice.call("GET", f"/api/incidents/{INC['alice_new']}", label="BEFORE: Alice reads own")
    alice.call("POST", f"/api/incidents/{INC['alice_new']}/triage",
               label="Alice(Reporter) -> triage own New incident")
    alice.call("POST", f"/api/incidents/{INC['alice_new']}/triage",
               {"status": "Triaged", "role": "Analyst", "isTransitionAllowed": True},
               label="Alice(Reporter) -> triage + forged role/status in body")
    alice.call("GET", f"/api/incidents/{INC['alice_new']}", label="AFTER: Alice reads own")
    morgan = Client("morgan")
    morgan.call("POST", f"/api/incidents/{INC['alice']}/triage",
                label="Morgan -> triage already Triaged incident (очікувано 409)")


def scenario_child():
    header("CHILD: GET /api/incident-comments/{id} (A-12)")
    alice = Client("alice")
    alice.call("GET", f"/api/incident-comments/{COMMENT['to_alice']}", label="Alice -> public comment on own")
    alice.call("GET", f"/api/incident-comments/{COMMENT['to_bob']}", label="Alice -> comment on Bob incident")
    alice.call("GET", f"/api/incident-comments/{COMMENT['internal']}", label="Alice -> internal comment on own")
    Client("morgan").call("GET", f"/api/incident-comments/{COMMENT['internal']}",
                          label="Morgan -> internal comment")


SCENARIOS = {
    "read": scenario_read, "list": scenario_list, "update": scenario_update,
    "overpost": scenario_overpost, "child": scenario_child,
    "triage": scenario_triage, "delete": scenario_delete,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=list(SCENARIOS) + ["all"])
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args()
    BASE = args.base.rstrip("/")
    order = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for name in order:
        SCENARIOS[name]()
