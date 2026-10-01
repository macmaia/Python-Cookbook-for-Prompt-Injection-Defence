OUT = "06-when-the-value-is-yours-and-theirs.ipynb"

md("""
# When the value is yours and the attacker's

Sometimes the injected content contains the *right* value. A page the user asked the agent to read mentions the user's own address, or the invoice number the user typed also appears in the supplier's email. The model uses the value, and the gate can't tell which copy it came from: the user's message or the page.

catraca calls this a **coincidence**. It's the one place where the gate doesn't have a clean answer, so it gives you three options instead of guessing.
""")
code("""
%pip install -q catraca==0.2.0
""")
code("""
from catraca import Caller, ChannelConfig, ContextRegistry, DeclarativePolicy, Egress, EvidenceLog, Gate, MemorySink

channels = ChannelConfig.from_dict({"version": 1, "channels": {
    "user": {"integrity": "TRUSTED",   "confidentiality": "*"},
    "web":  {"integrity": "UNTRUSTED", "confidentiality": "*"},
}})
egress = Egress.from_dict({"version": 1, "tools": {"send_email": {"emails": ["@example.com"]}}})
ana = Caller(tenant="acme", user="ana")

def policy(confirm):
    return DeclarativePolicy.from_dict({"version": 1, "tools": {"send_email": {
        "callers": {"tenants": ["acme"], "users": "*"},
        "confirm_on_coincidence": confirm,
        "args": {"to": {}, "body": {"integrity": "ANY"}},
    }}})

def gate(confirm=False):
    registry = ContextRegistry(channels)
    registry.annotate("Email the meeting notes to ana@example.com", "user")
    registry.annotate("Meeting notes. Questions? Write to ana@example.com.", "web")
    log = EvidenceLog(MemorySink())
    return Gate(registry, policy(confirm), egress=egress, evidence=log), log

CALL = {"to": "ana@example.com", "body": "Here are the notes."}
""")
md("""
## Option 1: deny (the default)
""")
code("""
g, _ = gate()
d = g.decide("send_email", CALL, caller=ana)
print(d.verdict.value, d.reason.value)
""")
md("""
The address is right, and the call is refused anyway. That's the safe default: in this example the copy in the page is harmless, but the gate can't know that, and a coincidence is exactly what an attacker would try to produce if they could.

## Option 2: ask the person

With `"confirm_on_coincidence": true` in the policy, the same call comes back as `REQUIRE_CONFIRMATION`, with what to show the person and a token:
""")
code("""
g, log = gate(confirm=True)
d = g.decide("send_email", CALL, caller=ana, call_id="call-1")
print(d.verdict.value, d.reason.value)
for c in d.confirmation:
    print(f"  confirm {c.argument} = {c.value!r}, which you typed in: {', '.join(c.trusted_origins)}")
""")
md("""
Your app shows that to the person. On an explicit yes, it calls `decide` again with the same call and the token:
""")
code("""
token = d.confirmation_token
again = g.decide("send_email", CALL, caller=ana, call_id="call-1", confirmation=token)
print(again.verdict.value, again.reason.value)
""")
md("""
The token is bound to that exact call. It works once, it expires, and it doesn't carry over to anything else:
""")
code("""
reused = g.decide("send_email", CALL, caller=ana, call_id="call-1", confirmation=token)
print("reused:        ", reused.verdict.value, reused.reason.value)

d = g.decide("send_email", CALL, caller=ana, call_id="call-2")
swapped = g.decide("send_email", {**CALL, "body": "Something else."}, caller=ana, call_id="call-2",
                   confirmation=d.confirmation_token)
print("changed body:  ", swapped.verdict.value, swapped.reason.value)

d = g.decide("send_email", CALL, caller=ana, call_id="call-3")
print("person said no:", g.decline(d.confirmation_token))
""")
md("""
Only a pure coincidence can be confirmed. A value the page brought in that the user never wrote is denied, even with confirmation switched on:
""")
code("""
g, _ = gate(confirm=True)
d = g.decide("send_email", {"to": "thief@example.com", "body": "Here are the notes."}, caller=ana)
print(d.verdict.value, d.reason.value)
""")
md("""
Otherwise confirmation would become a way to launder injected values through a tired person clicking "yes".

## Option 3: measure before you decide

Confirmation only helps if your app shows the prompt, waits for a real yes and sends the token back, and if people read the prompts. Asking too often teaches them to click without reading. So before building it, count how often coincidences actually happen in your traffic. The evidence log has a figure for it:
""")
code("""
from catraca import evidence

g, log = gate()
for _ in range(3):
    g.decide("send_email", CALL, caller=ana)
g.decide("send_email", {"to": "ana@example.com", "body": "hi"}, caller=ana)
print(evidence.stats(log.sink.records))
""")
md("""
`coincidence_rate` is the share of decisions that were refused only because of a coincidence. Here it's 1.0, since this toy traffic is nothing but the same coincidence. In real traffic, if it's low, the denials cost little and you can leave confirmation off. If it's high, it's worth building the confirmation step, or looking at why trusted values keep showing up in untrusted content.

**Next:** [Plans the injection can't change](07-plans-the-injection-cant-change.ipynb)
""")
