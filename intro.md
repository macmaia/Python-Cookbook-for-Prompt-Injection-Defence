# Python Cookbook for Prompt Injection Defence

An agent that reads email, tickets, web pages or documents can be told what to do by whoever wrote them. That's indirect prompt injection, and it's now part of how agent security is taught. This book works through it in runnable Python, with one library: [catraca](https://github.com/macmaia/catraca), which checks where every argument of a tool call came from before the call runs.

Every chapter runs as it is, with no API key. The language model is a short function that makes the tool call a fooled model would make, so the examples are free, fast and give the same result every time. The output under each cell is what the code printed.

## Chapters

1. [Your agent followed an instruction it read in a ticket](01-your-agent-followed-an-instruction.ipynb). Indirect prompt injection end to end: an agent leaks another customer's data, a keyword filter misses three rewordings, and a provenance check denies all four.
2. [Where did this argument come from?](02-where-did-this-argument-come-from.ipynb). Channels, integrity and confidentiality labels, and the whole-token rule that decides whether a tool-call argument is trusted.
3. [A gate, not a filter](03-a-gate-not-a-filter.ipynb). A declarative policy, the three verdicts, reason codes, failing closed, and linting a policy that was loosened too far.
4. [Rewording doesn't help the attacker](04-rewording-doesnt-help.ipynb). The same injected address hidden seven ways (base64, rot13, leetspeak, homoglyphs, spelled out, described, translated), all denied for the same reason.
5. [Exfiltration through a link](05-exfiltration-through-a-link.ipynb). The EchoLeak pattern: Markdown images, redirectors and scheme-relative links in a message body, stopped by egress allowlists and link provenance.
6. [When the value is yours and the attacker's](06-when-the-value-is-yours-and-theirs.ipynb). Coincidences, single-use confirmation tokens bound to the call, and measuring the coincidence rate before turning confirmation on.
7. [Plans the injection can't change](07-plans-the-injection-cant-change.ipynb). CaMeL-style sealed plans: literal destinations, a quarantine model for untrusted data, human confirmation, and what the guarantee costs.
8. [Keeping the registry honest](08-keeping-the-registry-honest.ipynb). What happens when an integration forgets to label a source or drops one too early, and how observe() turns both into denials.
9. [The log an auditor can read](09-the-log-an-auditor-can-read.ipynb). A hash-chained, pseudonymised decision log: what a record holds, tamper detection, signed checkpoints, replay and statistics, with LGPD and GDPR notes.
10. [Measuring it on yourself](10-measuring-it-on-yourself.ipynb). Catch rate, false positives, Wilson intervals and latency on your own cases, and how to read published benchmark numbers.
11. [What none of this does](11-what-none-of-this-does.ipynb). The limits, each with code: choosing among the user's own values, the wrong tool with the right values, leaks in reply text, denial by coincidence.

## Running it yourself

```
pip install -r requirements.txt
jupyter lab
```

Python 3.10 or newer. catraca has no dependencies of its own.

*Em português:* o livro está em inglês. Ele ensina, com código que roda, como a biblioteca catraca protege agentes de LLM contra injeção indireta de prompt e vazamento de dados. Para rodar, use `pip install -r requirements.txt` e depois `jupyter lab`.

## Citing

Maia, M. A. (2026). *Python Cookbook for Prompt Injection Defence*. https://macmaia.github.io/Python-Cookbook-for-Prompt-Injection-Defence/

## Licence

Code under the Apache License 2.0, text under CC BY 4.0.
