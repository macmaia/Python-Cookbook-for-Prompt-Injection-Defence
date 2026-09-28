# Python Cookbook for Prompt Injection Defence

An agent that reads email, tickets, web pages or documents can be told what to do by whoever wrote them. That's indirect prompt injection, and it's now part of how agent security is taught. This book works through it in runnable Python, with one library: [catraca](https://github.com/macmaia/catraca), which checks where every argument of a tool call came from before the call runs.

Every chapter runs as it is, with no API key. The language model is a short function that makes the tool call a fooled model would make, so the examples are free, fast and give the same result every time. The output under each cell is what the code printed.

## Chapters

1. [Your agent followed an instruction it read in a ticket](01-your-agent-followed-an-instruction.ipynb)
2. [Where did this argument come from?](02-where-did-this-argument-come-from.ipynb)
3. [A gate, not a filter](03-a-gate-not-a-filter.ipynb)
4. [Rewording doesn't help the attacker](04-rewording-doesnt-help.ipynb)
5. [Exfiltration through a link](05-exfiltration-through-a-link.ipynb)

Coming next: when the value is yours and the attacker's, plans the injection can't change, keeping the registry honest, the log an auditor can read, measuring it on yourself, and what none of this does.

## Running it yourself

```
pip install catraca
jupyter lab
```

Python 3.10 or newer. catraca has no dependencies of its own.
