---
title: "Privacy Impact Assessment of Third-Party Dependencies"
date: 2026-10-12 09:00:00 +0100
categories: [AppSec, Privacy]
tags: [privacy, pia, supply-chain, llm, python, gdpr, masters]
description: "A masters project that scores your dependencies on how they treat personal data — using an LLM to read the privacy policy so you don't have to."
---

We scan dependencies for CVEs all day. We pin versions, we generate SBOMs, we get Dependabot PRs at 3am. But ask a team *"what does this analytics SDK do with our users' data?"* and you usually get a shrug and a link to a 9,000-word privacy policy nobody has read.

That gap is what my masters project was about. The result is **PIA Framework** — a CLI that takes a dependency name and version and gives you a privacy score out of 10.

> Repo: [kevinshaji97/PIA-Framework](https://github.com/kevinshaji97/PIA-Framework)
{: .prompt-info }

## The problem

A Privacy Impact Assessment (PIA) is the process of working out how something handles personal data before you commit to it. Under GDPR, that's not optional for high-risk processing — and pulling in a third-party SDK that phones home is exactly the kind of decision that should get one.

In practice, nobody does it per dependency. It's slow, it's manual, and it means reading legal text. So the dependency goes in, and the privacy review happens later — or never.

I wanted to see how much of that first pass could be automated without turning it into a black box.

## What it does

```bash
pia assess sentry-sdk 2.19.0
pia assess mixpanel-browser@2.58.0
pia assess posthog==3.7.0 --json
```

Give it a package (PyPI or npm), and it:

1. **Looks up the registry** to confirm the version exists and find the vendor's homepage.
2. **Hunts down the privacy policy** — links on the homepage, plus a web search (Brave, falling back to DuckDuckGo). Candidates get ranked, and GitHub issues, forum threads and docs pages are penalised, because "the first result that mentions privacy" is frequently a Stack Overflow question.
3. **Has an LLM classify the policy** against a fixed set of criteria, quoting the policy as evidence.
4. **Scores it in code**, not in the model.

That last point is the one I care about most.

## Don't let the LLM pick the number

The obvious version of this tool is: paste the policy into a chatbot and ask "score this out of 10." That gives you a number. It does not give you the *same* number twice, and you can't explain where it came from.

So the LLM's job is narrow. For each criterion it picks a rating from a fixed list of options and quotes the bit of the policy that justifies it. The score is then computed deterministically from those ratings in [`pia/rubric.py`](https://github.com/kevinshaji97/PIA-Framework/blob/main/pia/rubric.py):

| Criterion | Weight |
|---|---|
| Data collection scope | 2.0 |
| Sensitive data | 1.5 |
| Purpose of processing | 1.5 |
| Third-party sharing | 1.5 |
| Data retention | 1.0 |
| User rights | 1.0 |
| Consent and control | 0.5 |
| Security measures | 0.5 |
| International transfers | 0.5 |

Grades: **Strong** ≥ 8, **Adequate** ≥ 6, **Weak** ≥ 4, **Poor** < 4.

A few design calls worth flagging:

- **Silence scores zero.** If a policy doesn't mention retention, it doesn't get the benefit of the doubt. Vague policies should look bad.
- **"We collect nothing" scores 10.** If the policy states no personal data is collected at all, there's nothing else to assess.
- **Quotes get verified.** Every quote the model returns is checked against the actual policy text. If it isn't there, it's flagged `[unverified]`. LLMs will happily invent a reassuring sentence about encryption at rest; this catches it.

The model does the reading. The code does the judging. You can audit both.

## Bring your own model

Not everyone wants to send documents to a cloud API, so the provider is pluggable: Anthropic, OpenAI, Gemini, any OpenAI-compatible server (LM Studio, vLLM, OpenRouter, Groq), or **Ollama** — in which case the policy text never leaves your machine.

Privacy policies are public, so this is less about secrecy and more about the principle of a privacy tool not casually shipping data off to a third party. It would have been a bit embarrassing otherwise.

Fair warning on local models: policies can run to ~25k tokens, so you'll need to bump Ollama's `num_ctx` or trim with `--max-chars`.

## When the search falls over

Scripted web search gets rate-limited. Some vendors bury their policy behind three redirects and a cookie wall. Some have no policy at all.

So there are escape hatches:

```bash
pia assess acme-sdk 1.4.0 --policy-url https://acme.example/legal/privacy
pia assess acme-sdk 1.4.0 --policy-file ./acme-privacy.txt
```

In a terminal, a failed search just prompts you for a URL or file, and asks for confirmation if the page doesn't look like a privacy policy. In CI it fails loudly and tells you the exact `--policy-url` command to run, rather than hanging forever waiting for input nobody will type.

## Putting it in the pipeline

The point was never a tool you run once. It's a gate:

```bash
pia assess some-new-sdk 1.0.0 --fail-under 6
```

Below the threshold, the build fails, and someone has to have a conversation about it. That conversation is the whole point. History is kept in a local SQLite DB (`pia history`, `pia show <id>`) so you can see how a dependency's score moves between versions.

<!-- TODO: drop in a real `pia assess` run here — screenshot or trimmed output -->

## What it doesn't do

I'd be doing a bad job of a security blog if I oversold this.

- **It reads the policy, not the traffic.** A policy is what a vendor *says* it does. What the SDK actually transmits is a job for a proxy and an afternoon. The score is a starting point for that, not a substitute.
- **Garbage policy in, garbage score out.** Always check the policy URL in the report. Pure open-source libraries usually have no privacy policy at all, and the tool can end up picking up the publisher's *website* policy instead — it warns you when that's likely, but it's worth a look.
- **It isn't legal advice.** It's an automated first pass to make the real review faster, not to skip it.

## What I learned

<!-- TODO: your own take. Some prompts:
  - What surprised you when you ran it against real packages?
  - What did your supervisor / examiners push back on?
  - What would you change if you started again?
-->

The biggest lesson for me: LLMs are genuinely good at reading dense legal text, and genuinely bad at being the thing you trust for a final answer. Constrain the output, verify the evidence, and keep the decision in code you can read.

## Try it

```bash
git clone https://github.com/kevinshaji97/PIA-Framework.git
cd PIA-Framework
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
cp .env.example .env   # add your API key
pia assess sentry-sdk 2.19.0
```

Issues and PRs welcome — especially if you find a policy that breaks the discovery logic. I'm sure there are plenty.
