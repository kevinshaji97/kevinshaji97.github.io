---
title: "It Starts With One Request"
description: "Why I'm starting this blog, and what a single curl command teaches about AppSec, pentesting, cloud security and incident response."
date: 2026-09-30 10:00:00 +0100
categories: [Meta]
tags: [intro, appsec, pentesting, cloud-security, incident-response]
pin: true
---

Almost every assessment I've done starts the same way:

```bash
curl -I https://target.example
```

One request. No payloads, no scanners, nothing clever. And yet the response often says more than the application intended:

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3
Set-Cookie: session=abc123; path=/
Access-Control-Allow-Origin: *
```

A version string to check against known CVEs. A runtime that's past end-of-life. A session cookie missing `Secure`, `HttpOnly` and `SameSite`. A CORS policy that trusts everyone. There's no exploit yet, just a system quietly describing its own weak spots to anyone who asks.

That's what this blog is about: **the gap between what a system is supposed to do and what it actually tells you.**

## Why I'm writing this

I've spent over five years in security across Application Securitypentesting, vulnerability management and SOC/incident handling, and now product security. Along the way, I've noticed that the most useful lessons rarely make it into documentation. They live in Slack threads, triage notes and post-incident retros, and then they're forgotten.

This blog is where I'll write them down properly. Partly for you, and partly so that future me stops relearning the same things.

## What you'll find here

Everything here follows the lifecycle of a vulnerability, from the moment it's written to the moment someone exploits it.

**AppSec: before it ships.**
Threat modelling, secure code review and making security findings that developers actually want to fix. The goal is fewer bugs reaching production, not more tickets.

**Pentesting: finding what slipped through.**
Web app testing methodology, DAST that isn't just noise, and how to tell a real finding from a false positive before it wastes everyone's afternoon.

**Cloud Security: where the blast radius lives.**
IAM misconfigurations, over-permissive roles, exposed storage, and why "it's in a private subnet" is not a security control.

**Incident Response: when it's already happened.**
Triage, log analysis and what the first hour of an incident should look like, along with the lessons that only show up in the post-mortem.

> Each area feeds the next. Pentest findings shape AppSec guidance. Cloud misconfigurations become incidents. Incidents reveal what testing missed.
{: .prompt-info }

## What to expect

- ** Commands you can run, checklists you can steal, and reasoning you can apply.
- ** Tools that didn't deliver, approaches that backfired, and findings I got wrong.

> Everything here is for education and authorised testing only. If you don't have permission, don't point it at a target.
{: .prompt-warning }

## One last thing

Next time you look at a web app, run `curl -I` against it and read the headers slowly. You'll be surprised how often the system tells you exactly where to look.

See you in the next post.

— Kevin
