# Security Header & Misconfig Scanner

A Python command-line tool that checks a website for missing security
settings and accidentally exposed sensitive files. Built as a learning
project while studying web application security.

```
Overall grade: D
```

## Table of contents

- [What this tool actually does](#what-this-tool-actually-does)
- [Why this matters (for beginners)](#why-this-matters-for-beginners)
- [Installation](#installation)
- [Usage](#usage)
- [Example output](#example-output)
- [How each check works](#how-each-check-works)
- [Project structure](#project-structure)
- [Running the tests](#running-the-tests)
- [Disclaimer - please read](#disclaimer---please-read)
- [Roadmap](#roadmap)

## What this tool actually does

You give it a website address. It acts like a browser visiting that site,
then checks four things:

1. **Security headers** - small instructions a server is supposed to send
   that tell the browser "block this kind of attack."
2. **Exposed sensitive files** - files like `.env` or `.git/config` that
   should never be publicly reachable, but sometimes are by accident.
3. **HTTPS enforcement** - whether the site forces a secure connection, or
   allows an insecure `http://` connection too.
4. **SSL certificate expiry** - how many days are left before the site's
   HTTPS certificate expires.

It then prints a pass/fail report and an overall letter grade (A-F).

## Why this matters (for beginners)

If you're new to security, here's the short version:

**Security headers** are like safety instructions a website sends along
with every page, invisible to normal visitors but read by the browser. For
example, `X-Frame-Options` tells the browser "don't let other sites hide my
page inside an invisible frame and trick people into clicking it" (this
attack is called *clickjacking*). Missing headers don't mean a site is
instantly hackable, but they remove a layer of protection that costs
nothing to turn on.

**Exposed files** happen when a developer forgets a file on the live
server. A `.env` file often contains passwords and API keys. A `.git`
folder can leak a site's entire source code and history. If a stranger can
download these by typing the right URL, that's a real, exploitable problem.

This category of issue is common enough that it appears throughout the
[OWASP Top 10](https://owasp.org/www-project-top-ten/), the standard
reference list of the most common web application security risks.

## Installation

You need Python 3.9 or newer installed.

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/security-header-scanner.git
cd security-header-scanner

# 2. (Recommended) create a virtual environment so dependencies
#    don't clash with other Python projects on your machine
python3 -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate

# 3. Install the one dependency this project needs
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan - prints a readable text report
python3 scanner.py example.com

# You can include or omit https://, both work
python3 scanner.py https://example.com

# Get the result as JSON instead (useful for scripts/automation)
python3 scanner.py example.com --json

# Save the report to a file as well as printing it
python3 scanner.py example.com --output report.json

# Increase the timeout for a slow server (default is 10 seconds)
python3 scanner.py example.com --timeout 20
```

## Example output

Real scan of github.com, captured on 2026-10-01:

```
Scanning: https://github.com/
HTTP status: 200
HTTPS enforced: yes

-- Security Headers --
[PASS] Content-Security-Policy      Blocks malicious inline scripts (XSS attacks)
[PASS] Strict-Transport-Security    Forces HTTPS, blocks downgrade attacks
[PASS] X-Frame-Options              Prevents clickjacking via hidden iframes
[PASS] X-Content-Type-Options       Stops the browser from mis-reading file types
[PASS] Referrer-Policy              Controls what leaks in the Referer header
[FAIL] Permissions-Policy           Restricts access to camera, mic, location, etc.
Header score: 5/6

-- Exposed File Check --
[PASS] /.env                  not reachable
[PASS] /.git/config           not reachable
[PASS] /.git/HEAD             not reachable
[PASS] /config.php.bak        not reachable
[PASS] /wp-config.php         not reachable
[PASS] /.DS_Store             not reachable
[PASS] /backup.zip            not reachable
[PASS] /.aws/credentials      not reachable
[PASS] /phpinfo.php           not reachable
Exposed files found: 0/9

-- SSL/TLS Certificate --
Days until expiry: 61
[PASS] Certificate is valid and not expiring soon

Overall grade: A
```

## How each check works

| Check | Method |
|---|---|
| Security headers | Sends one GET request, reads the response headers, compares against a known list |
| Exposed files | Requests each known-sensitive path directly (e.g. `yoursite.com/.env`) and flags any that return HTTP 200 |
| HTTPS enforcement | Requests the `http://` version of the site and checks whether it redirects to `https://` |
| Certificate expiry | Opens a raw TLS connection and reads the certificate's expiry date |

The grading logic lives in `ScanReport.overall_grade` inside `scanner.py` -
it's a simple weighted percentage, not a cryptographic risk score, so treat
the letter grade as a rough guide rather than an authoritative rating.

## A note on results that differ from your browser

While testing this tool, I found that scanning my own site
(`luxicon.sothebyasae.workers.dev`, a Cloudflare Workers deployment)
returned a 404 from this tool and from `curl`, while the site loaded
perfectly in a normal browser.

Digging into it, this wasn't a bug in the scanner. Some hosting setups
(Cloudflare Workers/Pages included) serve different responses depending on
*how* a request is made, not just the URL:

- A plain script request (Python's `requests`, `curl`) can be routed
  differently than real browser navigation, especially on sites using
  internal asset-serving logic or SPA routing.
- In my case, a `curl -I` (HEAD request) returned a plain 404, while a full
  `curl` GET request returned Cloudflare error 1042 - which specifically
  means the Worker's own code attempted an internal fetch that Cloudflare
  blocks, not that the page doesn't exist.
- Changing the tool's User-Agent to mimic a browser did **not** fix this,
  which ruled out simple bot-blocking as the cause.

**The takeaway:** a scanner like this one shows you what an automated,
non-browser client sees - which is a legitimate and useful thing to know,
since real-world bots, crawlers, and monitoring tools are non-browser
clients too. But it is not automatically the same as what a human visitor
sees. If a scan result looks wrong, the right next step is to compare it
against the site's own server/Worker logs and a plain `curl` request before
assuming the tool is broken or the site is broken.

## Project structure

```
security-header-scanner/
├── scanner.py              # the tool itself
├── tests/
│   └── test_scanner.py     # unit tests (no network needed to run them)
├── requirements.txt        # dependency needed to run the tool
├── requirements-dev.txt    # adds pytest, for running tests
├── LICENSE                 # MIT license
├── CONTRIBUTING.md         # how to extend the tool
└── README.md               # this file
```

The code is deliberately split into small functions: one that fetches data
from the network, and separate "pure" functions that just evaluate results
(e.g. `evaluate_headers`). This is why the tests in `tests/test_scanner.py`
can run instantly without needing an internet connection - they test the
evaluation logic directly, not the network calls.

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

You should see 9 tests pass.

## Disclaimer - please read

**Only scan websites you own, or have explicit written permission to test.**

Running this against a website you don't control, even just to "check," can
violate that site's Terms of Service, and in some jurisdictions may be
treated as unauthorized access under computer misuse laws - regardless of
whether you found anything or caused any damage.

Safe targets to practice on:
- A site or app you built and deployed yourself
- Deliberately vulnerable practice sites (e.g. OWASP Juice Shop,
  HackTheBox, TryHackMe labs) designed for this kind of testing

This tool is also not a complete security audit. It checks a small, specific
set of common misconfigurations. A clean report does not mean a site is
fully secure, the same way a car passing an inspection doesn't mean it can
never break down.

## Roadmap

- [ ] Parallelize the exposed-file checks for faster scans
- [ ] Add a `--wordlist` option to supply a custom list of paths to check
- [ ] Add colorized terminal output
- [ ] Add a GitHub Actions workflow to run the test suite automatically
- [ ] Bulk mode: scan a list of URLs from a file

## License

MIT - see [LICENSE](LICENSE).