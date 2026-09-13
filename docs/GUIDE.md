# capat guide

The full reference. For installation and a command you can copy right now,
start at the [README](../README.md).

## Start here: benchmark offline

Tuning needs ground truth, and ground truth means a human reading the images.
`collect` fetches challenges and saves them **unlabelled**. Only the CAPTCHA
endpoint is touched, so no login is attempted and nothing approaches a lockout
threshold:

```bash
capat collect -c https://app.example.com/captcha.png --count 25 --output corpus
```

Files arrive as `unlabelled-001-<hash>.png`. Rename each to the answer it
shows, then measure the engine against that ground truth:

```bash
capat bench corpus --solver ddddocr
```

```
  label   predicted   match   conf   sec
  T29MG   T29M6       no      0.41   0.63

  1/2 solved exactly = 50.0% accuracy   (character similarity 90.0%)
  0.58s mean per solve  ->  ~3,100 correct solves/hour, single process
```

The filename is the label, so `A8R36.png` and `A8R36_002.png` both label as
`A8R36`. Identical images are reported rather than saved twice: a challenge
that repeats during collection is a finding on its own.

Twenty to thirty images is enough to steer tuning. Fewer than ten steers
nothing, so report such a run as indicative, not as a rate.

This is the most defensible number you can produce, because it depends on
nothing but the images. Use `capat solve <image> --save-processed out.png` to
tune preprocessing until accuracy stops improving.

`-c` alone is enough for `collect`; `-u https://app.example.com/login` also
works and finds the image on the page, as does `--profile app.json`.


## Auditing a live login page

### The short way: answer the questions

```bash
capat setup
```

It asks for the facts, writes `app.json`, prints the command it assembled, and
runs it. Nothing is sent to the target until the questions are done.

```
target
  login URL, where the form posts: https://app.example.com/api/auth/login
  CAPTCHA URL, or 'auto' if it changes on every page load: https://app.example.com/api/captcha

the CAPTCHA endpoint
  what it returns (image/json) [image]: json
  JSON path to the base64 image [image]:
  JSON path to the challenge id, blank if none [id]:
  field name the id is submitted back in [captchaId]:

the login request
  body encoding (form/json/multipart) [form]: json
  username field name [username]:
  password field name [password]:
  CAPTCHA answer field name [captcha]: captchaValue
  extra field, name=value (blank when done): lang=en

how the application answers - this is what the measurement reads
  it says WRONG CAPTCHA:            Invalid CAPTCHA
  it says WRONG USERNAME/PASSWORD:  Invalid username or password
  it says SUCCESS, blank to skip:   json:isSuccess=true
```

The last three are the only ones you cannot guess from the URL bar. Submit one
login by hand with a wrong CAPTCHA, then one with a wrong password, and copy
what comes back - telling those two apart *is* the measurement, and the tool
will not infer them for you.

`--dry-run` writes the profile and prints the command without running it.

### The direct way: flags

Point it at the URL and describe the form with flags, the way you would drive
`ffuf`:

```bash
capat audit -u https://app.example.com/login \
  --captcha-fail "invalid captcha" \
  --auth-fail   "invalid username or password" \
  --success-url /dashboard
```

Three facts, and only two of them are really about the target: how the
application says *wrong CAPTCHA* and how it says *wrong password*. Telling
those apart **is** the measurement — the solve-rate module refuses to guess
without both, because reading one as the other silently inflates the number.

`--captcha-url` is optional: left out, the login page is fetched and the
CAPTCHA image found on it, and the URL used is printed. Only an `<img>` that
actually names itself (src, id, class, alt) counts as a match — a guess that
picked the site logo would report a solve rate for the wrong image, so when
nothing matches the tool asks for `--captcha-url` rather than guessing.

The rest of the form is flags too:

```bash
capat audit -u https://app.example.com/api/login \
  --form-url https://app.example.com/login \
  --csrf-field _token \
  --encoding json \
  -H "X-Requested-With: XMLHttpRequest" \
  -F "remember=1" \
  --captcha-response json --captcha-image-key data.image \
  --captcha-id-key data.id --captcha-id-field captcha_id \
  --captcha-fail json:code=4001 \
  --auth-fail   json:code=4002 \
  --success     json:code=0 \
  --save-profile app.json
```

Match values are body substrings unless they carry a prefix: `re:PATTERN`,
`status:422`, `url:/dashboard`, `json:code=4001`, `header:location=/home`.
Repeat any of the three flags to list every phrasing the app uses; they are
OR-ed. Everything a profile can express except `body_template` has a flag —
`--username-field`, `--password-field`, `--captcha-field`, `-X/--method`,
`--extract 'token=hidden:_token'`, `--captcha-header`.

`--save-profile app.json` writes the run out as a profile, so once a target is
described on the command line it never has to be described again.

### Or describe the form once, in JSON

```json
{
  "login_url": "https://app.example.com/login",
  "captcha_url": "https://app.example.com/captcha.png",
  "csrf_field": "_token",
  "captcha_length": 5,
  "captcha_charset": "ABCDEFGHIJKLMNPQRSTUVWXYZ23456789",
  "username": "audit-account",
  "criteria": {
    "captcha_failure": ["invalid captcha", "wrong verification code"],
    "auth_failure": ["invalid username or password"],
    "success_url_contains": "/dashboard"
  }
}
```

Then run it:

```bash
capat audit --profile app.json --samples 50
```

```bash
# write it out, through Burp, slower
capat audit --profile app.json \
  \
  --proxy http://127.0.0.1:8080 \
  --rps 1 --samples 100 \
  --format markdown --output captcha-assessment.md
```

Exit codes: `0` clean, `1` findings at MEDIUM or above, `2` usage error or unreachable target.

Flags and profiles compose, and the flag wins, so one saved profile points at
a different environment without editing it:

```bash
capat audit --profile app.json -u https://staging.example.com/login
```

### If the CAPTCHA endpoint returns JSON

Plenty of applications don't serve a raw image. They return JSON carrying a
**base64 image and an identifier**, and the login request has to send that
identifier back — the id, not the session cookie, is what binds an answer to a
challenge:

```json
{ "status": "ok", "data": { "id": "ch-42", "image": "data:image/png;base64,iVBORw0..." } }
```

Point the profile at both keys and name the field the id is submitted in:

```json
{
  "login_url": "https://app.example.com/api/login",
  "captcha_url": "https://app.example.com/api/captcha",
  "captcha_response": "json",
  "captcha_image_key": "data.image",
  "captcha_id_key":    "data.id",
  "captcha_id_field":  "captcha_id",
  "criteria": { "...": "as above" }
}
```

Keys are dotted paths, so `data.image` or even `result.items.0.png` all work.
The base64 is decoded whether or not it carries a `data:` prefix, line wrapping,
padding, or the URL-safe alphabet. `captcha_id_key` and `captcha_id_field` must
be set together — reading an id and never sending it back would fail every
attempt while looking like an unbreakable CAPTCHA, so the profile is rejected
instead.

Everything else is unchanged: the solve rate, the enforcement checks and the
credential audit all thread the identifier through automatically.

### A CAPTCHA URL that changes every load

An `<img>` whose id or query string changes on each request (`capture_qw23`,
then `capture_ew34`). A URL captured once goes stale, so add one word:

```bash
capat audit -u https://app.example.com/login -c auto \
  -cf "invalid captcha" -af "invalid username or password"
```

`-c auto` re-reads the image URL from every login page, at no extra request.
When the URL is *derivable* rather than unguessable, name the varying part and
let an extractor fill it - URLs take `{{placeholders}}` like headers and bodies
do:

```bash
  -c 'https://app.example.com/captcha?n={{nonce}}' \
  -E 'nonce=regex:captcha[?]n=([^"]+)'
```

Without either, capat reports "rotation not measured" rather than claiming the
challenge is static.

### A CAPTCHA drawn inline

A base64 `data:` URI with no endpoint behind it - the shape most SPAs now use:

```bash
capat audit -u https://app.example.com/login -c base64 \
  -cf "invalid captcha" -af "invalid username or password"
```

There is nothing to fetch, so capat reads the image out of each login page it
already loads. Settings that describe a CAPTCHA *response* - `-cd`/`-cn`, a
`@captcha` extractor - are refused up front rather than waiting on a reply that
never comes.

### Fitting it to any application

No two login flows are alike, so everything variable is data in the profile.
The defaults cover a plain form post; each knob below exists because some real
application needed it.

**Body encoding.** `"encoding": "form"` (default), `"json"`, or `"multipart"`.
Under `json`, dotted field names nest - `"username_field": "user.name"` sends
`{"user": {"name": "..."}}`. Form bodies keep dots literal.

**Headers.** `"headers": {"X-Requested-With": "XMLHttpRequest"}` - sent on every
request, and values may contain placeholders.

**Extracting tokens.** Not every app puts its CSRF token in a hidden input.
Name what you need and where it lives:

```json
"extract": [
  {"name": "csrf",  "source": "regex",  "key": "content=\"([^\"]+)\""},
  {"name": "xsrf",  "source": "cookie", "key": "XSRF-TOKEN"},
  {"name": "nonce", "source": "json",   "key": "session.nonce", "required": false}
]
```

Sources are `hidden` (input name), `regex` (one capture group), `json` (dotted
path), `header`, and `cookie`. Read from the login page by default, or from the
CAPTCHA response with `"from": "captcha"`. Each name becomes a placeholder.

**Matchers.** A bare list is shorthand for body substrings. When the app answers
with codes rather than prose, say so:

```json
"criteria": {
  "captcha_failure": { "json": { "code": 4001 } },
  "auth_failure":    { "json": { "code": 4002 }, "status": [401] },
  "success":         { "json": { "code": 0 } }
}
```

Conditions available: `body`, `regex`, `json`, `status`, `header`, `url`. They
are OR-ed - list every phrasing the app uses - unless you set `"mode": "all"`.

**The escape hatch.** When the structured fields cannot express the request,
write it yourself:

```json
"encoding": "json",
"body_template": "{\"auth\":{\"user\":{{username|json}},\"cap\":{{captcha|json}},\"key\":{{captcha_id|json}}}}"
```

Placeholders are `{{username}}`, `{{password}}`, `{{captcha}}`, `{{captcha_id}}`
and any extractor name. The `|json` filter emits a properly escaped JSON string
so an answer containing a quote cannot break the body; `|url` percent-encodes.
Unknown placeholders are caught when the profile loads, not mid-run.


### How the live solve rate is measured

Without labeled data you cannot know whether a solve was right — unless the
application tells you. It does, through *which* error it returns:

```
submit(solved_captcha, random_user, random_password)
   -> "invalid captcha"              the solve was wrong
   -> "invalid username or password" the solve was RIGHT; the CAPTCHA was passed
```

That is what `criteria.captcha_failure` and `criteria.auth_failure` are for; the
solve-rate module refuses to guess without both. Two consequences worth knowing:

- **No real account is touched.** The probe identity defaults to a random,
  non-existent username (`cb-probe-…`), so a measurement cannot lock anyone out.
  The `username` field is used *only* by the opt-in credential audit.
- **Nothing can accidentally succeed.** The password is random per attempt.

### Checks that need no OCR at all

`captcha-gate` runs whether or not a recognition engine is installed, and in
practice it finds more than the solve rate does:

| Check | Failure means |
|---|---|
| Answer omitted from an otherwise valid request | The answer is validated only when the client chooses to send it — skip it. |
| Empty value accepted | An empty answer matches an unset server-side value. |
| Image never rotates | Solve it once by hand, replay forever. |
| Answer replayable | Not invalidated after use; one solve amortises over many attempts. |

Each of these submits a *real* challenge (and, on a JSON API, its real
identifier) and varies only the answer, so a finding means the answer itself
went unchecked — not that the request was malformed.

Run just these with `--skip-solve-rate`.

### The credential audit (opt-in)

```bash
capat audit --profile app.json \
  --passwords passwords.txt --users accounts.txt --lockout-threshold 3
```

Off unless the flag is given. `--users` is optional; without it the audit runs
against the single `username` named in the profile.

**Ordering is a safety decision, so it is explicit.** `--order spray` (the
default) walks passwords on the outside and identities on the inside, so every
account takes at most one failure per password and the run stays as far from a
lockout policy as it can for as long as it can. `--order brute` exhausts one
identity before moving to the next - the classic ordering, and the fastest way
to lock an account out. Budgets are tracked **per identity**, so one account
reaching its limit does not end the audit.

It is deliberately slow. It exists to demonstrate that the CAPTCHA does not
stop the attempt, not to be an efficient cracker.

Responses matching none of the criteria are counted and reported: an
unrecognised success would otherwise be indistinguishable from a clean run.

**A cracked password is reported in full**, in the finding title and in the
evidence, next to the wordlist line it came from. A finding that will not say
which password worked cannot be acted on:

```json
{
  "username": "audit-account",
  "password": "sunshine",
  "wordlist_line": 4207
}
```

That makes a findings file a credential file. Treat it like one.

A wrong CAPTCHA solve is not a failed login and does not consume the lockout
budget.

### Pick a solver, then run the wordlist

This is the sequence that matters. A brute-force run costs one CAPTCHA solve
per attempt, so the solve rate decides whether a wordlist is runnable at all:
at 15% you pay about 7 requests per password, at 60% under 2.

**1. Try each solver against the live target.** No corpus, no labelling - the
application itself says whether a solve was right, so no ground truth is
needed. Eight samples each, about thirty seconds a run, no credential attempts:

```bash
capat audit -p app.json -M solve-rate -n 8 -s ddddocr
capat audit -p app.json -M solve-rate -n 8 -s ensemble-fast -l 5
capat audit -p app.json -M solve-rate -n 8 -s ddddocr -l 5 --min-saturation 60 --dilate 3
```

Each prints one line you can compare directly:

```
CAPTCHA solved automatically in 25% of attempts     <- ddddocr, defaults
CAPTCHA solved automatically in 50% of attempts     <- ensemble-fast --length 5
CAPTCHA solved automatically in 75% of attempts     <- ddddocr + preprocessing
```

Eight samples tells 25% from 75%; it is not a number to quote. Re-run the
winner with `-n 25`.

**2. Save the winning recipe into the profile** with `-P app.json`. It lands
under `"solver"` and every later run picks it up:

```json
"solver": { "name": "ddddocr", "length": 5, "min_saturation": 60, "dilate": 3 }
```

**3. Run the wordlists.** No solver flags needed - the profile has them:

```bash
capat audit -p app.json -M credential \
  -w passwords.txt -U users.txt \
  --order spray --lockout-threshold 3 --captcha-retries 5 -r 1
```

- `-w` password list - **giving it is what enables the credential test**
- `-U` username list, or `--username alice` for a single account
- `--order spray` tries every identity per password, so no one account takes
  consecutive failures; `brute` exhausts one identity first
- `--lockout-threshold 3` stops that account after 3 *credential* failures - a
  misread CAPTCHA never counts against it
- `--captcha-retries 5` retries a password whose CAPTCHA was misread, so a bad
  solve cannot silently skip a wordlist entry

A hit is reported in full, because a finding that will not say which password
worked cannot be acted on:

```
| critical | credential-audit | valid credentials found: alice:sunshine |
```

and the summary states what the run actually covered:

```
22 automated attempts across 1 identity, in 1m 47s (4.9s each). The CAPTCHA was
solved on 3 of 22 (13.6%), and those reached credential evaluation; 19 were
rejected at the CAPTCHA. WARNING: 2 password(s) were never tested ...
```

**Instead of step 1, build a corpus once.** Slower to set up, but it touches
the target once and then never again, and every config is compared on identical
images rather than a fresh sample - which is what makes it the number to put in
a report:

```bash
capat collect -c https://app.example.com/api/captcha -n 25 -o corpus
# rename each file to the answer it shows: A8R36.png
capat bench corpus -s ddddocr -l 5
capat bench corpus -s ensemble-fast -l 5 --min-saturation 60
```

**See every request while you tune** with `-d`:

```
[*] captcha https://app.example.com/api/captcha -> 200, 9456 bytes
[!] login   user=demo pass=letmein captcha=22zs -> 401 captcha_failure
[!] captcha misread, retrying 'letmein' (2 left)
[-] login   user=demo pass=letmein captcha=Gchqr -> 401 auth_failure
[+] login   user=demo pass=sunshine captcha=T1SPG -> 200 success
```

`[+]` got in - `[-]` reached the credential check - `[!]` never passed the
CAPTCHA - `[?]` unclassifiable, or the target started rate limiting.

A run stops when the target rate-limits it, rather than measuring the limiter,
and reports where the limit began. That threshold is worth as much as the solve
rate: it is the control that actually bounds automated guessing, so a target
that has one is credited with it.

## Options

| Flag | Meaning |
|---|---|
| `-u URL` / `-c URL` | Login URL and CAPTCHA endpoint. `-c` is discovered if omitted |
| `--captcha-fail` / `--auth-fail` / `--success` | How the app answers. Substring, or `re:`, `status:`, `url:`, `json:`, `header:` |
| `-H 'Name: v'` / `-F name=v` / `-X` | Headers, extra form fields, method |
| `--encoding` / `--extract` / `--csrf-field` | Fit the request to the app from the CLI |
| `--profile FILE` | Same description as a file; any flag above overrides it |
| `--save-profile FILE` | Write the assembled profile out for reuse |
| `collect --count N --output DIR` | Fetch unlabelled CAPTCHAs for a corpus |
| `--samples N` | CAPTCHAs to measure (default 25) |
| `--rps` / `--threads` | Rate and parallelism (default 2/s, 5) — low on purpose |
| `--solver` | `ddddocr`, `easyocr`, `tesseract`, `ensemble`, or a plugin |
| `--charset` / `--length` | Known shape of the code; both improve accuracy |
| `encoding`, `headers`, `extract`, `body_template` (profile) | Fit the request to the app |
| `captcha_response` (profile) | `image` (default) or `json` for a base64+id API |
| `--scale` / `--threshold` / `--median` / `--invert` | Preprocessing knobs |
| `--min-saturation` | Drop grey noise lines, keep coloured glyphs |
| `--dilate` | Thicken strokes thinned by thresholding |
| `--format` | `table`, `json`, or `markdown` |
| `--output FILE` | Write the report to a file |
| `--proxy` | Route through Burp/ZAP |
| `--skip-solve-rate` | Enforcement checks only, no OCR |
| `-w, --passwords WORDLIST` | Enable the end-to-end test (off by default) |
| `--users WORDLIST` | Username list for the audit (default: the profile username) |
| `--order` | `spray` (default, safest) or `brute` |
| `--ignore-lockout` | Disable lockout protection. Can lock out a real account. |
| `--debug` | One line per request: values sent, status, classification, body |
| `--only` | `gate`, `solve-rate`, `credential` — run just these checks |
| `--captcha-retries` | Retries for a misread CAPTCHA so no password is skipped (default 3) |

## What actually stops this

Not "buy a harder CAPTCHA". Harder distortion costs real users more than it
costs a model - that trade has been losing for a decade. Stop treating the
challenge as the control:

- Rate-limit and lock out **per account and per source**, with exponential
  backoff on repeated failures.
- Base the bot decision on signals a client cannot replay, evaluated
  server-side.
- Require a second factor for anything worth guessing a password for.
- If a challenge is still wanted, prefer an attested or privacy-preserving one
  over distorted text.

## Extending it

Both extension points are entry points, so you can ship your own without
forking:

```toml
[project.entry-points."capat.solvers"]
trocr = "capat_trocr:TrOCRSolver"

[project.entry-points."capat.modules"]
audio = "capat_audio:AudioChallenge"
```

A solver implements one method:

```python
from capat.solvers.base import Fragment, Solver


class MySolver(Solver):
    name = "mine"

    def recognize(self, image: bytes) -> list[Fragment]:
        # return raw fragments; the base class handles preprocessing,
        # left-to-right ordering, charset filtering, and timing
        return [Fragment(text="A8R36", confidence=0.9, x_center=0.0)]
```

Open an issue before a large change, so the approach can be agreed first.

## Development

```bash
git clone https://github.com/goblensec/capat && cd capat
pip install -e ".[dev]"
pytest -q
ruff check . && mypy src
```

No test touches the network or loads a real OCR model.

## Disclaimer

Provided "as is", no warranty, no liability for misuse.

Breaking into systems you do not own is a crime in most of the world. Pointing
this at one is the same act with extra steps. Your own targets, or ones you
have permission to hit - nothing else.

## License

MIT — see [LICENSE](../LICENSE).
