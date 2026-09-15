# That CAPTCHA Is Not a Bot Control. Here Is How to Prove It in a Report.

*Every number below came out of a real run on 2026-09-14, against
`examples/demo_app.py` and the 30 labelled images in `examples/corpus`. Every
command is in here, so you can re-run the lot and see what you get instead of
taking my word for it. I'm just a guy with a terminal.*

---

I keep finding the same thing on client login pages. There's an image CAPTCHA
sitting in front of the password field, looking busy, doing absolutely nothing.

Not "not much". Nothing. Either a model reads it faster than you can blink, or
the app never checks the answer in the first place. Both are everywhere. What's
rare is a tester who actually checked which one it was before writing it up -
or, more often, before quietly skipping the login page because there was a
CAPTCHA on it.

That's the real damage. The CAPTCHA isn't stopping attackers, it's stopping
*us*. It sits there looking like an obstacle, the credential and lockout testing
gets marked N/A, and the client ends up with a report saying the login page is
fine because nobody tried.

Which is a hell of a control. The one group it reliably holds up is the group
working from a signed scope and a deadline.

So I wrote a thing that checks. It's out today.

## Why these stopped working

The squiggly-letters CAPTCHA was invented back when software genuinely couldn't
read squiggly letters, which was a completely reasonable assumption at the time
and has not been true for years. A text-recognition model about 10 MB big, free,
downloads in a few seconds and reads distorted text on a normal laptop CPU. You
don't train it. You don't need a GPU. There's no API key and nobody to pay.

On my 30-image corpus, the stock engine got **11 of them exactly right (36.7%)**
and **84.1% of the characters**, with zero tuning, at **20 ms an image**. That's
roughly **82,000 tries an hour** out of one process on a laptop.

Now, 36.7% sounds low, and that's the trap - it's the number you'll get handed
back in the readout call. It means an attacker burns 2.7 attempts per password
guess. That's the "cost" the CAPTCHA is imposing. Two point seven. On a control
that was sold as making automation impossible.

And 2.7 is the *attacker's* cost. Yours is worse. Sit there hand-typing squiggles
into a browser to test a login and you are the only participant in this paying
full price for the thing.

And that's the *lazy* number - first command, no tuning, straight out of the box.
The number that belongs in the finding is what someone gets after poking at it
for an afternoon, which is the rabbit hole further down.

If a stock model does struggle on the CAPTCHA in front of you, the move is to
train one on that exact CAPTCHA. That's not some elite thing. That's a weekend,
and a weekend is well inside what a real adversary will spend. You will never be
given that weekend on an engagement, which is the whole point and belongs in the
finding rather than in a footnote: the gap between what you had time to do and
what they have time to do is not evidence the control works.

## Three questions, and only one is about OCR

A CAPTCHA either costs an attacker something or it doesn't. Three things decide
that, and all three fit in an engagement window:

**1. Can a machine read it?**
The solve rate. At 70% an attacker spends 1.4 tries per guess, which rounds to
"no obstacle" on any throughput that matters - and it means the CAPTCHA isn't in
your way either, so the rest of your login testing can go ahead.

**2. Is anyone even checking the answer?**
This is the one that writes itself into a CRITICAL. Loads of apps only validate
the CAPTCHA if the browser bothers to send it. Drop the field entirely and you
walk straight in. Send it empty and it happily matches the empty thing sitting on
the server. Send yesterday's correct answer and it gets accepted again, and
again, and again. None of this needs OCR or a model or any of the clever stuff.
It needs curl.

**3. So what *is* protecting this page?**
Usually rate limiting. Not the CAPTCHA. Worth knowing before you let "but there's
a CAPTCHA" knock a severity down, and before the answer to your brute-force
finding comes back as "we'll buy a harder CAPTCHA".

## The tool

`capat` - CAPtcha ATtacking Tool. Point it at a login page you are authorised to
test, and it answers all three.

```bash
pip install "capat[ddddocr]"
```

![A full capat audit finding three enforcement failures and a solve rate](img/audit.png)
*One run against a deliberately broken demo app: three enforcement failures,
then the rate.*

Those two quoted phrases in the command are doing all the work. You're teaching
it to tell *wrong CAPTCHA* apart from *wrong password*. Without that it can't
tell a misread image from a rejected login, and every number after that point is
vibes - which is exactly the kind of number that falls apart the moment a client
engineer re-runs it.

## Enforcement first - no model required

Before you ask whether a machine can read the image, ask whether the image
matters at all. Three things, no recognition needed, nothing to install:

- send the login with the CAPTCHA field **missing**
- send it **empty**
- send an answer that **already worked once**

![The three enforcement findings with a fix line under each](img/enforcement.png)
*The enforcement findings, with the reasoning and the fix printed under each
one.*

If any of those get through, stop. Don't measure the solve rate, don't tune
anything. The image is wallpaper, the finding is "the CAPTCHA is not enforced",
and the remediation is about one line in the login handler. That's a better
finding than any solve rate, it takes five minutes, and it survives being argued
with, because you can reproduce it live with curl in front of the dev who wrote
it.

It also unblocks the rest of your login testing, which is usually the actual
point.

## Then the solve rate

![The solve-rate check reporting 16 of 25 challenges solved](img/solve-rate.png)
*16 of 25 sampled challenges. 64%.*

Now hold on. The first screenshot in this post said 92% against the *same app*,
and I'm not going to quietly pretend you didn't notice.

That run sampled 12 challenges, this one sampled 25. The demo mints a fresh
answer and a fresh distortion every single request, so nothing about the target
changed. 11-of-12 and 16-of-25 just aren't a real difference - Fisher's exact
puts them at p = 0.12, and the 95% intervals (65-98% and 45-80%) overlap almost
completely. Pool them and the honest answer is **27 of 37, 73%, interval
57-85%**.

Which is why `-n` exists. A percentage out of twelve attempts is a headline, not
a measurement. If it's going in a report, sample until the interval is tight
enough to act on, and put the interval next to the number. I've handed over the
bare percentage before, and the one thing you do not want is the client's
security engineer re-running your test and getting a different figure.

This bit does submit real logins, so it's deliberately boring about safety: made
up username, fresh random password every attempt. It can't lock out a real
account and it can't accidentally log in as someone - which matters when the
account you'd have locked belongs to the client's CFO and it's 4pm on a Friday.
Real passwords only get tried if you hand it a wordlist yourself.

Notice what all that careful behaviour does to the number, though. We're the ones
running a made-up username at an agreed request rate, watching the clock because
of somebody's lockout policy. Whoever this control was bought to stop has none of
that. So every figure in this post is a floor, and it's worth saying so out loud
in the report - "73% under testing constraints the attacker does not have" is a
sentence nobody can argue down to "so it mostly works".

## When something actually works, say so

Most scanners only ever tell you what's broken, which makes them exhausting to
read and easy to dismiss, and it also means the one control that's genuinely
holding the line goes unmentioned. Your report is better when it names what
worked. So when the app starts refusing requests, capat stops and reports where
the wall was, as a finding in its own right.

![capat stopping on HTTP 429 and reporting the rate limit as a finding](img/rate-limited.png)
*A target that defends itself, and gets credit for it. The 30-second wait isn't
invented - that's the target's own `Retry-After` header. No header, no sentence;
it doesn't make one up on your behalf.*

Stopping there is also the polite thing to do to somebody else's production
login endpoint.

## The part that took longest and nobody will notice

The classic failure mode for a tool like this is claiming more than the run
showed. I've spent more time on that than on the solving, honestly - because
every one of those claims ends up in a document with your name on it.

- An **unrecognised response is not a missing control.** If the app answers in
  wording the tool doesn't know, that's an inconclusive INFO. Not a CRITICAL.
  Defending a CRITICAL that turns out to be a parsing failure costs you the rest
  of the report.
- A **zero solve rate measures my engine, not the target's CAPTCHA.** It says so,
  and points at your solver settings instead of letting you write "CAPTCHA
  effective" off the back of your own bad flags.
- A **check that couldn't run is not a clean result.** If the replay test never
  managed to solve a challenge to replay, it says "couldn't test this". It does
  not say "no findings".
- A **password whose CAPTCHA got misread has not been tested.** It's retried, and
  anything still untested gets counted and named - so "we tried the top 100" is
  a sentence you can stand behind.

A tool that quietly says "all good" about a test it never ran is worse than no
tool, because now you've signed off on it. All four of those are pinned by tests
so they can't quietly come back.

## Bring your own model

The engines swap out, and the interesting case is a model trained on the exact
CAPTCHA in front of you - which, again, is what a motivated attacker has, and
therefore what the finding should assume.

```bash
capat bench examples/corpus -s ddddocr
capat bench examples/corpus -s easyocr -l 5
```

![ddddocr scoring 11 of 30 on the labelled corpus](img/bench-ddddocr.png)
![easyocr scoring 5 of 30 on the same corpus](img/bench-easyocr.png)
*Same 30 images, two engines: ddddocr 36.7% exact and 84.1% character similarity
at 0.02s an image; easyocr 16.7% and 68.1%. The table only lists the misses,
which is why every row on screen is wrong - `--show-all` gives you the rest.*

## The rabbit hole: finding the recipe

Every image gets cleaned up before the engine ever sees it, and on a nasty
CAPTCHA that cleanup matters more than which engine you picked. There is no
magic default, because the right recipe is a property of *this* image. You can't
look it up. You have to go look at the thing.

It's the same loop as everything else in this job, so you already know how to run
it: look at the thing properly, guess, poke it, then read what fell out instead of
just reading the score.

![One corpus image: coloured glyphs over thin grey wavy lines](img/captcha-sample.png)

So open one up and ask what actually separates the letters from the junk:

- **What's ink and what's noise?** Here: five coloured glyphs, thin grey wavy
  lines scribbled over them, white background.
- **What one property tells them apart?** Not brightness - the lines and the
  letters are about equally dark, so a brightness threshold just trades one for
  the other. Colour does it: the letters are saturated, the lines are grey.
  That's what `--min-saturation` is for, and on this corpus it's *the* knob.

  Worth a detour, because this is the bit I actually enjoyed: it converts to HSV
  and keeps pixels whose S channel is above your number, *before* anything gets
  turned grey. Order matters. Once you've flattened to greyscale the colour is
  gone and a grey noise line and a red letter stroke are the same pixel value -
  no threshold on earth separates them after that. Filter on colour while you
  still have colour.
- **How thick is the noise vs a stroke?** One pixel against several, so a small
  median filter wipes the lines and leaves the letters. Crank the kernel and it
  starts eating letters too.
- **How big is the image?** 170x54, which is tiny. Thresholding thins strokes and
  sometimes snaps them, so upscale first - `--scale` defaults to 3 for exactly
  that reason.

Here's where I went wrong, which is the useful bit. I'd worked out that
saturation was the thing that mattered, so I cranked it - high `--min-saturation`,
high threshold, be aggressive, throw away everything that isn't obviously a
letter. Sounds right. It was exactly backwards, and it took me three runs to
admit it.

Three runs, same 30 images, same engine.

![easyocr at 0% with short, truncated predictions](img/tuning-1-too-strict.png)
*`--min-saturation 100 --threshold 200 --median 2`: 0 of 30, character
similarity 52.1%.*

Zero percent. Which looks like a dead end, and I nearly binned the whole recipe
on the strength of it. On an engagement this is the exact moment someone writes
"the CAPTCHA resisted automated solving" and moves on, and they'd be wrong.

Look at the `predicted` column instead of the headline. `23BET` came back as
`288`. `445YP` as `5`. `8JAAX` as `8s14Z`. Everything's *too short*. Short means
characters are being **erased**, not misread. Something in my recipe is deleting
ink before the engine even gets a look at it.

Two suspects: `--min-saturation 100` is chucking away every glyph that isn't
vividly coloured, and `--threshold 200` is turning anything lighter than that
into background.

![easyocr at 0% with mostly blank predictions and 0.00 confidence](img/tuning-2-erased.png)
*Same recipe, `--min-saturation 200`: 0 of 30, character similarity 9.2%.*

So I shoved the suspect knob further the *wrong* way on purpose, just to be sure
I'd understood it. 100 to 200. Most rows come back completely empty at
`conf 0.00`, which is easyocr politely telling me there is nothing in the image.
I had very successfully deleted the CAPTCHA.

And this is the most useful run of the three, despite being comfortably the
worst. Both runs scored exactly 0%, so the headline number couldn't tell them
apart at all - but character similarity fell 52.1% → 9.2%. **When accuracy is
pinned at zero, steer by the similarity figure.** It still moves. It's the only
compass you've got down there.

![easyocr at 20% with full-length near-miss predictions](img/tuning-3-best.png)
*`--min-saturation 20 --threshold 240 --median 2`: 6 of 30 = 20.0%, character
similarity 76.6%, ~6,950 solves an hour.*

So: reverse. Only throw out the properly grey pixels, and raise the threshold so
faint ink survives instead of getting flattened. (Two knobs at once, which breaks
my own rule below - both suspects pointed the same way, so treat this run as
confirming the diagnosis, not as proof of which knob earned the points.)

The number went up, fine. But the *far* more interesting thing is that **the
failure changed shape**. `23BET` is now `23011`. `39V9P` is `389V9P`. `CF5M7` is
`CF5My`. Full length now, and wrong in a completely different way - these are
letter-for-letter mix-ups, not gaps.

Nothing's being erased any more. The engine is just confusing characters. That's
a completely different problem, and telling those two apart is basically the
whole skill:

- **Ink is being erased** - short or blank predictions, low confidence. That's
  yours to fix. Keep tuning.
- **Characters are being confused** - full length, decent confidence, wrong
  letters. That is *not* a flags problem. More filtering buys you a point at a
  time while you burn an afternoon somebody is paying for. What buys the rest is
  a different engine, or a model trained on this exact font.

Three rules to stop yourself lying to yourself, and by extension to the client:

1. **One knob per run.** The banner prints the recipe it measured with, so every
   screenshot up there is reproducible from the picture alone - which is what you
   want in an appendix. That was a bug I fixed for this exact reason: two runs
   once printed identical banners and different accuracies, which is the tool
   gaslighting you.
2. **30 images is a small corpus.** 5-of-30 vs 6-of-30 is *one image*, not a
   discovery. Move when several images move, or go grow the corpus with
   `capat collect`.
3. **Do all of this offline first.** A labelled corpus costs zero requests, runs
   the same every time, and can't lock anybody out of anything. Tune against
   saved images, then spend your request budget on the live target - not on
   testing your own guesses against somebody's production login.

And keep it in proportion: everything above is the *weaker* engine getting
dragged from 16.7% to 20% by a few minutes of guessing. ddddocr read the same
corpus at 36.7% cold, in a fifth of the time. An attacker starts where I
finished, and nobody is billing that afternoon. That's why the number that belongs
in the report is never the one from your first run.

A custom network is a file path, not a plugin: `-s model.onnx`, charset sidecar
next to it. I'm working on a companion project for training one.

## If you don't fancy learning twenty flags at 9am on day one

```bash
capat setup
```

It asks you for the URLs, the field names and the two phrases, writes a profile,
shows you the command it built, and runs it. The profile is a file, so the next
tester on that app - or you, at the retest - gets the same run for free.

![capat setup asking for the login URL, the CAPTCHA URL and the field names](img/setup.png)
*The wizard, asking for what it needs.*

## Grab it

```bash
pip install "capat[ddddocr]"
capat audit -u https://target/login -cf "invalid captcha" -af "invalid username or password"
```

Source, full guide, every flag: **https://github.com/goblensec/capat**

MIT. Issues and PRs welcome.

## One serious note, and I do mean serious

capat sends real login attempts at a live application. It belongs inside a scope
document. Get the authorisation in writing, check the host is actually in scope
before you paste it into `-u`, agree the request rate, and find out whether the
client's lockout policy is going to burn accounts - `--lockout-threshold` exists
for that conversation. There is no allowlist in the tool doing any of this for
you: it takes a URL and runs, exactly like everything else on your box.

Outside that, this is probably a crime where you live, and the defaults will not
save you.

---

*If you run it on an engagement, tell me the number you got. That's the entire
point of the thing.*
