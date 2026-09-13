"""The start-of-run banner states what the run is about to do.

Most of this tool's flags describe the *target*, not the tool, and a wrong one
produces a confident number about something that was never measured. The
configuration block is what lets an operator catch that before the requests go
out, so the rows that carry a warning - a missing matcher, real credentials,
disabled TLS - have to be present and have to be readable.
"""

from __future__ import annotations

from capat.core.config import DEFAULT_USER_AGENT, Config
from capat.core.matching import Matcher, SuccessCriteria
from capat.core.profile import LoginProfile, SolverSettings
from capat.reporting import banner


def profile(**kwargs: object) -> LoginProfile:
    base: dict[str, object] = {
        "login_url": "https://app.example.test/login",
        "captcha_url": "https://app.example.test/captcha.png",
        "criteria": SuccessCriteria(
            captcha_failure=["invalid captcha"],
            auth_failure=["invalid username or password"],
        ),
    }
    base.update(kwargs)
    return LoginProfile(**base)  # type: ignore[arg-type]


def rows_as_dict(rows: list[tuple[str, str]]) -> dict[str, str]:
    return dict(rows)


def test_a_matcher_renders_in_the_syntax_it_was_typed_in() -> None:
    """A config line should be copy-pasteable back onto the command line. If it
    printed the dataclass instead, reproducing a run would mean translating."""
    matcher = Matcher(
        body=["invalid captcha"],
        regex=["captcha.{0,20}expired"],
        status=[422],
        json={"code": 4001},
        header={"location": "/home"},
        url=["/dashboard"],
    )
    line = banner.describe_matcher(matcher)
    assert '"invalid captcha"' in line
    assert "re:captcha.{0,20}expired" in line
    assert "status:422" in line
    assert "json:code=4001" in line
    assert "header:location=/home" in line
    assert "url:/dashboard" in line


def test_a_missing_matcher_says_so_rather_than_rendering_empty() -> None:
    """An unset auth-failure matcher means the solve rate cannot be measured.
    Showing a blank would hide the one thing worth catching before the run."""
    rows = rows_as_dict(
        banner.audit_rows(
            profile(criteria=SuccessCriteria(captcha_failure=["nope"])),
            Config(),
            ["gate"],
        )
    )
    assert rows["Auth fail"] == banner.NOT_SET
    assert rows["CAPTCHA fail"] == '"nope"'


def test_a_credential_run_announces_that_it_submits_real_logins() -> None:
    """The one row that has to be impossible to miss: everything else measures,
    this one authenticates."""
    rows = rows_as_dict(
        banner.audit_rows(
            profile(username="alice"),
            Config(lockout_threshold=3),
            ["credential"],
            wordlist="rockyou.txt",
            order="brute",
        )
    )
    assert "SUBMITS REAL LOGINS" in rows["Credentials"]
    assert "brute" in rows["Credentials"]
    assert "lockout at 3" in rows["Credentials"]
    assert rows["Passwords"] == "rockyou.txt"


def test_disabled_lockout_protection_is_called_out_in_the_same_row() -> None:
    """--ignore-lockout can lock a real account out of a live application."""
    rows = rows_as_dict(
        banner.audit_rows(
            profile(),
            Config(ignore_lockout=True),
            ["credential"],
            wordlist="pw.txt",
        )
    )
    assert "LOCKOUT PROTECTION OFF" in rows["Credentials"]


def test_the_keyword_captcha_urls_are_explained_not_echoed() -> None:
    """'auto' and 'base64' are modes, not URLs; printing the bare word would
    read like a target that could not be resolved."""
    auto = rows_as_dict(banner.audit_rows(profile(captcha_url="auto"), Config(), ["gate"]))
    assert "re-read from every login page" in auto["CAPTCHA URL"]

    inline = rows_as_dict(banner.audit_rows(profile(captcha_url="base64"), Config(), ["gate"]))
    assert "read inline from the login page" in inline["CAPTCHA URL"]


def test_rows_that_only_restate_a_default_are_left_out() -> None:
    """The block is meant to be read at a glance, so a row earns its place by
    being something the operator chose or needs to check."""
    rows = rows_as_dict(banner.audit_rows(profile(), Config(), ["gate"]))
    assert "Proxy" not in rows
    assert "TLS" not in rows
    assert "User-Agent" not in rows
    assert "Report" not in rows
    # ...and a solve-rate sample count is meaningless when solve-rate is off.
    assert "Samples" not in rows


def test_overridden_defaults_do_appear() -> None:
    rows = rows_as_dict(
        banner.audit_rows(
            profile(),
            Config(proxy="http://127.0.0.1:8080", verify_tls=False, user_agent="Mozilla/5.0"),
            ["gate", "solve-rate"],
            output="run.json",
            fmt="json",
        )
    )
    assert rows["Proxy"] == "http://127.0.0.1:8080"
    assert "DISABLED" in rows["TLS"]
    assert rows["User-Agent"] == "Mozilla/5.0"
    assert rows["Report"] == "run.json (json)"
    assert rows["Samples"] == str(Config().samples)


def test_the_honest_default_user_agent_is_not_worth_a_row() -> None:
    rows = rows_as_dict(
        banner.audit_rows(profile(), Config(user_agent=DEFAULT_USER_AGENT), ["gate"])
    )
    assert "User-Agent" not in rows


def test_a_long_charset_is_truncated_so_the_block_stays_readable() -> None:
    tuning = SolverSettings(charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij", length=5)
    rows = rows_as_dict(banner.audit_rows(profile(solver=tuning), Config(), ["gate"]))
    assert "..." in rows["Solver"]
    assert len(rows["Solver"]) < 60


def test_keys_are_padded_into_one_column() -> None:
    """Alignment is the whole reason this reads as a block rather than a list."""
    out = banner.render_config([("A", "1"), ("Longer key", "2")])
    first, second = out.split("\n")
    assert first.index(" : ") == second.index(" : ")


def test_render_without_rows_drops_the_configuration_section() -> None:
    """`capat setup` prints the banner before it has asked anything, so there
    is no configuration yet - an empty block would just be two rules."""
    out = banner.render("9.9.9")
    assert "v9.9.9" in out
    assert "::" not in out
    assert out.count(banner.RULE) == 1


def test_render_with_rows_fences_the_configuration_between_two_rules() -> None:
    out = banner.render("9.9.9", [("Login URL", "https://x.test")])
    assert out.count(banner.RULE) == 2
    assert " :: Login URL : https://x.test" in out


def test_bench_shows_no_network_rows() -> None:
    """bench is offline. A rate or proxy row would imply otherwise."""
    rows = rows_as_dict(
        banner.bench_rows("corpus", 12, SolverSettings(name="ddddocr"), case_sensitive=False)
    )
    assert rows["Corpus"] == "corpus"
    assert rows["Images"] == "12"
    assert rows["Compare"] == "case-insensitive"
    assert "Rate" not in rows
    assert "Proxy" not in rows


def test_collect_shows_where_the_images_come_from() -> None:
    rows = rows_as_dict(banner.collect_rows(profile(), Config(), 25, "corpus"))
    assert rows["CAPTCHA URL"] == "https://app.example.test/captcha.png"
    assert rows["Images"] == "25"
    # collect never submits a login, so it has no matchers to show.
    assert "CAPTCHA fail" not in rows
    assert "Credentials" not in rows


def test_collect_names_the_page_when_there_is_no_endpoint() -> None:
    rows = rows_as_dict(banner.collect_rows(profile(captcha_url="auto"), Config(), 5, "corpus"))
    assert "the login page at" in rows["Source"]
    assert "CAPTCHA URL" not in rows


def test_solve_shows_the_preprocessing_recipe_in_force() -> None:
    """solve is how a recipe gets tuned, so the recipe belongs on screen next
    to the answer it produced."""
    rows = rows_as_dict(
        banner.solve_rows(
            "a.png", SolverSettings(scale=2.0, threshold=99, median=5), save_processed="out.png"
        )
    )
    assert rows["Image"] == "a.png"
    assert rows["Preprocess"] == "scale 2, threshold 99, median 5"
    assert rows["Processed"] == "out.png"


def test_the_banner_names_its_author_under_the_version() -> None:
    """The author line is what a reader of a screenshot uses to find the
    project. Without this the line could be dropped in a refactor and nobody
    would notice until the next screenshot was taken."""
    block = banner.render("0.1.0")
    lines = [line for line in block.split("\n") if line.strip()]
    version_at = next(i for i, line in enumerate(lines) if line.strip() == "v0.1.0")
    assert lines[version_at + 1].strip() == f"by {banner.AUTHOR}"
