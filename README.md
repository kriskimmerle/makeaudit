# makeaudit

**Makefile linter & security checker.** Catches tab/space errors, missing `.PHONY`, shell injection, sudo usage, hardcoded secrets, bashisms, recursive make, and more.

Zero dependencies. Stdlib only. Single file.

## Why?

Makefiles are everywhere — but no Python linter exists for them. checkmake (Go) checks ~3 things. makeaudit checks 17.

Common Makefile problems that waste hours of debugging:

- **Spaces instead of tabs** — `make: *** missing separator. Stop.`
- **Missing `.PHONY`** — `make: 'test' is up to date.` (when a `test/` dir exists)
- **`curl | bash` in recipes** — supply chain attacks in your build
- **`sudo` in install targets** — builds should never require root
- **Bashisms without `SHELL := /bin/bash`** — `[[`, `source`, `pushd` silently break on `/bin/sh`
- **Hardcoded secrets** — API keys committed in Makefiles
- **Duplicate targets** — last one wins, confusing behavior

## Install

```bash
curl -o makeaudit.py https://raw.githubusercontent.com/kriskimmerle/makeaudit/main/makeaudit.py
```

No `pip install`. No dependencies. Just Python 3.8+.

## Usage

```bash
# Lint a Makefile (auto-detects if no file specified)
makeaudit Makefile

# Verbose output with fix suggestions
makeaudit --verbose Makefile

# JSON output for automation
makeaudit --format json Makefile

# CI mode — exit 1 if any errors
makeaudit --check Makefile

# CI mode — exit 1 if grade below B
makeaudit Makefile --check B

# Filter by severity
makeaudit --severity warning Makefile

# Ignore specific rules
makeaudit --ignore MA005,MA016 Makefile

# Lint multiple files
makeaudit Makefile *.mk

# List all rules
makeaudit --list-rules
```

## What It Checks

### 🔴 Errors (Must Fix)

| Rule | Name | Description |
|------|------|-------------|
| MA001 | Spaces Instead of Tab | Recipe line uses spaces instead of required tab |
| MA002 | Shell Injection Risk | `curl \| bash`, `eval`, `rm -rf /`, `chmod 777` in recipes |
| MA003 | Sudo in Recipe | Build scripts should not require elevated privileges |
| MA004 | Secrets in Makefile | Hardcoded API keys, tokens, passwords (8+ patterns) |

### 🟡 Warnings (Should Fix)

| Rule | Name | Description |
|------|------|-------------|
| MA005 | Missing .PHONY | Target like `test` or `clean` without `.PHONY` declaration |
| MA006 | Duplicate Target | Same target defined twice — last wins, confusing |
| MA007 | Recursive Make | `$(MAKE) -C` — "Recursive Make Considered Harmful" |
| MA008 | Hardcoded Absolute Path | `/Users/dev/src/...` — reduces portability |
| MA009 | Undefined Variable | `$(FOO)` referenced but never assigned |
| MA010 | Large Recipe | 20+ line recipe — extract to a script |
| MA011 | Missing Error Handling | Semicolon chains without error checking |
| MA012 | Bashism in Recipe | `[[`, `source`, `pushd`, `echo -n` without `SHELL := /bin/bash` |

### ℹ️ Info (Nice to Fix)

| Rule | Name | Description |
|------|------|-------------|
| MA013 | Missing Default Target | No `all` target — first target becomes default |
| MA014 | Missing Clean Target | No `clean` target |
| MA015 | Deprecated Syntax | Old-style suffix rules |
| MA016 | Long Line | Line exceeds 120 characters |
| MA017 | TODO/FIXME | Unresolved TODO comments |

## Grading

| Grade | Score | Verdict |
|-------|-------|---------|
| A | 90-100 | Clean Makefile ✅ |
| B | 75-89 | Minor issues — review recommended 🔍 |
| C | 60-74 | Needs improvement ⚠️ |
| D | 40-59 | Significant issues detected 🚨 |
| F | 0-39 | Critical problems — fix before using 🛑 |

## Example Output

```
makeaudit v1.0.0 — Makefile Linter & Security Checker

File: Makefile
Targets: 12
Variables: 5
.PHONY targets: 3
Grade: D (45/100)
Verdict: Significant issues detected 🚨

🔴 ERRORS (3):
  🔴 Line 15 [MA001]: Recipe line uses spaces instead of tab
  🔴 Line 28 [MA002]: Dangerous command in 'deploy': curl piped to shell
  🔴 Line 32 [MA003]: sudo in recipe for 'install'

🟡 WARNINGS (4):
  🟡 Line 5 [MA005]: Target 'test' should be declared .PHONY
  🟡 Line 10 [MA005]: Target 'clean' should be declared .PHONY
  🟡 Line 40 [MA012]: Bashism in 'run': source — bash-only (use . for POSIX)
  🟡 Line 42 [MA012]: Bashism in 'run': [[ ]] — bash test syntax (use [ ] for POSIX)

Summary: 3 errors, 4 warnings, 0 info
```

## Bashism Detection

If `SHELL` is not set to bash, makeaudit flags bash-specific syntax:

| Pattern | Issue | POSIX Alternative |
|---------|-------|-------------------|
| `[[ ... ]]` | Bash-only test | `[ ... ]` |
| `<<<` | Here-string | `echo ... \|` |
| `${var//pat/rep}` | Pattern substitution | `sed` |
| `source file` | Bash-only include | `. file` |
| `echo -n` | Non-portable | `printf` |
| `pushd`/`popd` | Bash built-in | `cd` + subshell |
| `function name()` | Bash keyword | `name()` |
| `shopt` | Bash built-in | N/A |
| `select ... in` | Bash built-in | N/A |
| Arrays `arr=()` | Bash-only | N/A |

## CI Integration

```yaml
# GitHub Actions
- name: Lint Makefile
  run: |
    curl -sO https://raw.githubusercontent.com/kriskimmerle/makeaudit/main/makeaudit.py
    python3 makeaudit.py --check Makefile
```

## Why Not checkmake?

| Feature | checkmake | makeaudit |
|---------|-----------|-----------|
| Language | Go | Python (zero deps) |
| Rules | ~3 | 17 |
| .PHONY check | ✅ | ✅ (smarter — skips file-producing targets) |
| Tab/space check | ❌ | ✅ |
| Security checks | ❌ | ✅ (shell injection, sudo, secrets) |
| Bashism detection | ❌ | ✅ |
| Recursive make | ❌ | ✅ |
| Hardcoded paths | ❌ | ✅ |
| Grading system | ❌ | ✅ (A-F) |
| JSON output | ✅ | ✅ |
| CI mode | ❌ | ✅ |

## License

MIT
