#!/usr/bin/env python3
"""makeaudit - Makefile Linter & Security Checker

Lint Makefiles for correctness, security issues, and best practice violations.
Catches missing .PHONY, tab/space problems, shell injection, recursive make,
hardcoded paths, and more.

Zero dependencies. Stdlib only. Single file.

Usage:
    makeaudit Makefile                    # Lint a Makefile
    makeaudit --verbose Makefile          # Show fix suggestions
    makeaudit --format json Makefile      # JSON output
    makeaudit --check Makefile            # CI mode (exit 1 on errors)
    makeaudit --list-rules                # Show all rules
"""

__version__ = "1.0.0"

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def symbol(self) -> str:
        return {"error": "🔴", "warning": "🟡", "info": "ℹ️ "}[self.value]


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    line: int
    message: str
    detail: str = ""
    recommendation: str = ""
    matched: str = ""


# ── Rules ─────────────────────────────────────────────────────────────────────

RULES = {
    # Errors
    "MA001": ("Spaces Instead of Tab", Severity.ERROR,
              "Recipe line uses spaces instead of required tab indentation"),
    "MA002": ("Shell Injection Risk", Severity.ERROR,
              "Recipe contains curl|bash, wget|sh, eval, or other dangerous patterns"),
    "MA003": ("Sudo in Recipe", Severity.ERROR,
              "Recipe uses sudo — build scripts should not require elevated privileges"),
    "MA004": ("Secrets in Makefile", Severity.ERROR,
              "Hardcoded API keys, tokens, or passwords detected in variable assignments"),

    # Warnings
    "MA005": ("Missing .PHONY Declaration", Severity.WARNING,
              "Target that doesn't produce a file should be declared .PHONY"),
    "MA006": ("Duplicate Target", Severity.WARNING,
              "Same target defined multiple times — last definition wins, which is confusing"),
    "MA007": ("Recursive Make", Severity.WARNING,
              "Using $(MAKE) -C or submake — 'Recursive Make Considered Harmful'"),
    "MA008": ("Hardcoded Absolute Path", Severity.WARNING,
              "Absolute paths reduce portability across systems"),
    "MA009": ("Undefined Variable Reference", Severity.WARNING,
              "Variable referenced but never assigned in this Makefile"),
    "MA010": ("Large Recipe", Severity.WARNING,
              "Recipe has many lines — consider extracting to a shell script"),
    "MA011": ("Missing Error Handling", Severity.WARNING,
              "Recipe uses && chains or ; without set -e or error checking"),
    "MA012": ("Bashism in Recipe", Severity.WARNING,
              "Recipe uses bash-specific syntax but SHELL is not set to bash"),

    # Info
    "MA013": ("Missing Default Target", Severity.INFO,
              "No 'all' target defined — first target becomes default"),
    "MA014": ("Missing Clean Target", Severity.INFO,
              "No 'clean' target — users expect 'make clean' to work"),
    "MA015": ("Deprecated Syntax", Severity.INFO,
              "Uses deprecated make features or conventions"),
    "MA016": ("Long Line", Severity.INFO,
              "Line exceeds 120 characters — consider line continuation"),
    "MA017": ("TODO/FIXME in Makefile", Severity.INFO,
              "Unresolved TODO or FIXME comment found"),
}

# ── Patterns ──────────────────────────────────────────────────────────────────

# Common phony targets (don't produce files with these names)
COMMON_PHONY_TARGETS = {
    "all", "clean", "install", "uninstall", "test", "tests", "check", "lint",
    "build", "run", "deploy", "dist", "release", "help", "info", "version",
    "format", "fmt", "docs", "doc", "coverage", "bench", "benchmark",
    "dev", "serve", "start", "stop", "restart", "debug", "watch",
    "docker", "docker-build", "docker-run", "docker-push",
    "push", "pull", "publish", "init", "setup", "update", "upgrade",
    "verify", "validate", "audit", "scan", "fix", "ci", "cd",
    "pre-commit", "pre-push", "changelog", "tag", "bump",
    ".PHONY", ".DEFAULT", ".SUFFIXES", ".PRECIOUS", ".INTERMEDIATE",
    ".SECONDARY", ".DELETE_ON_ERROR", ".IGNORE", ".SILENT",
    ".EXPORT_ALL_VARIABLES", ".NOTPARALLEL", ".ONESHELL", ".POSIX",
}

# Dangerous command patterns in recipes
DANGEROUS_PATTERNS = [
    (r'curl\s+.*\|\s*(sh|bash|zsh)\b', "curl piped to shell"),
    (r'wget\s+.*\|\s*(sh|bash|zsh)\b', "wget piped to shell"),
    (r'curl\s+.*>\s*/tmp/.*&&\s*(sh|bash|chmod)', "curl to temp file and execute"),
    (r'\beval\s+', "eval — arbitrary code execution"),
    (r'\brm\s+(-[a-zA-Z]*)?.*\s+/\s', "rm with root path"),
    (r'\brm\s+-[a-zA-Z]*r[a-zA-Z]*f.*\s+/(?!\S)', "rm -rf /"),
    (r'chmod\s+777\s', "chmod 777 — world-writable"),
    (r'chmod\s+\+s\s', "setuid bit — privilege escalation"),
    (r'>\s*/dev/sd[a-z]', "write to block device"),
    (r'dd\s+.*of=/dev/', "dd to device"),
    (r'mkfs\b', "filesystem format"),
    (r':()\{\s*:\|:&\s*\};:', "fork bomb"),
    (r'python[23]?\s+-c\s+.*(?:__import__|exec|eval)\s*\(', "python code execution"),
    (r'node\s+-e\s+.*require.*child_process', "node child_process execution"),
]

# Secret patterns
SECRET_PATTERNS = [
    (r'(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD)\s*[:=]\s*["\']?[a-zA-Z0-9_/+=-]{16,}',
     "hardcoded secret in variable"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub token"),
    (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub fine-grained token"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'xoxb-[a-zA-Z0-9-]+', "Slack token"),
    (r'sk_live_[a-zA-Z0-9]{20,}', "Stripe key"),
    (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', "private key"),
]

# Bash-specific patterns (not POSIX)
BASHISMS = [
    (r'\[\[', "[[ ]] — bash test syntax (use [ ] for POSIX)"),
    (r'<<<', "<<< here-string (bash-only)"),
    (r'\$\{[^}]*//[^}]*\}', "${var//pat/rep} — bash pattern substitution"),
    (r'\$\{[^}]*:[0-9]+:[0-9]+\}', "${var:offset:length} — bash substring"),
    (r'\bfunction\s+\w+\s*\(\)', "function keyword (bash-only, use name() for POSIX)"),
    (r'\bselect\s+\w+\s+in\b', "select — bash built-in"),
    (r'\bshopt\b', "shopt — bash built-in"),
    (r'\bpushd\b|\bpopd\b', "pushd/popd — bash built-in"),
    (r'echo\s+-[neE]\b', "echo -n/-e — non-portable (use printf)"),
    (r'\bsource\s+', "source — bash-only (use . for POSIX)"),
    (r'\barray=\(', "arrays — bash-only"),
]


# ── Makefile Parser ──────────────────────────────────────────────────────────

@dataclass
class MakeTarget:
    name: str
    line: int
    prerequisites: List[str]
    recipe_lines: List[Tuple[int, str]]  # (line_number, content)
    is_pattern: bool = False


@dataclass
class MakeVariable:
    name: str
    line: int
    operator: str  # =, :=, ?=, +=, !=
    value: str


@dataclass
class ParsedMakefile:
    targets: List[MakeTarget]
    variables: List[MakeVariable]
    phony_targets: Set[str]
    includes: List[Tuple[int, str]]
    shell_setting: Optional[str]
    lines: List[str]
    conditionals: List[Tuple[int, str]]  # (line, type: ifdef/ifeq/etc)


def parse_makefile(filepath: str) -> ParsedMakefile:
    """Parse a Makefile into structured data."""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

    targets: List[MakeTarget] = []
    variables: List[MakeVariable] = []
    phony_targets: Set[str] = set()
    includes: List[Tuple[int, str]] = []
    shell_setting: Optional[str] = None
    conditionals: List[Tuple[int, str]] = []

    # Join continuation lines
    lines: List[str] = []
    line_map: List[int] = []  # maps joined line index -> original line number
    i = 0
    while i < len(raw_lines):
        line = raw_lines[i].rstrip("\n")
        orig_line = i + 1
        while line.endswith("\\") and i + 1 < len(raw_lines):
            i += 1
            line = line[:-1] + " " + raw_lines[i].rstrip("\n").lstrip()
        lines.append(line)
        line_map.append(orig_line)
        i += 1

    current_target: Optional[MakeTarget] = None

    for idx, line in enumerate(lines):
        lineno = line_map[idx]

        # Empty line or comment
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if current_target and not stripped:
                current_target = None  # blank line ends target context
            continue

        # Recipe line (starts with tab)
        if line.startswith("\t"):
            if current_target:
                current_target.recipe_lines.append((lineno, line[1:]))  # strip tab
            continue

        # Recipe with spaces (common error)
        if line.startswith("    ") and current_target and not any(
            line.lstrip().startswith(kw) for kw in
            ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif",
             "define", "endef", "include", "-include", "export",
             "unexport", "override", "vpath")
        ):
            # Looks like a recipe with spaces instead of tabs
            current_target.recipe_lines.append((lineno, line.lstrip()))
            continue

        # Conditionals
        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            conditionals.append((lineno, stripped.split()[0]))
            continue
        if stripped in ("else", "endif"):
            continue

        # Include
        inc_match = re.match(r'^-?include\s+(.+)', stripped)
        if inc_match:
            includes.append((lineno, inc_match.group(1).strip()))
            continue

        # Directive keywords
        if stripped.startswith(("define ", "endef", "export ", "unexport ",
                                "override ", "vpath ")):
            # Handle define blocks, exports, etc.
            if stripped.startswith("export "):
                var_match = re.match(
                    r'^export\s+(\w+)\s*([?:!+]?=)\s*(.*)', stripped)
                if var_match:
                    variables.append(MakeVariable(
                        name=var_match.group(1),
                        line=lineno,
                        operator=var_match.group(2),
                        value=var_match.group(3).strip(),
                    ))
            continue

        # Variable assignment
        var_match = re.match(r'^(\w[\w.-]*)\s*([?:!+]?=)\s*(.*)', stripped)
        if var_match:
            var_name = var_match.group(1)
            var_op = var_match.group(2)
            var_val = var_match.group(3).strip()
            variables.append(MakeVariable(
                name=var_name, line=lineno, operator=var_op, value=var_val
            ))

            # Track SHELL setting
            if var_name == "SHELL":
                shell_setting = var_val

            current_target = None
            continue

        # Target rule
        target_match = re.match(r'^([^:=]+?)\s*:\s*(.*)', stripped)
        if target_match and not re.match(r'^\s*\w+\s*[?:!+]?=', stripped):
            target_names_str = target_match.group(1).strip()
            prereqs_str = target_match.group(2).strip()

            # Handle .PHONY
            if target_names_str == ".PHONY":
                phony_names = prereqs_str.split()
                phony_targets.update(phony_names)
                current_target = None
                continue

            # Could be multiple targets
            target_names = target_names_str.split()
            prereqs = prereqs_str.split() if prereqs_str else []

            for tname in target_names:
                is_pattern = "%" in tname
                target = MakeTarget(
                    name=tname, line=lineno, prerequisites=prereqs,
                    recipe_lines=[], is_pattern=is_pattern,
                )
                targets.append(target)
                current_target = target

            continue

        # If we get here, it might be a continuation or something unexpected
        if current_target:
            current_target.recipe_lines.append((lineno, stripped))

    return ParsedMakefile(
        targets=targets,
        variables=variables,
        phony_targets=phony_targets,
        includes=includes,
        shell_setting=shell_setting,
        lines=raw_lines,
        conditionals=conditionals,
    )


# ── Checkers ──────────────────────────────────────────────────────────────────

def check_spaces_instead_of_tabs(parsed: ParsedMakefile, raw_lines: List[str]) -> List[Finding]:
    """MA001: Recipe lines must use tabs, not spaces."""
    findings = []
    in_recipe = False
    current_target_line = 0

    for i, line in enumerate(raw_lines):
        lineno = i + 1
        stripped = line.rstrip("\n")

        # Skip blank lines and comments
        if not stripped.strip() or stripped.strip().startswith("#"):
            if not stripped.strip():
                in_recipe = False
            continue

        # Target definition
        if (not stripped.startswith(("\t", " "))
                and re.match(r'^[^:=]+\s*:', stripped)
                and not re.match(r'^\s*\w+\s*[?:!+]?=', stripped)):
            in_recipe = True
            current_target_line = lineno
            continue

        # Variable assignment, directive — ends recipe context
        if re.match(r'^\w[\w.-]*\s*[?:!+]?=', stripped):
            in_recipe = False
            continue
        if stripped.lstrip().startswith(("ifeq", "ifneq", "ifdef", "ifndef",
                                         "else", "endif", "define", "endef",
                                         "include", "-include", "export",
                                         "override", ".PHONY")):
            in_recipe = False
            continue

        # Recipe line — should start with tab
        if in_recipe and stripped.startswith("    ") and not stripped.startswith("\t"):
            findings.append(Finding(
                rule_id="MA001",
                severity=Severity.ERROR,
                line=lineno,
                message="Recipe line uses spaces instead of tab",
                detail=f"Line {lineno}: '{stripped[:60]}'",
                recommendation="Replace leading spaces with a single tab character",
                matched=stripped[:80],
            ))

    return findings


def check_dangerous_commands(parsed: ParsedMakefile) -> List[Finding]:
    """MA002: Check for shell injection and dangerous commands in recipes."""
    findings = []
    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            for pattern, description in DANGEROUS_PATTERNS:
                if re.search(pattern, recipe, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="MA002",
                        severity=Severity.ERROR,
                        line=lineno,
                        message=f"Dangerous command in '{target.name}': {description}",
                        detail=f"Recipe: {recipe[:100]}",
                        recommendation="Remove dangerous commands or use safer alternatives",
                        matched=recipe[:120],
                    ))
                    break  # One finding per recipe line

    return findings


def check_sudo(parsed: ParsedMakefile) -> List[Finding]:
    """MA003: Check for sudo in recipes."""
    findings = []
    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            if re.search(r'\bsudo\b', recipe):
                findings.append(Finding(
                    rule_id="MA003",
                    severity=Severity.ERROR,
                    line=lineno,
                    message=f"sudo in recipe for '{target.name}'",
                    detail="Build scripts should not require root privileges",
                    recommendation="Install to user-writable locations or use "
                                   "DESTDIR for staged installs",
                    matched=recipe[:100],
                ))
    return findings


def check_secrets(parsed: ParsedMakefile) -> List[Finding]:
    """MA004: Check for hardcoded secrets."""
    findings = []

    # Check variable assignments
    for var in parsed.variables:
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, f"{var.name} = {var.value}"):
                findings.append(Finding(
                    rule_id="MA004",
                    severity=Severity.ERROR,
                    line=var.line,
                    message=f"Possible {secret_type}: {var.name}",
                    detail=f"Value: {var.value[:20]}{'...' if len(var.value) > 20 else ''}",
                    recommendation=f"Use environment variable: {var.name} ?= $({var.name})",
                    matched=f"{var.name} = {var.value[:30]}",
                ))
                break

    # Check recipe lines
    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            for pattern, secret_type in SECRET_PATTERNS:
                if re.search(pattern, recipe):
                    findings.append(Finding(
                        rule_id="MA004",
                        severity=Severity.ERROR,
                        line=lineno,
                        message=f"Possible {secret_type} in '{target.name}' recipe",
                        detail=f"Recipe line: {recipe[:60]}",
                        recommendation="Pass secrets via environment variables",
                        matched=recipe[:80],
                    ))
                    break

    return findings


def check_phony(parsed: ParsedMakefile) -> List[Finding]:
    """MA005: Check for missing .PHONY declarations."""
    findings = []
    declared_phony = parsed.phony_targets

    for target in parsed.targets:
        if target.is_pattern:
            continue  # Pattern rules don't need .PHONY
        if target.name.startswith("."):
            continue  # Built-in special targets
        if target.name in declared_phony:
            continue

        # Heuristic: target is likely phony if:
        # 1. Name is in common phony set (and is a plain name)
        # 2. Not a variable-based target name (those produce files)
        # 3. Has no file extension or path separators
        name_lower = target.name.lower()

        # Skip targets that contain variables or path components — they build files
        if "$(" in target.name or "${" in target.name:
            continue
        if "/" in target.name or "." in target.name:
            continue

        # Skip targets whose recipes create files (touch, >, cp, mkdir, gcc, etc.)
        creates_file = any(
            re.search(r'\b(touch|mkdir|cp |mv |install |gcc |g\+\+ |cc |'
                      r'ld |ar |>|>>)\b', r)
            for _, r in target.recipe_lines
        )
        if creates_file:
            continue

        is_likely_phony = (
            name_lower in COMMON_PHONY_TARGETS
            or name_lower.startswith(("test-", "lint-", "check-", "docker-",
                                       "deploy-", "build-", "run-", "install-"))
        )

        if is_likely_phony:
            findings.append(Finding(
                rule_id="MA005",
                severity=Severity.WARNING,
                line=target.line,
                message=f"Target '{target.name}' should be declared .PHONY",
                detail="Without .PHONY, make checks for a file with this name "
                       "and skips the target if it exists",
                recommendation=f"Add: .PHONY: {target.name}",
                matched=target.name,
            ))

    return findings


def check_duplicate_targets(parsed: ParsedMakefile) -> List[Finding]:
    """MA006: Check for duplicate target definitions."""
    findings = []
    seen: Dict[str, int] = {}

    for target in parsed.targets:
        if target.is_pattern:
            continue
        if target.name in seen:
            findings.append(Finding(
                rule_id="MA006",
                severity=Severity.WARNING,
                line=target.line,
                message=f"Duplicate target '{target.name}' "
                        f"(first defined at line {seen[target.name]})",
                detail="Only the last definition's recipe is used, "
                       "which can be confusing",
                recommendation=f"Merge recipes or use different target names",
                matched=target.name,
            ))
        else:
            seen[target.name] = target.line

    return findings


def check_recursive_make(parsed: ParsedMakefile) -> List[Finding]:
    """MA007: Check for recursive make."""
    findings = []
    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            if re.search(r'\$\(MAKE\)\s+-C\b|\$\{MAKE\}\s+-C\b|make\s+-C\b',
                          recipe):
                findings.append(Finding(
                    rule_id="MA007",
                    severity=Severity.WARNING,
                    line=lineno,
                    message=f"Recursive make in '{target.name}'",
                    detail="Peter Miller's 'Recursive Make Considered Harmful' — "
                           "recursive make can miss dependencies across directories",
                    recommendation="Consider non-recursive make with include directives",
                    matched=recipe[:100],
                ))
    return findings


def check_hardcoded_paths(parsed: ParsedMakefile) -> List[Finding]:
    """MA008: Check for hardcoded absolute paths."""
    findings = []
    # Common prefixes that are usually OK
    ok_prefixes = {"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/stdin",
                   "/bin/sh", "/bin/bash", "/usr/bin/env", "/tmp",
                   "/etc/os-release"}

    for var in parsed.variables:
        abs_paths = re.findall(r'(/(?:home|Users|opt|usr/local|srv)/\S+)', var.value)
        for path in abs_paths:
            if not any(path.startswith(p) for p in ok_prefixes):
                findings.append(Finding(
                    rule_id="MA008",
                    severity=Severity.WARNING,
                    line=var.line,
                    message=f"Hardcoded absolute path in '{var.name}': {path}",
                    detail="Absolute paths reduce portability across machines",
                    recommendation=f"Use a variable: {var.name} ?= {path}",
                    matched=f"{var.name} = {var.value[:80]}",
                ))

    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            abs_paths = re.findall(
                r'(/(?:home|Users|opt|usr/local|srv)/\S+)', recipe)
            for path in abs_paths:
                if not any(path.startswith(p) for p in ok_prefixes):
                    findings.append(Finding(
                        rule_id="MA008",
                        severity=Severity.WARNING,
                        line=lineno,
                        message=f"Hardcoded absolute path in '{target.name}': {path}",
                        detail="Consider using a variable for portability",
                        recommendation=f"Define a variable: INSTALL_DIR ?= {os.path.dirname(path)}",
                        matched=recipe[:80],
                    ))

    return findings


def check_undefined_variables(parsed: ParsedMakefile) -> List[Finding]:
    """MA009: Check for undefined variable references."""
    findings = []

    # Collect all defined variables
    defined = set()
    for var in parsed.variables:
        defined.add(var.name)

    # Built-in / automatic variables
    builtins = {
        "@", "<", "^", "?", "+", "*", "%", "D", "F",
        "@D", "@F", "*D", "*F", "<D", "<F", "^D", "^F",
        "MAKE", "MAKEFLAGS", "MAKECMDGOALS", "MAKEFILE_LIST",
        "MAKEFILES", "VPATH", "SHELL", "CURDIR", "SUFFIXES",
        ".DEFAULT_GOAL", ".RECIPEPREFIX", ".FEATURES", ".INCLUDE_DIRS",
        "CC", "CXX", "CPP", "FC", "AS", "AR", "LD", "LEX", "YACC",
        "CFLAGS", "CXXFLAGS", "CPPFLAGS", "FFLAGS", "LDFLAGS",
        "LDLIBS", "LFLAGS", "YFLAGS", "ARFLAGS",
        "RM", "INSTALL", "INSTALL_PROGRAM", "INSTALL_DATA",
        "HOME", "USER", "PATH", "PWD",
        "DESTDIR", "PREFIX", "prefix", "exec_prefix",
        "bindir", "sbindir", "libdir", "includedir",
        "datarootdir", "datadir", "sysconfdir", "localstatedir",
        "mandir", "infodir", "docdir",
    }
    defined.update(builtins)

    # Also consider environment variables as defined
    defined.update(os.environ.keys())

    # Scan for references
    all_text = ""
    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            all_text += recipe + "\n"
    for var in parsed.variables:
        all_text += var.value + "\n"

    # Find $(...) and ${...} references
    refs = set(re.findall(r'\$[\({](\w+)[\)}]', all_text))

    undefined = refs - defined
    # Filter out common false positives
    false_positives = {"shell", "wildcard", "patsubst", "subst", "strip",
                       "findstring", "filter", "filter-out", "sort", "word",
                       "words", "wordlist", "firstword", "lastword",
                       "dir", "notdir", "suffix", "basename", "addsuffix",
                       "addprefix", "join", "realpath", "abspath",
                       "if", "or", "and", "foreach", "call", "value",
                       "eval", "origin", "flavor", "error", "warning", "info",
                       "file", "guile"}
    undefined -= false_positives

    for varname in sorted(undefined):
        # Find the first line where it's referenced
        for target in parsed.targets:
            for lineno, recipe in target.recipe_lines:
                if f"$({varname})" in recipe or f"${{{varname}}}" in recipe:
                    findings.append(Finding(
                        rule_id="MA009",
                        severity=Severity.WARNING,
                        line=lineno,
                        message=f"Variable '{varname}' referenced but not defined",
                        detail="May be set by the environment or a parent Makefile",
                        recommendation=f"Add: {varname} ?= default_value",
                        matched=f"$({varname})",
                    ))
                    break
            else:
                continue
            break

    return findings


def check_large_recipes(parsed: ParsedMakefile) -> List[Finding]:
    """MA010: Check for recipes that are too long."""
    findings = []
    threshold = 20

    for target in parsed.targets:
        if len(target.recipe_lines) > threshold:
            findings.append(Finding(
                rule_id="MA010",
                severity=Severity.WARNING,
                line=target.line,
                message=f"Target '{target.name}' has {len(target.recipe_lines)} "
                        f"recipe lines (threshold: {threshold})",
                detail="Large recipes are hard to maintain and debug",
                recommendation=f"Extract to a shell script: scripts/{target.name}.sh",
                matched=f"{target.name}: ({len(target.recipe_lines)} lines)",
            ))

    return findings


def check_error_handling(parsed: ParsedMakefile) -> List[Finding]:
    """MA011: Check for missing error handling in complex recipes."""
    findings = []

    for target in parsed.targets:
        if len(target.recipe_lines) < 3:
            continue

        has_set_e = False
        has_long_chains = False

        for lineno, recipe in target.recipe_lines:
            if "set -e" in recipe:
                has_set_e = True
            # Long semicolon chains without error checking
            if recipe.count(";") >= 3 and "||" not in recipe and "&&" not in recipe:
                has_long_chains = True

        if has_long_chains and not has_set_e:
            findings.append(Finding(
                rule_id="MA011",
                severity=Severity.WARNING,
                line=target.line,
                message=f"Target '{target.name}' has long command chains without error handling",
                detail="Semicolon-separated commands continue even if earlier ones fail",
                recommendation="Use && between commands, or add 'set -e' at the start",
                matched=target.name,
            ))

    return findings


def check_bashisms(parsed: ParsedMakefile) -> List[Finding]:
    """MA012: Check for bash-specific syntax when SHELL is not bash."""
    findings = []

    # If SHELL is explicitly set to bash, bashisms are fine
    if parsed.shell_setting:
        shell_base = os.path.basename(parsed.shell_setting.strip("\"' "))
        if shell_base in ("bash", "/bin/bash", "/usr/bin/bash",
                           "/usr/local/bin/bash"):
            return findings

    for target in parsed.targets:
        for lineno, recipe in target.recipe_lines:
            for pattern, description in BASHISMS:
                if re.search(pattern, recipe):
                    findings.append(Finding(
                        rule_id="MA012",
                        severity=Severity.WARNING,
                        line=lineno,
                        message=f"Bashism in '{target.name}': {description}",
                        detail="Default SHELL is /bin/sh, which may not support bash features",
                        recommendation="Set SHELL := /bin/bash at the top, "
                                       "or use POSIX-compatible syntax",
                        matched=recipe[:80],
                    ))
                    break  # One finding per recipe line

    return findings


def check_default_target(parsed: ParsedMakefile) -> List[Finding]:
    """MA013: Check for missing default 'all' target."""
    findings = []
    target_names = {t.name for t in parsed.targets}

    if "all" not in target_names and parsed.targets:
        first = parsed.targets[0]
        findings.append(Finding(
            rule_id="MA013",
            severity=Severity.INFO,
            line=1,
            message=f"No 'all' target — '{first.name}' will be the default",
            detail="Convention: 'all' should be the default target",
            recommendation="Add: all: build  (or whatever your main target is)",
            matched=f"first target: {first.name}",
        ))

    return findings


def check_clean_target(parsed: ParsedMakefile) -> List[Finding]:
    """MA014: Check for missing 'clean' target."""
    findings = []
    target_names = {t.name for t in parsed.targets}

    if "clean" not in target_names and len(parsed.targets) > 2:
        findings.append(Finding(
            rule_id="MA014",
            severity=Severity.INFO,
            line=1,
            message="No 'clean' target defined",
            detail="Users expect 'make clean' to remove build artifacts",
            recommendation="Add a clean target to remove generated files",
            matched="(missing)",
        ))

    return findings


def check_deprecated(parsed: ParsedMakefile) -> List[Finding]:
    """MA015: Check for deprecated syntax."""
    findings = []

    for target in parsed.targets:
        # Double-colon rules (not deprecated but often misused)
        pass

    for var in parsed.variables:
        # Check for old-style suffix rules in variables
        if var.name.startswith(".") and "." in var.name[1:]:
            # Could be an old-style suffix rule
            if re.match(r'^\.\w+\.\w+$', var.name):
                findings.append(Finding(
                    rule_id="MA015",
                    severity=Severity.INFO,
                    line=var.line,
                    message=f"Old-style suffix rule: {var.name}",
                    detail="Suffix rules are supported but pattern rules (%.o: %.c) "
                           "are more readable",
                    recommendation=f"Use pattern rule: %.{var.name.split('.')[2]}: "
                                   f"%.{var.name.split('.')[1]}",
                    matched=var.name,
                ))

    return findings


def check_long_lines(parsed: ParsedMakefile, raw_lines: List[str]) -> List[Finding]:
    """MA016: Check for excessively long lines."""
    findings = []
    threshold = 120

    for i, line in enumerate(raw_lines):
        # Skip continuation lines (they're joined for readability)
        if line.rstrip().endswith("\\"):
            continue
        if len(line.rstrip()) > threshold:
            findings.append(Finding(
                rule_id="MA016",
                severity=Severity.INFO,
                line=i + 1,
                message=f"Line exceeds {threshold} characters ({len(line.rstrip())} chars)",
                detail="Long lines are hard to read in terminals and diffs",
                recommendation="Use line continuation (\\) to break long lines",
                matched=line.rstrip()[:80] + "...",
            ))

    # Cap at 5 findings to avoid noise
    return findings[:5]


def check_todos(parsed: ParsedMakefile, raw_lines: List[str]) -> List[Finding]:
    """MA017: Check for TODO/FIXME comments."""
    findings = []
    pattern = re.compile(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', re.IGNORECASE)

    for i, line in enumerate(raw_lines):
        match = pattern.search(line)
        if match and "#" in line:  # Only in comments
            comment_start = line.index("#")
            if match.start() > comment_start:
                findings.append(Finding(
                    rule_id="MA017",
                    severity=Severity.INFO,
                    line=i + 1,
                    message=f"Unresolved {match.group(1).upper()} comment",
                    detail=line.strip()[:100],
                    recommendation="Resolve or track this issue",
                    matched=line.strip()[:80],
                ))

    return findings[:10]  # Cap


# ── Main Analysis ─────────────────────────────────────────────────────────────

def analyze(filepath: str, ignore_rules: Optional[List[str]] = None,
            min_severity: Severity = Severity.INFO) -> Tuple[List[Finding], ParsedMakefile]:
    """Run all checks on a Makefile."""
    parsed = parse_makefile(filepath)
    findings: List[Finding] = []
    ignore = set(ignore_rules or [])

    raw_lines = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except Exception:
        pass

    checks = [
        lambda: check_spaces_instead_of_tabs(parsed, raw_lines),
        lambda: check_dangerous_commands(parsed),
        lambda: check_sudo(parsed),
        lambda: check_secrets(parsed),
        lambda: check_phony(parsed),
        lambda: check_duplicate_targets(parsed),
        lambda: check_recursive_make(parsed),
        lambda: check_hardcoded_paths(parsed),
        lambda: check_undefined_variables(parsed),
        lambda: check_large_recipes(parsed),
        lambda: check_error_handling(parsed),
        lambda: check_bashisms(parsed),
        lambda: check_default_target(parsed),
        lambda: check_clean_target(parsed),
        lambda: check_deprecated(parsed),
        lambda: check_long_lines(parsed, raw_lines),
        lambda: check_todos(parsed, raw_lines),
    ]

    sev_rank = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}

    for check_fn in checks:
        for finding in check_fn():
            if finding.rule_id not in ignore:
                if sev_rank[finding.severity] >= sev_rank[min_severity]:
                    findings.append(finding)

    # Sort by line number
    findings.sort(key=lambda f: (f.line, f.rule_id))

    return findings, parsed


# ── Scoring ───────────────────────────────────────────────────────────────────

def calculate_score(findings: List[Finding]) -> Tuple[int, str]:
    """Calculate quality score (0-100) and grade (A-F)."""
    score = 100
    for f in findings:
        if f.severity == Severity.ERROR:
            score -= 15
        elif f.severity == Severity.WARNING:
            score -= 5

    score = max(0, score)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def grade_verdict(grade: str) -> str:
    return {
        "A": "Clean Makefile ✅",
        "B": "Minor issues — review recommended 🔍",
        "C": "Needs improvement ⚠️",
        "D": "Significant issues detected 🚨",
        "F": "Critical problems — fix before using 🛑",
    }[grade]


# ── Output Formatting ─────────────────────────────────────────────────────────

def format_text(filepath: str, findings: List[Finding], parsed: ParsedMakefile,
                score: int, grade: str, verbose: bool = False) -> str:
    """Format findings as human-readable text."""
    lines = []
    lines.append(f"makeaudit v{__version__} — Makefile Linter & Security Checker")
    lines.append("")
    lines.append(f"File: {filepath}")
    lines.append(f"Targets: {len(parsed.targets)}")
    lines.append(f"Variables: {len(parsed.variables)}")
    lines.append(f".PHONY targets: {len(parsed.phony_targets)}")
    lines.append(f"Grade: {grade} ({score}/100)")
    lines.append(f"Verdict: {grade_verdict(grade)}")
    lines.append("")

    if not findings:
        lines.append("✅ No issues found!")
        return "\n".join(lines)

    errors = [f for f in findings if f.severity == Severity.ERROR]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]

    if errors:
        lines.append(f"🔴 ERRORS ({len(errors)}):")
        for f in errors:
            lines.append(f"  {f.severity.symbol()} Line {f.line} [{f.rule_id}]: {f.message}")
            if verbose and f.detail:
                lines.append(f"     Detail: {f.detail}")
            if verbose and f.recommendation:
                lines.append(f"     Fix: {f.recommendation}")
        lines.append("")

    if warnings:
        lines.append(f"🟡 WARNINGS ({len(warnings)}):")
        for f in warnings:
            lines.append(f"  {f.severity.symbol()} Line {f.line} [{f.rule_id}]: {f.message}")
            if verbose and f.detail:
                lines.append(f"     Detail: {f.detail}")
            if verbose and f.recommendation:
                lines.append(f"     Fix: {f.recommendation}")
        lines.append("")

    if infos:
        lines.append(f"ℹ️  INFO ({len(infos)}):")
        for f in infos:
            lines.append(f"  {f.severity.symbol()} Line {f.line} [{f.rule_id}]: {f.message}")
            if verbose and f.detail:
                lines.append(f"     Detail: {f.detail}")
        lines.append("")

    lines.append(f"Summary: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info")
    return "\n".join(lines)


def format_json(filepath: str, findings: List[Finding], parsed: ParsedMakefile,
                score: int, grade: str) -> str:
    """Format findings as JSON."""
    return json.dumps({
        "version": __version__,
        "file": filepath,
        "targets": len(parsed.targets),
        "variables": len(parsed.variables),
        "phony_targets": len(parsed.phony_targets),
        "score": score,
        "grade": grade,
        "verdict": grade_verdict(grade),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "line": f.line,
                "message": f.message,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "matched": f.matched,
            }
            for f in findings
        ],
        "summary": {
            "errors": sum(1 for f in findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in findings if f.severity == Severity.WARNING),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        },
    }, indent=2)


def format_list_rules() -> str:
    lines = ["makeaudit rules:", ""]
    for rule_id, (name, severity, description) in sorted(RULES.items()):
        lines.append(f"  {severity.symbol()} {rule_id}: {name}")
        lines.append(f"     {description}")
        lines.append("")
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="makeaudit",
        description="Makefile Linter & Security Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  makeaudit Makefile                      # Lint a Makefile
  makeaudit --verbose Makefile            # Show fix suggestions
  makeaudit --format json Makefile        # JSON output
  makeaudit --check Makefile              # CI mode (exit 1 on errors)
  makeaudit --check B Makefile            # CI mode (exit 1 if below B)
  makeaudit --ignore MA005,MA016 Makefile # Skip specific rules
  makeaudit --severity warning Makefile   # Warnings+ only
  makeaudit --list-rules                  # Show all rules
  makeaudit Makefile *.mk                 # Lint multiple files
""",
    )

    parser.add_argument("files", nargs="*", help="Makefile(s) to lint")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--check", nargs="?", const="error", metavar="GRADE",
                        help="CI mode: exit 1 if any errors (or if grade below GRADE)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show fix suggestions and details")
    parser.add_argument("--ignore", metavar="RULES",
                        help="Comma-separated rule IDs to ignore (e.g., MA005,MA016)")
    parser.add_argument("--severity", choices=["error", "warning", "info"],
                        default="info",
                        help="Minimum severity to report (default: info)")
    parser.add_argument("--list-rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--version", action="version",
                        version=f"makeaudit {__version__}")

    args = parser.parse_args()

    if args.list_rules:
        print(format_list_rules())
        return

    files = list(args.files)

    if not files:
        # Auto-detect
        candidates = ["Makefile", "makefile", "GNUmakefile"]
        for c in candidates:
            if os.path.exists(c):
                files.append(c)
                break
        if not files:
            # Check for *.mk files
            mk_files = sorted(Path(".").glob("*.mk"))
            files = [str(f) for f in mk_files]

        if not files:
            print("No Makefile found in current directory.", file=sys.stderr)
            parser.print_help()
            sys.exit(1)

        print(f"Auto-detected: {', '.join(files)}", file=sys.stderr)

    ignore_rules = args.ignore.split(",") if args.ignore else []
    min_severity = {
        "error": Severity.ERROR,
        "warning": Severity.WARNING,
        "info": Severity.INFO,
    }[args.severity]

    all_exit_ok = True

    for filepath in files:
        findings, parsed = analyze(filepath, ignore_rules, min_severity)
        score, grade = calculate_score(findings)

        if args.format == "json":
            print(format_json(filepath, findings, parsed, score, grade))
        else:
            print(format_text(filepath, findings, parsed, score, grade, args.verbose))

        if args.check is not None:
            check_val = args.check.upper()
            if check_val == "ERROR":
                if any(f.severity == Severity.ERROR for f in findings):
                    all_exit_ok = False
            else:
                grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
                if grade_order.get(grade, 0) < grade_order.get(check_val, 0):
                    all_exit_ok = False

        if len(files) > 1:
            print("\n" + "=" * 60 + "\n")

    if args.check is not None and not all_exit_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
