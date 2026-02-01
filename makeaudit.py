#!/usr/bin/env python3
"""
makeaudit - A pure Python Makefile linter with zero dependencies.
Checks for common issues, best practices, and portability problems.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import List, Set, Dict, Optional


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    line: int
    code: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Rule:
    id: str
    severity: Severity
    title: str
    description: str


RULES = [
    Rule("MA001", Severity.WARNING, "Missing .PHONY declaration",
         "Targets that don't create files should be declared .PHONY"),
    Rule("MA002", Severity.ERROR, "Undefined variable",
         "Variable referenced but never assigned"),
    Rule("MA003", Severity.INFO, "Missing help target",
         "No help target defined (best practice for discoverability)"),
    Rule("MA004", Severity.ERROR, "Spaces instead of tabs",
         "Recipe lines must be indented with tabs, not spaces"),
    Rule("MA005", Severity.INFO, "Unused variable",
         "Variable defined but never referenced"),
    Rule("MA006", Severity.WARNING, "Shell portability issue",
         "Bash-specific syntax without SHELL := /bin/bash"),
    Rule("MA007", Severity.INFO, "Missing .DEFAULT_GOAL",
         "No .DEFAULT_GOAL set and no 'all' target"),
    Rule("MA008", Severity.INFO, "Recursive make",
         "Using $(MAKE) -C or make -C (may indicate suboptimal build structure)"),
    Rule("MA009", Severity.WARNING, "Hardcoded absolute path",
         "Absolute paths reduce portability"),
    Rule("MA010", Severity.INFO, "Missing clean target",
         "No clean target defined"),
    Rule("MA011", Severity.WARNING, "Missing error handling",
         "Multi-line recipe without set -e or && chaining"),
    Rule("MA012", Severity.INFO, "Excessive echo suppression",
         "Overuse of @ prefix makes debugging difficult"),
]

# Well-known Make automatic variables and built-ins
BUILTIN_VARS = {
    '@', '<', '^', '*', '+', '?', '|', '%',
    'MAKE', 'MAKEFILE_LIST', 'MAKEFLAGS', 'MAKECMDGOALS',
    'CURDIR', 'SHELL', 'MAKE_VERSION', '.DEFAULT_GOAL',
    '.RECIPEPREFIX', '.VARIABLES', '.FEATURES', '.INCLUDE_DIRS',
    'MAKEFILE', 'CC', 'CXX', 'AR', 'LD', 'CFLAGS', 'CXXFLAGS',
    'LDFLAGS', 'ARFLAGS', 'RM', 'INSTALL', 'PREFIX',
}

# Common non-file targets
COMMON_PHONY_TARGETS = {
    'all', 'clean', 'test', 'install', 'build', 'lint', 'help',
    'run', 'dev', 'prod', 'deploy', 'format', 'check', 'setup',
    'init', 'dist', 'release', 'publish', 'serve', 'start', 'stop',
}


class MakefileParser:
    def __init__(self, content: str):
        self.lines = content.splitlines()
        self.targets: Dict[str, int] = {}  # target -> line number
        self.phony_targets: Set[str] = set()
        self.variables: Dict[str, int] = {}  # var -> line number
        self.var_references: Dict[str, List[int]] = {}  # var -> [line numbers]
        self.recipes: Dict[str, List[tuple]] = {}  # target -> [(line_num, code)]
        self.has_help = False
        self.has_clean = False
        self.has_all = False
        self.has_default_goal = False
        self.has_bash_shell = False
        self.current_target = None

    def parse(self):
        """Parse the Makefile and extract relevant information."""
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            line_num = i + 1
            
            # Handle line continuations
            full_line = line
            while full_line.rstrip().endswith('\\') and i + 1 < len(self.lines):
                i += 1
                full_line = full_line.rstrip()[:-1] + ' ' + self.lines[i]
            
            # Skip comments
            if full_line.strip().startswith('#'):
                i += 1
                continue
            
            # Check for SHELL assignment
            if re.match(r'^\s*SHELL\s*[:?]?=\s*/bin/bash', full_line):
                self.has_bash_shell = True
            
            # Check for .DEFAULT_GOAL
            if re.match(r'^\s*\.DEFAULT_GOAL\s*[:?]?=', full_line):
                self.has_default_goal = True
            
            # Variable assignment
            var_match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]?=', full_line)
            if var_match:
                var_name = var_match.group(1)
                self.variables[var_name] = line_num
                # Find variable references in the value
                self._extract_var_refs(full_line, line_num)
                i += 1
                continue
            
            # .PHONY declaration
            phony_match = re.match(r'^\.PHONY\s*:\s*(.+)', full_line)
            if phony_match:
                targets = phony_match.group(1).split()
                self.phony_targets.update(targets)
                i += 1
                continue
            
            # Target definition
            target_match = re.match(r'^([^:\s#]+)\s*:((?:[^=]|$).*)', full_line)
            if target_match and ':=' not in full_line.split(':')[0]:
                target = target_match.group(1).strip()
                # Handle pattern rules and special targets
                if not target.startswith('.') or target == '.PHONY':
                    self.targets[target] = line_num
                    self.current_target = target
                    
                    if target == 'help':
                        self.has_help = True
                    if target == 'clean':
                        self.has_clean = True
                    if target == 'all':
                        self.has_all = True
                    
                    # Extract variable references from prerequisites
                    prereqs = target_match.group(2)
                    self._extract_var_refs(prereqs, line_num)
                    
                    self.recipes[target] = []
                i += 1
                continue
            
            # Recipe line (starts with tab)
            if line.startswith('\t') and self.current_target:
                self.recipes[self.current_target].append((line_num, line))
                self._extract_var_refs(line, line_num)
            elif line.strip() and not line[0].isspace():
                # Non-recipe, non-target line resets current target
                self.current_target = None
            
            i += 1

    def _extract_var_refs(self, text: str, line_num: int):
        """Extract variable references from a line."""
        # Match $(VAR) and ${VAR}
        for match in re.finditer(r'\$[\({]([A-Za-z_@<^*+?|%][A-Za-z0-9_]*?)[\)}]', text):
            var_name = match.group(1)
            # Skip automatic variables (single char or known built-ins)
            if len(var_name) == 1 or var_name in BUILTIN_VARS:
                continue
            if var_name not in self.var_references:
                self.var_references[var_name] = []
            self.var_references[var_name].append(line_num)


class MakefileLinter:
    def __init__(self, filepath: Path, ignored_rules: Set[str] = None):
        self.filepath = filepath
        self.ignored_rules = ignored_rules or set()
        self.findings: List[Finding] = []
        
    def lint(self) -> List[Finding]:
        """Run all linting rules."""
        content = self.filepath.read_text()
        parser = MakefileParser(content)
        parser.parse()
        
        self._check_missing_phony(parser)
        self._check_undefined_vars(parser)
        self._check_missing_help(parser)
        self._check_tabs_vs_spaces(content)
        self._check_unused_vars(parser)
        self._check_shell_portability(parser)
        self._check_missing_default_goal(parser)
        self._check_recursive_make(parser)
        self._check_hardcoded_paths(parser)
        self._check_missing_clean(parser)
        self._check_error_handling(parser)
        self._check_echo_suppression(parser)
        
        return [f for f in self.findings if f.rule_id not in self.ignored_rules]
    
    def _add_finding(self, rule_id: str, line: int, code: str = ""):
        """Add a finding if the rule is not ignored."""
        rule = next(r for r in RULES if r.id == rule_id)
        self.findings.append(Finding(
            rule_id=rule.id,
            severity=rule.severity.value,
            title=rule.title,
            description=rule.description,
            line=line,
            code=code.strip()
        ))
    
    def _check_missing_phony(self, parser: MakefileParser):
        """MA001: Check for targets that should be .PHONY but aren't."""
        for target, line_num in parser.targets.items():
            # Skip pattern rules
            if '%' in target:
                continue
            
            # Skip targets with variable expansions (likely file paths)
            if '$(' in target or '${' in target:
                continue
            
            # Check if it's a common phony target or doesn't look like a file
            is_likely_phony = (
                target in COMMON_PHONY_TARGETS or
                not re.match(r'^[a-zA-Z0-9_.-]+\.[a-z0-9]+$', target)
            )
            
            if is_likely_phony and target not in parser.phony_targets:
                self._add_finding('MA001', line_num, f"Target '{target}' should be in .PHONY")
    
    def _check_undefined_vars(self, parser: MakefileParser):
        """MA002: Check for undefined variables."""
        for var, line_nums in parser.var_references.items():
            if var not in parser.variables and var not in BUILTIN_VARS:
                # Report first use
                self._add_finding('MA002', line_nums[0], f"Variable '$({{var}})' used but not defined")
    
    def _check_missing_help(self, parser: MakefileParser):
        """MA003: Check for missing help target."""
        if not parser.has_help:
            self._add_finding('MA003', 1, "No 'help' target found")
    
    def _check_tabs_vs_spaces(self, content: str):
        """MA004: Check for spaces instead of tabs in recipes."""
        lines = content.splitlines()
        in_recipe = False
        
        for i, line in enumerate(lines, 1):
            # Recipe lines start with tab
            if line and line[0] == '\t':
                in_recipe = True
                continue
            
            # Lines starting with spaces after a target might be recipe errors
            if line.startswith('    ') and not line.strip().startswith('#'):
                # Check if previous non-empty line was a target
                for j in range(i - 2, -1, -1):
                    prev = lines[j].strip()
                    if not prev or prev.startswith('#'):
                        continue
                    if ':' in prev and not prev.startswith('\t'):
                        self._add_finding('MA004', i, line[:40])
                    break
    
    def _check_unused_vars(self, parser: MakefileParser):
        """MA005: Check for unused variables."""
        # Variables that are set for their side effects (not for referencing)
        side_effect_vars = {'SHELL', 'MAKEFLAGS', '.RECIPEPREFIX'}
        
        for var, line_num in parser.variables.items():
            if var not in parser.var_references and var not in side_effect_vars:
                self._add_finding('MA005', line_num, f"Variable '{var}' defined but never used")
    
    def _check_shell_portability(self, parser: MakefileParser):
        """MA006: Check for bash-specific syntax without SHELL := /bin/bash."""
        if parser.has_bash_shell:
            return
        
        bash_patterns = [
            (r'\[\[', '[[ ... ]] (use [ ... ] or test)'),
            (r'<\(', 'process substitution <(...)'),
            (r'<<<', 'here string <<<'),
            (r'\{[a-zA-Z0-9]+\.\.[a-zA-Z0-9]+\}', 'brace expansion {a..z}'),
            (r'\[\s*[0-9]+\s*\]', 'array syntax [n]'),
        ]
        
        for target, recipe_lines in parser.recipes.items():
            for line_num, code in recipe_lines:
                for pattern, desc in bash_patterns:
                    if re.search(pattern, code):
                        self._add_finding('MA006', line_num, f"{desc}: {code.strip()}")
                        break
    
    def _check_missing_default_goal(self, parser: MakefileParser):
        """MA007: Check for missing .DEFAULT_GOAL or 'all' target."""
        if not parser.has_default_goal and not parser.has_all:
            self._add_finding('MA007', 1, "Neither .DEFAULT_GOAL nor 'all' target defined")
    
    def _check_recursive_make(self, parser: MakefileParser):
        """MA008: Check for recursive make usage."""
        for target, recipe_lines in parser.recipes.items():
            for line_num, code in recipe_lines:
                if re.search(r'\$\(MAKE\)\s+-C|make\s+-C', code):
                    self._add_finding('MA008', line_num, code.strip())
    
    def _check_hardcoded_paths(self, parser: MakefileParser):
        """MA009: Check for hardcoded absolute paths."""
        for target, recipe_lines in parser.recipes.items():
            for line_num, code in recipe_lines:
                # Look for absolute paths like /usr/bin/python
                if re.search(r'/(usr|opt|bin|sbin|local)/[a-zA-Z0-9/_-]+', code):
                    self._add_finding('MA009', line_num, code.strip())
    
    def _check_missing_clean(self, parser: MakefileParser):
        """MA010: Check for missing clean target."""
        if not parser.has_clean:
            self._add_finding('MA010', 1, "No 'clean' target found")
    
    def _check_error_handling(self, parser: MakefileParser):
        """MA011: Check for multi-line recipes without error handling."""
        for target, recipe_lines in parser.recipes.items():
            if len(recipe_lines) < 2:
                continue
            
            # Check if any line has 'set -e' or uses && chaining
            has_set_e = any('set -e' in code for _, code in recipe_lines)
            
            if not has_set_e:
                # Check for && chaining (most lines should end with && or ; or be last)
                non_chained = []
                for i, (line_num, code) in enumerate(recipe_lines):
                    stripped = code.strip().lstrip('@-')
                    # Skip comments and empty lines
                    if not stripped or stripped.startswith('#'):
                        continue
                    # Last line doesn't need chaining
                    if i == len(recipe_lines) - 1:
                        continue
                    # Check if line ends with && or ; or \
                    if not re.search(r'(&&|;|\\)\s*$', stripped):
                        non_chained.append((line_num, code))
                
                if non_chained and len(recipe_lines) > 2:
                    line_num, code = recipe_lines[0]
                    self._add_finding('MA011', line_num, 
                                    f"Multi-line recipe in '{target}' without set -e or && chaining")
    
    def _check_echo_suppression(self, parser: MakefileParser):
        """MA012: Check for excessive @ prefix usage."""
        for target, recipe_lines in parser.recipes.items():
            if len(recipe_lines) < 3:
                continue
            
            suppressed = sum(1 for _, code in recipe_lines if code.strip().startswith('@'))
            ratio = suppressed / len(recipe_lines)
            
            if ratio > 0.75:  # More than 75% of lines suppressed
                line_num = recipe_lines[0][0]
                self._add_finding('MA012', line_num, 
                                f"Target '{target}' has {suppressed}/{len(recipe_lines)} lines with @ prefix")


def format_text(findings: List[Finding], filepath: Path) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return f"✓ {filepath}: No issues found"
    
    output = [f"{filepath}:"]
    
    # Group by severity
    by_severity = {'error': [], 'warning': [], 'info': []}
    for f in findings:
        by_severity[f.severity].append(f)
    
    for severity in ['error', 'warning', 'info']:
        items = by_severity[severity]
        if items:
            output.append(f"\n{severity.upper()}S ({len(items)}):")
            for f in items:
                code_str = f" → {f.code}" if f.code else ""
                output.append(f"  Line {f.line}: [{f.rule_id}] {f.title}{code_str}")
    
    return "\n".join(output)


def format_json(findings: List[Finding]) -> str:
    """Format findings as JSON."""
    return json.dumps([f.to_dict() for f in findings], indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="makeaudit - Lint Makefiles for common issues and best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  makeaudit                    # Lint ./Makefile
  makeaudit Makefile.prod      # Lint specific file
  makeaudit --format json      # JSON output
  makeaudit --check            # Exit 1 if errors found (CI mode)
  makeaudit --ignore MA001     # Ignore specific rule
        """
    )
    
    parser.add_argument('makefile', nargs='?', default='Makefile',
                       help='Path to Makefile (default: ./Makefile)')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--severity', choices=['info', 'warning', 'error'],
                       help='Minimum severity to show')
    parser.add_argument('--ignore', action='append', dest='ignored_rules',
                       help='Ignore specific rule (repeatable)')
    parser.add_argument('--check', action='store_true',
                       help='Exit 1 if any errors found (CI mode)')
    parser.add_argument('--list-rules', action='store_true',
                       help='Show all available rules')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Only show errors')
    
    args = parser.parse_args()
    
    # List rules and exit
    if args.list_rules:
        print("Available rules:\n")
        for rule in RULES:
            print(f"  {rule.id} [{rule.severity.value.upper()}]")
            print(f"    {rule.title}")
            print(f"    {rule.description}\n")
        return 0
    
    # Find and lint the Makefile
    makefile = Path(args.makefile)
    if not makefile.exists():
        print(f"Error: {makefile} not found", file=sys.stderr)
        return 1
    
    # Run linter
    ignored = set(args.ignored_rules or [])
    linter = MakefileLinter(makefile, ignored)
    findings = linter.lint()
    
    # Filter by severity
    if args.severity:
        severity_order = {'info': 0, 'warning': 1, 'error': 2}
        min_level = severity_order[args.severity]
        findings = [f for f in findings if severity_order[f.severity] >= min_level]
    
    if args.quiet:
        findings = [f for f in findings if f.severity == 'error']
    
    # Output results
    if args.format == 'json':
        print(format_json(findings))
    else:
        print(format_text(findings, makefile))
    
    # Exit code
    if args.check and any(f.severity == 'error' for f in findings):
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
