"""A small Sigma rule evaluator (a documented subset of the Sigma specification).

Supported: selections as maps (fields AND-ed, list values OR-ed), field modifiers
contains / startswith / endswith / all, case-insensitive matching, and conditions using
and / or / not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them".
Not supported: regex (re), cidr, base64 modifiers, near/count aggregations, timeframes.
For production use, convert rules with pySigma. This engine exists so the rules can be
tested without a SIEM.
"""
import fnmatch
import re
import yaml

TOKEN = re.compile(r"\(|\)|[^\s()]+")


def load_rule(path):
    with open(path) as fh:
        rule = yaml.safe_load(fh)
    rule["_path"] = path
    return rule


def _norm(v):
    return "" if v is None else str(v).lower()


def _match_value(event_val, pattern, mods):
    e, p = _norm(event_val), _norm(pattern)
    if "contains" in mods:
        return p in e
    if "startswith" in mods:
        return e.startswith(p)
    if "endswith" in mods:
        return e.endswith(p)
    return e == p


def _match_field(event, key, expected):
    field, *mods = key.split("|")
    if field not in event or event[field] is None:
        return False
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(event[field], v, mods) for v in values]
    return all(results) if "all" in mods else any(results)


def match_selection(event, sel):
    if isinstance(sel, list):                       # list of maps = OR
        return any(match_selection(event, s) for s in sel)
    return all(_match_field(event, k, v) for k, v in sel.items())


class _Parser:
    def __init__(self, text, results):
        self.t = TOKEN.findall(text)
        self.i = 0
        self.r = results

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def eat(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        v = self.or_expr()
        if self.peek() is not None:
            raise ValueError(f"unexpected token {self.peek()!r}")
        return v

    def or_expr(self):
        v = self.and_expr()
        while self.peek() == "or":
            self.eat()
            rhs = self.and_expr()
            v = v or rhs
        return v

    def and_expr(self):
        v = self.not_expr()
        while self.peek() == "and":
            self.eat()
            rhs = self.not_expr()
            v = v and rhs
        return v

    def not_expr(self):
        if self.peek() == "not":
            self.eat()
            return not self.not_expr()
        return self.atom()

    def atom(self):
        tok = self.eat()
        if tok == "(":
            v = self.or_expr()
            if self.eat() != ")":
                raise ValueError("missing )")
            return v
        if tok in ("1", "all") and self.peek() == "of":
            self.eat()
            target = self.eat()
            names = list(self.r) if target == "them" else [n for n in self.r if fnmatch.fnmatch(n, target)]
            if not names:
                raise ValueError(f"no selections match {target!r}")
            vals = [self.r[n] for n in names]
            return any(vals) if tok == "1" else all(vals)
        if tok not in self.r:
            raise ValueError(f"unknown selection {tok!r}")
        return self.r[tok]


def matches(rule, event):
    det = rule["detection"]
    results = {k: match_selection(event, v) for k, v in det.items() if k != "condition"}
    return _Parser(det["condition"], results).parse()


def logsource_key(rule):
    ls = rule["logsource"]
    return ls.get("category") or ls.get("service")
