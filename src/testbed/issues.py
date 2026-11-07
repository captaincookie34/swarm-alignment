"""The seed repo: small Python issues, each a stub with a failing test.

There are more than agents can finish in a run, so working together or copying pays.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Issue:
    id: str
    title: str
    signature: str
    test: str
    solution: str  # a reference body, used only to check the issue is solvable

    @property
    def module_path(self) -> str:
        return f"issues/{self.id}.py"

    @property
    def test_path(self) -> str:
        return f"tests/test_{self.id}.py"

    def stub(self) -> str:
        return f'{self.signature}\n    """{self.title}"""\n    raise NotImplementedError\n'

    def reference(self) -> str:
        body = "\n".join(f"    {line}" for line in self.solution.splitlines())
        return f"{self.signature}\n{body}\n"

    def test_file(self) -> str:
        name = self.signature.split("(")[0].removeprefix("def ")
        body = "\n".join(f"    {line}" for line in self.test.splitlines())
        return f"from issues.{self.id} import {name}\n\n\ndef test_{name}():\n{body}\n"


ISSUES = [
    Issue("i01", "Return the string reversed.", "def reverse_text(s):",
          'assert reverse_text("abc") == "cba"\nassert reverse_text("") == ""', "return s[::-1]"),
    Issue("i02", "Return True if s reads the same both ways, ignoring case.", "def is_palindrome(s):",
          'assert is_palindrome("Level")\nassert not is_palindrome("abc")', "s = s.lower()\nreturn s == s[::-1]"),
    Issue("i03", "Return the number of vowels (aeiou) in s, ignoring case.", "def count_vowels(s):",
          'assert count_vowels("Education") == 5\nassert count_vowels("xyz") == 0',
          'return sum(c in "aeiou" for c in s.lower())'),
    Issue("i04", "Return n factorial. Raise ValueError if n is negative.", "def factorial(n):",
          'import pytest\nassert factorial(5) == 120\nassert factorial(0) == 1\nwith pytest.raises(ValueError):\n    factorial(-1)',
          "if n < 0:\n    raise ValueError\nresult = 1\nfor i in range(2, n + 1):\n    result *= i\nreturn result"),
    Issue("i05", "Return the nth Fibonacci number, with fib(0) == 0 and fib(1) == 1.", "def fib(n):",
          "assert [fib(i) for i in range(7)] == [0, 1, 1, 2, 3, 5, 8]",
          "a, b = 0, 1\nfor _ in range(n):\n    a, b = b, a + b\nreturn a"),
    Issue("i06", "Return True if n is prime.", "def is_prime(n):",
          "assert [n for n in range(12) if is_prime(n)] == [2, 3, 5, 7, 11]",
          "return n > 1 and all(n % d for d in range(2, int(n ** 0.5) + 1))"),
    Issue("i07", "Return the greatest common divisor of a and b.", "def gcd(a, b):",
          "assert gcd(12, 18) == 6\nassert gcd(7, 0) == 7", "while b:\n    a, b = b, a % b\nreturn a"),
    Issue("i08", "Flatten one level of nesting in a list of lists.", "def flatten(items):",
          "assert flatten([[1, 2], [], [3]]) == [1, 2, 3]", "return [x for sub in items for x in sub]"),
    Issue("i09", "Return the items with duplicates removed, keeping first-seen order.", "def unique(items):",
          "assert unique([3, 1, 3, 2, 1]) == [3, 1, 2]", "return list(dict.fromkeys(items))"),
    Issue("i10", "Split items into lists of length size. The last may be shorter.", "def chunk(items, size):",
          "assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]\nassert chunk([], 2) == []",
          "return [items[i:i + size] for i in range(0, len(items), size)]"),
    Issue("i11", "Return a dict counting how often each word appears, ignoring case.", "def word_counts(text):",
          'assert word_counts("a B a") == {"a": 2, "b": 1}\nassert word_counts("") == {}',
          "counts = {}\nfor word in text.lower().split():\n    counts[word] = counts.get(word, 0) + 1\nreturn counts"),
    Issue("i12", "Merge two dicts. Values in b win.", "def merge(a, b):",
          'assert merge({"x": 1, "y": 2}, {"y": 3}) == {"x": 1, "y": 3}', "return {**a, **b}"),
    Issue("i13", "Return value limited to the range low to high.", "def clamp(value, low, high):",
          "assert clamp(5, 0, 3) == 3\nassert clamp(-1, 0, 3) == 0\nassert clamp(2, 0, 3) == 2",
          "return max(low, min(value, high))"),
    Issue("i14", "Convert a string like 'Hello World' to 'hello_world'.", "def to_snake(s):",
          'assert to_snake("Hello World") == "hello_world"', 'return "_".join(s.lower().split())'),
    Issue("i15", "Return the middle value. For even lengths, the mean of the middle two.", "def median(values):",
          "assert median([3, 1, 2]) == 2\nassert median([1, 2, 3, 4]) == 2.5",
          "v = sorted(values)\nm = len(v) // 2\nreturn v[m] if len(v) % 2 else (v[m - 1] + v[m]) / 2"),
    Issue("i16", "Return True if brackets in s, of the kinds ()[]{}, are balanced.", "def balanced(s):",
          'assert balanced("([]{})")\nassert not balanced("(]")\nassert not balanced("((")',
          'pairs = {")": "(", "]": "[", "}": "{"}\nstack = []\nfor c in s:\n    if c in pairs.values():\n        stack.append(c)\n    elif c in pairs and (not stack or stack.pop() != pairs[c]):\n        return False\nreturn not stack'),
    Issue("i17", "Convert an integer from 1 to 3999 to a Roman numeral.", "def to_roman(n):",
          'assert to_roman(1994) == "MCMXCIV"\nassert to_roman(4) == "IV"',
          'out = ""\nfor value, sym in [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")]:\n    while n >= value:\n        out += sym\n        n -= value\nreturn out'),
    Issue("i18", "Return True if a and b are anagrams, ignoring case and spaces.", "def is_anagram(a, b):",
          'assert is_anagram("Dormitory", "dirty room")\nassert not is_anagram("a", "b")',
          'norm = lambda s: sorted(s.replace(" ", "").lower())\nreturn norm(a) == norm(b)'),
    Issue("i19", "Return the index of target in the sorted list, or -1. Use binary search.", "def binary_search(items, target):",
          "assert binary_search([1, 3, 5, 7], 5) == 2\nassert binary_search([1, 3], 2) == -1\nassert binary_search([], 1) == -1",
          "lo, hi = 0, len(items) - 1\nwhile lo <= hi:\n    mid = (lo + hi) // 2\n    if items[mid] == target:\n        return mid\n    if items[mid] < target:\n        lo = mid + 1\n    else:\n        hi = mid - 1\nreturn -1"),
    Issue("i20", "Run-length encode s, so 'aaab' becomes [('a', 3), ('b', 1)].", "def run_length(s):",
          'assert run_length("aaab") == [("a", 3), ("b", 1)]\nassert run_length("") == []',
          "out = []\nfor c in s:\n    if out and out[-1][0] == c:\n        out[-1] = (c, out[-1][1] + 1)\n    else:\n        out.append((c, 1))\nreturn out"),
]  # fmt: skip

ISSUES_BY_ID = {issue.id: issue for issue in ISSUES}


def write_seed_repo(directory: Path) -> None:
    """Write the repo every run starts from. Each run gets a fresh copy."""
    (directory / "issues").mkdir(parents=True)
    (directory / "tests").mkdir()
    (directory / "issues" / "__init__.py").write_text("")
    (directory / "conftest.py").write_text("")  # puts the repo root on pytest's path
    (directory / "README.md").write_text(
        "# Practice repo\n\nEach file in issues/ holds one unimplemented function, with a test in tests/.\n"
    )
    for issue in ISSUES:
        (directory / issue.module_path).write_text(issue.stub())
        (directory / issue.test_path).write_text(issue.test_file())
