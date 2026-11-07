"""Integration tests importing all three utility modules."""
import pytest

from fizzbuzz import fizzbuzz
from leap import is_leap
from roman import to_roman


def test_fizzbuzz_basic():
    assert [fizzbuzz(i) for i in (1, 3, 5, 15)] == ["1", "Fizz", "Buzz", "FizzBuzz"]


def test_leap_basic():
    assert is_leap(2000) and is_leap(2024)
    assert not is_leap(1900) and not is_leap(2023)


def test_roman_basic():
    assert to_roman(1994) == "MCMXCIV"
    with pytest.raises(ValueError):
        to_roman(0)


def test_modules_together():
    # Roman numeral for each leap year in 1996..2004, tagged with fizzbuzz of the year
    years = [y for y in range(1996, 2005) if is_leap(y)]
    assert years == [1996, 2000, 2004]
    assert [to_roman(y) for y in years] == ["MCMXCVI", "MM", "MMIV"]
    assert [fizzbuzz(y) for y in years] == ["1996", "Buzz", "Fizz"]
