import pytest

from roman import to_roman


@pytest.mark.parametrize("n, expected", [
    (1, "I"), (3, "III"), (4, "IV"), (5, "V"), (9, "IX"), (14, "XIV"),
    (40, "XL"), (90, "XC"), (400, "CD"), (900, "CM"),
    (1994, "MCMXCIV"), (2024, "MMXXIV"), (3999, "MMMCMXCIX"),
])
def test_known_values(n, expected):
    assert to_roman(n) == expected


@pytest.mark.parametrize("bad", [0, -1, 4000, 10000])
def test_out_of_range(bad):
    with pytest.raises(ValueError):
        to_roman(bad)


@pytest.mark.parametrize("bad", [1.0, "5", None, True, False])
def test_non_int(bad):
    with pytest.raises(ValueError):
        to_roman(bad)
