import pytest

from leap import is_leap


@pytest.mark.parametrize(
    "year, expected",
    [
        (1900, False),
        (2000, True),
        (2024, True),
        (2023, False),
        (2100, False),
        (2400, True),
        (1996, True),
        (1, False),
    ],
)
def test_is_leap(year, expected):
    assert is_leap(year) is expected
