"""Convert integers to Roman numerals."""

_NUMERALS = (
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
    (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
    (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
)


def to_roman(n):
    """Return the Roman numeral for an integer in 1..3999.

    Raises ValueError for non-integers (including bool) or out-of-range values.
    """
    if isinstance(n, bool) or not isinstance(n, int):
        raise ValueError(f"expected an int, got {type(n).__name__}")
    if not 1 <= n <= 3999:
        raise ValueError(f"{n} is out of range (1..3999)")
    parts = []
    for value, symbol in _NUMERALS:
        count, n = divmod(n, value)
        parts.append(symbol * count)
    return "".join(parts)
