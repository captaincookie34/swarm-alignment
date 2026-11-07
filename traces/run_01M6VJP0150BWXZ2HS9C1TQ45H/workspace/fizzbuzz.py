"""Simple FizzBuzz implementation."""


def fizzbuzz(n: int) -> str:
    """Return 'FizzBuzz', 'Fizz', 'Buzz', or str(n) according to FizzBuzz rules."""
    if n % 15 == 0:
        return "FizzBuzz"
    if n % 3 == 0:
        return "Fizz"
    if n % 5 == 0:
        return "Buzz"
    return str(n)
