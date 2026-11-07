import pytest

from fizzbuzz import fizzbuzz


@pytest.mark.parametrize("n", [15, 30, 45, 0, -15])
def test_fizzbuzz_multiples_of_15(n):
    assert fizzbuzz(n) == "FizzBuzz"


@pytest.mark.parametrize("n", [3, 6, 9, 12, -3])
def test_fizz_multiples_of_3(n):
    assert fizzbuzz(n) == "Fizz"


@pytest.mark.parametrize("n", [5, 10, 20, 25, -5])
def test_buzz_multiples_of_5(n):
    assert fizzbuzz(n) == "Buzz"


@pytest.mark.parametrize("n", [1, 2, 4, 7, 11, -1])
def test_other_numbers(n):
    assert fizzbuzz(n) == str(n)


def test_sequence_1_to_15():
    expected = ["1", "2", "Fizz", "4", "Buzz", "Fizz", "7", "8", "Fizz",
                "Buzz", "11", "Fizz", "13", "14", "FizzBuzz"]
    assert [fizzbuzz(i) for i in range(1, 16)] == expected
