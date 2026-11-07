import pytest

from harness.identity import Signer


@pytest.fixture(scope="session")
def signer() -> Signer:
    return Signer.generate()
