import pytest

from traceable.identity import Signer


@pytest.fixture(scope="session")
def signer() -> Signer:
    return Signer.generate()
