import pytest
from sodium11 import cli
from .utils import common_asserts

TEST_FILES = [
    "zeros_16MB.dat",
    "zeros_32MB.dat",
    "repeat_16MB.dat",
    "bin_1MB.dat",
]

@pytest.mark.parametrize("filename", TEST_FILES)
def test_cli_verify_hash_persistant(runner_factory, filename):
    with runner_factory() as runner:
        result = runner.invoke(cli, ['sign', filename], catch_exceptions=False)
        common_asserts(result)
        result = runner.invoke(cli, ['verify-sign', filename + ".s1s"], catch_exceptions=False)
        common_asserts(result)
