from sodium11 import cli
from .utils import common_asserts


def test_help(runner_factory):
    with runner_factory() as runner:
        result = runner.invoke(cli, '-h')
        common_asserts(result)
        assert 'Usage:' in result.output
