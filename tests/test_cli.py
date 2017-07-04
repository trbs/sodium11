from click.testing import CliRunner
from sodium11 import cli


def test_help():
    runner = CliRunner()
    result = runner.invoke(cli, '-h')
    assert 'Usage:' in result.output
