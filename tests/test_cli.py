from sodium11 import cli


def test_help(runner):
    result = runner.invoke(cli, '-h')
    assert 'Usage:' in result.output
