import os
from click.testing import CliRunner
from sodium11 import cli


def _generate_key(filename):
    runner = CliRunner()
    with runner.isolated_filesystem():
        # cwd = os.getcwd()
        result = runner.invoke(cli, ['generate-key', '--key-file', filename, '--passphrase', '12345678'], catch_exceptions=False)
        assert not result.exception
        assert result.exit_code == 0
        with open(filename) as f:
            data = f.read()
        assert False
        assert '-----BEGIN SODIUM11 PRIVATE KEY-----' in data
        assert '-----END SODIUM11 PRIVATE KEY-----' in data


def test_cli_generate_key_without_directory():
    _generate_key("id_ed25519")


def test_cli_generate_key_with_directory():
    _generate_key("keys/id_ed25519")
