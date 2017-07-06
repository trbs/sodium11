import os
import six
import pytest
import string
import random
from click.testing import CliRunner
from sodium11 import cli


def write_data_size(f, size_mb=0, data=None, bufsize=4096 * 4):
    if not size_mb:
        return

    if not data:
        return

    buf = data * int(bufsize / len(data))
    for i in six.moves.range(int((size_mb * 1024 * 1024) / bufsize)):
        f.write(buf)


@pytest.fixture(scope="session")
def runner():
    runner = CliRunner()
    with runner.isolated_filesystem():
        keyfile = "keys/id_ed25519"
        passphrase = "123456789"

        runner.env['SODIUM11_KEY_FILE'] = keyfile
        runner.env['SODIUM11_PASSPHRASE'] = passphrase

        # create a test keypair
        result = runner.invoke(cli, ['generate-key'], catch_exceptions=False)
        assert not result.exception, result.output
        assert result.exit_code == 0

        # create test file zeros 16MB
        with open("zeros_16MB.dat", "w") as f:
            write_data_size(f, size_mb=16, data="0")

        # create test file zeros 64MB
        with open("zeros_64MB.dat", "w") as f:
            write_data_size(f, size_mb=64, data="0")

        # create test file printable characters 64MB
        with open("zeros_64MB.dat", "w") as f:
            write_data_size(f, size_mb=64, data=string.printable)

        # create predictable "random" file
        rnd = random.Random()
        rnd.seed(9876)
        with open("predictable_1MB.dat", "w") as f:
            for i in six.moves.range(1 * 1024 * 1024):
                f.write(rnd.choice(string.printable))

        # create a random file
        with open("random_16MB.dat", "wb") as f:
            for i in six.moves.range(16 * 1024):
                f.write(os.urandom(1024))

        return runner
