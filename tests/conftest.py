import os
import six
import pytest
import string
from click.testing import CliRunner
from Cryptodome.Cipher import AES


TEST_PRIVATE_KEY = """-----BEGIN SODIUM11 PRIVATE KEY-----
AAAAEHNvZGl1bTExLWVkMjU1MTkAAAAIMDAwMDAxMDAAAAAgzogGej28SJZ0XIy7s3NoW2T6t6bqte5FnvaAQ+D4PHUAAABI4hFEbM+g5+oGjysKOS8g2skNxEc0fphMX0TAgHMaCJpkDuH2OLge8TKejt5Vw3zR0VKMXt/17+0cq+q+jAqstYivTd2WJbVH
-----END SODIUM11 PRIVATE KEY-----
"""

TEST_PUBLIC_KEY = "sodium11-ed25519 AAAAEHNvZGl1bTExLWVkMjU1MTkAAAAIMDAwMDAxMDAAAAAgOuISdUuLEQIYeE1UcpbpktCk67kAK72Imdaq++Edw2I= test.keys\n"


def write_data_size(f, size_mb=0, data=None, bufsize=4096 * 4):
    if not size_mb:
        return

    if not data:
        return

    buf = data * int(bufsize / len(data))
    for i in six.moves.range(int((size_mb * 1024 * 1024) / bufsize)):
        f.write(buf)


@pytest.fixture(scope="session")
def runner_factory(tmpdir_factory):
    runner = CliRunner()

    isolated_dir = tmpdir_factory.mktemp('isolated_dir')

    keyfile = "keys/id_ed25519"
    passphrase = "123456789"

    runner.env['SODIUM11_KEY_FILE'] = keyfile
    runner.env['SODIUM11_PASSPHRASE'] = passphrase

    # x = isolated_dir.join("keys")
    # os.makedirs(x)

    # create a test keypair
    with isolated_dir.join("keys", "id_ed25519").open(mode="w", ensure=True) as f:
        f.write(TEST_PRIVATE_KEY)

    with isolated_dir.join("keys", "id_ed25519.pub").open(mode="w", ensure=True) as f:
        f.write(TEST_PUBLIC_KEY)

    # create test file zeros 16MB
    with isolated_dir.join("zeros_16MB.dat").open(mode="w") as f:
        write_data_size(f, size_mb=16, data="0")

    # create test file zeros 64MB
    with isolated_dir.join("zeros_32MB.dat").open(mode="w") as f:
        write_data_size(f, size_mb=32, data="0")

    # create test file printable characters 64MB
    with isolated_dir.join("repeat_16MB.dat").open(mode="w") as f:
        write_data_size(f, size_mb=16, data=string.printable)

    # create predictable "random" file
    cipher = AES.new('1234567890123456', AES.MODE_CFB, iv='1234567890123456')
    with isolated_dir.join("bin_1MB.dat").open(mode="wb") as f:
        block = b'0'*1024
        for i in six.moves.range(1 * 1024):
            f.write(cipher.encrypt(block))

    class RunnerFactory(object):
        def __init__(self, runner):
            self.runner = runner

        def __call__(self):
            return self

        def __enter__(self):
            self._current_dir = os.getcwd()
            os.chdir(str(isolated_dir))
            return self.runner

        def __exit__(self, type, value, traceback):
            os.chdir(self._current_dir)

    return RunnerFactory(runner)
