#!/usr/bin/env python

import os
import sys
# import json
# import time
import base64
import struct
import hashlib
# import yaml
import stat
import click
import platform
import nacl.utils
import nacl.public
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.hash
from cStringIO import StringIO
from functools import partial
from collections import OrderedDict
from contextlib import contextmanager
from Cryptodome.Cipher import AES
from Cryptodome.Hash import BLAKE2b, RIPEMD160, SHA3_256, SHA3_512, keccak
from Cryptodome.Cipher import ChaCha20
# from Cryptodome.Random import get_random_bytes
from tqdm import tqdm


class suppress_stdout_stderr(object):
    '''
    A context manager for doing a "deep suppression" of stdout and stderr in
    Python, i.e. will suppress all print, even if the print originates in a
    compiled C/Fortran sub-function.
       This will not suppress raised exceptions, since exceptions are printed
    to stderr just before a script exits, and after the context manager has
    exited (at least, I think that is why it lets exceptions through).

    Based on: http://stackoverflow.com/questions/11130156/suppress-stdout-stderr-print-from-python-functions
    '''

    def __init__(self):
        # Open a pair of null files
        self.null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
        # Save the actual stdout (1) and stderr (2) file descriptors.
        self.save_fds = (os.dup(1), os.dup(2))

    def __enter__(self):
        # Assign the null pointers to stdout and stderr.
        os.dup2(self.null_fds[0], 1)
        os.dup2(self.null_fds[1], 2)

    def __exit__(self, *_):
        # Re-assign the real stdout/stderr back to (1) and (2)
        os.dup2(self.save_fds[0], 1)
        os.dup2(self.save_fds[1], 2)
        # Close the null files
        os.close(self.null_fds[0])
        os.close(self.null_fds[1])


# with suppress_stdout_stderr():
#     try:
#         from pyeclib.ec_iface import ECDriver
#         HAS_PYECLIB = True
#     except ImportError:
#         HAS_PYECLIB = False

__version__ = "0.8.5"

MAX_INT64 = 0xFFFFFFFFFFFFFFFF
MAX_INT128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
SECRET_SENDER_PUBLICKEY_MARKER = "deadbeefdeadbeefdeadbeefdeadbeaf"
CONFIG_DIRECTORY = os.path.expanduser("~/.sodium11")
DEFAULT_KEYPATH = os.path.join(CONFIG_DIRECTORY, "id_ed25519")
DEFAULT_KEYPATH_PUB = DEFAULT_KEYPATH + ".pub"
BUFSIZE = 1024 * 1024
SODIUM11_HEADER_HASHES = "# Sodium11 File Hashes"
ERRASURE_TYPES = [
    "liberasurecode_rs_vand",
    "jerasure_rs_vand",
    "jerasure_rs_cauchy",
    # "isa_l_rs_vand",
    # "isa_l_rs_cauchy",
]
HASH_TYPES = {}
CIPHER_TYPES = {}


class Sodium11Error(Exception):
    pass


class Sodium11PublicKeyfileError(Exception):
    pass


class BaseVersion(object):

    @classmethod
    def version_str(cls):
        return "%08d" % cls.version


class Version100(BaseVersion):
    version = 100

    #  +----+---------+---------------+----------+-----------+----------------+
    #  + id + version + sender pubkey + metadata + signature + encrypted file +
    #  + 4  + 8       + 32            + 229      + 64        + ...            +
    #  +----+---------+---------------+----------+-----------+----------------+
    #  + 12           + 32            + 229      + 64        + ...            +
    #  + 44                           + 229      + 64        + ...            +
    #  + 273                                     + 64        + ...            +
    #  + 337                                                 + ...            +
    #  +----------------------------------------------------------------------+
    #
    prefix_size = 337

    key_type = "sodium11-ed25519"
    cipher = "ChaCha20"
    ops_limit = 33554432
    mem_limit = 1073741824


class ChaCha20Blake2bHMAC(object):
    @classmethod
    def new(cls, key, nonce):
        return cls(key=key, nonce=nonce)

    def __init__(self, key, nonce):
        cipher_nonce = BLAKE2b.new(digest_bits=64, key=key)
        cipher_nonce.update(nonce)
        cipher_nonce = cipher_nonce.digest()

        self.cipher = ChaCha20.new(key=key, nonce=cipher_nonce)
        self.blake = BLAKE2b.new(digest_bits=512, key=key)
        self.blake.update(cipher_nonce)

    def update(self, plaintext):
        """Protect associated data, must be called before encrypt() or decrypt()."""
        self.blake.update(plaintext)

    def encrypt(self, plaintext):
        ciphertext = self.cipher.encrypt(plaintext)
        self.blake.update(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext):
        self.blake.update(ciphertext)
        plaintext = self.cipher.decrypt(ciphertext)
        return plaintext

    def digest(self):
        return self.blake.digest()

    def hexdigest(self):
        return self.blake.hexdigest()

    def verify(self, digest):
        """Validate the HMAC."""
        return nacl.bindings.sodium_memcmp(bytes(self.digest()), bytes(digest))

    def hexverify(self, hexdigest):
        """Validate the HMAC."""
        return nacl.bindings.sodium_memcmp(bytes(self.hexdigest()), bytes(hexdigest))


def dummy_tqdm(*args, **kwargs):
    class DummyTqdm(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def update(self, *args, **kwargs):
            pass

    return DummyTqdm()


def dummy_for_writing(*args, **kwargs):
    class DummyTqdm(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def write(self, *args, **kwargs):
            pass

    return DummyTqdm()


def shorten_filename(filename):
    """
    Shorten a filename.

    >>> shorten_filename("verylongfilename.txt")
    'ver~longfilename.txt'
    """
    f = os.path.split(filename)[1]
    return "%s~%s" % (f[:3], f[-16:]) if len(f) > 19 else f


def pack_128bit_long(l):
    if l > MAX_INT128:
        raise Sodium11Error("pack_128bit_long value too large")
    return struct.pack('>QQ', (l >> 64) & MAX_INT64, l & MAX_INT64)


def unpack_128bit_long(bstr):
    q1, q2 = struct.unpack('>QQ', bstr)
    return (q1 << 64) | q2


def pack_bytes(msg, msg_length):
    if msg_length > 255:
        raise Sodium11Error("Cannot pack more then 255 bytes at once")

    if len(msg) > msg_length:
        raise Sodium11Error("Message is longer then pack length")

    return struct.pack("%dp" % (msg_length + 1), msg)


def unpack_bytes(msg, msg_length):
    if msg_length > 255:
        raise Sodium11Error("Cannot pack more then 255 bytes at once")
    if not len(msg) == msg_length + 1:
        raise Sodium11Error("Message is not %d bytes of length (found %d bytes)" % (msg_length + 1, len(msg)))

    unpacked_msg = struct.unpack("%dp" % (msg_length + 1), msg)
    if len(unpacked_msg) != 1:
        raise Sodium11Error("Unpacking failed")
    return unpacked_msg[0]


pack_64bytes = partial(pack_bytes, msg_length=64)
pack_32bytes = partial(pack_bytes, msg_length=32)
pack_16bytes = partial(pack_bytes, msg_length=16)
unpack_64bytes = partial(unpack_bytes, msg_length=64)
unpack_32bytes = partial(unpack_bytes, msg_length=32)
unpack_16bytes = partial(unpack_bytes, msg_length=16)


def pem_encode(*args):
    r = ""
    for a in args:
        if not isinstance(a, bytes):
            raise Sodium11Error("pem_encode value invalid type: %s" % type(a))
        r += struct.pack('>I', len(a))
        r += a
    return base64.b64encode(r)


def pem_decode(pem_data):
    pem_data = base64.b64decode(pem_data)
    parts = []
    while pem_data:
        l = struct.unpack('>I', pem_data[:4])[0] + 4
        d, pem_data = pem_data[4:l], pem_data[l:]
        parts.append(d)
    return parts


@contextmanager
def open_for_writing(filename, permissions=None):
    if permissions is None:
        permissions = stat.S_IRUSR | stat.S_IWUSR

    umask_original = os.umask(0)
    try:
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, permissions)
    finally:
        os.umask(umask_original)

    # Open file handle and write to file
    with os.fdopen(fd, 'w') as f:
        yield f


def save_public_keyfile(public_keyfile, public_key):
    if not isinstance(public_key, nacl.signing.VerifyKey):
        raise Sodium11Error("public_key is not of class nacl.signing.VerifyKey")

    comment = platform.node()
    public_key_raw = public_key.encode(encoder=nacl.encoding.RawEncoder)
    if public_key_raw == SECRET_SENDER_PUBLICKEY_MARKER:
        raise Sodium11Error("Public key encodes to sender publickey marker")
    pub_pem_data = pem_encode(Version100.key_type, Version100.version_str(), public_key_raw)

    with open_for_writing(public_keyfile, permissions=0o644) as f:
        f.write("%s %s %s\n" % (Version100.key_type, pub_pem_data, comment))


def save_private_keyfile(private_keyfile, private_key, passphrase):
    if not isinstance(private_key, nacl.signing.SigningKey):
        raise Sodium11Error("private_key is not of class nacl.signing.SigningKey")

    salt = nacl.utils.random(nacl.pwhash.SCRYPT_SALTBYTES)
    key = nacl.pwhash.kdf_scryptsalsa208sha256(
        nacl.secret.SecretBox.KEY_SIZE,
        bytes(passphrase),
        salt,
        opslimit=Version100.ops_limit,
        memlimit=Version100.mem_limit,
    )
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(private_key.encode(encoder=nacl.encoding.RawEncoder), nonce)
    prv_pem_data = pem_encode(Version100.key_type, Version100.version_str(), salt, ciphertext)

    with open_for_writing(private_keyfile, permissions=0o600) as f:
        f.write('-----BEGIN SODIUM11 PRIVATE KEY-----\n')
        f.write(prv_pem_data + "\n")
        f.write('-----END SODIUM11 PRIVATE KEY-----\n')


def load_public_keyfile(public_keyfile):
    with open(public_keyfile, "r") as f:
        key_type, pem_data = f.read(1024).split(None)[:2]

    pem_data = pem_decode(pem_data)
    if not pem_data[0] == Version100.key_type:
        raise Sodium11Error("Invalid Sodium11 public key file version, only key type %s is supported" % Version100.key_type)
    if not pem_data[1] == Version100.version_str():
        raise Sodium11Error("Invalid Sodium11 public key file version, only version %s is supported" % Version100.version_str())

    pem_key_type, public_key = pem_data[0], pem_data[2]
    if pem_key_type != key_type:
        raise Sodium11PublicKeyfileError("Key type difference")

    return nacl.signing.VerifyKey(public_key)


def load_private_keyfile(private_keyfile, passphrase):
    with open(private_keyfile, "r") as f:
        lines = f.read(1024).strip().split("\n")

    if not len(lines) == 3 or \
            not lines[0] == '-----BEGIN SODIUM11 PRIVATE KEY-----' or \
            not lines[-1] == '-----END SODIUM11 PRIVATE KEY-----':
        raise Sodium11Error("Invalid Sodium11 private key file")

    pem_data = pem_decode(lines[1])
    if not pem_data[0] == Version100.key_type:
        raise Sodium11Error("Invalid Sodium11 private key file version, only key type %s is supported" % Version100.key_type)
    if not pem_data[1] == Version100.version_str():
        raise Sodium11Error("Invalid Sodium11 private key file version, only version %s is supported" % Version100.version_str())

    salt, ciphertext = pem_data[2], pem_data[3]

    key = nacl.pwhash.kdf_scryptsalsa208sha256(
        nacl.secret.SecretBox.KEY_SIZE,
        bytes(passphrase),
        salt,
        opslimit=Version100.ops_limit,
        memlimit=Version100.mem_limit,
    )
    box = nacl.secret.SecretBox(key)
    try:
        plaintext = box.decrypt(ciphertext)
    except nacl.exceptions.CryptoError:
        raise Sodium11Error("Private key failed to decrypt, did you specify the correct passphrase ?")
    private_key = nacl.signing.SigningKey(plaintext)

    return private_key


def devired_key(k, salt=None):
    if salt and not len(salt) == nacl.hash.BLAKE2B_SALTBYTES:
        raise Sodium11Error("Salt has invalid length")
    derivation_salt = salt if salt is not None else nacl.utils.random(nacl.hash.BLAKE2B_SALTBYTES)
    d = nacl.hash.blake2b(
        b'',
        key=k,
        salt=derivation_salt,
        person=b'<Sodium11>',
        encoder=nacl.encoding.RawEncoder
    )
    return d, derivation_salt


def _get_hash_types():
    hash_types = OrderedDict()
    if 'md5' in hashlib.algorithms:
        hash_types['MD5'] = hashlib.md5
    if 'sha1' in hashlib.algorithms:
        hash_types['SHA1'] = hashlib.sha1
    if 'sha256' in hashlib.algorithms:
        hash_types['SHA256'] = hashlib.sha256
    if 'sha512' in hashlib.algorithms:
        hash_types['SHA512'] = hashlib.sha512

    hash_types['BLAKE2b_256'] = partial(BLAKE2b.new, digest_bits=256)
    hash_types['BLAKE2b_512'] = partial(BLAKE2b.new, digest_bits=512)
    hash_types['RIPEMD160'] = RIPEMD160.new
    # The ones from hashlib are faster
    # hash_types['MD5'] = MD5.new
    # hash_types['SHA1'] = SHA1.new
    # hash_types['SHA256'] = SHA256.new
    # hash_types['SHA512'] = SHA512.new
    hash_types['SHA3_256'] = SHA3_256.new
    hash_types['SHA3_512'] = SHA3_512.new
    hash_types['keccak_256'] = partial(keccak.new, digest_bits=256)
    hash_types['keccak_512'] = partial(keccak.new, digest_bits=512)

    return hash_types


HASH_TYPES = _get_hash_types()


def _get_cipher_types():
    cipher_types = {}
    cipher_types["ChaCha20Blake2b"] = ChaCha20Blake2bHMAC
    cipher_types["AES-EAX"] = partial(AES.new, mode=AES.MODE_EAX)
    cipher_types["AES-GCM"] = partial(AES.new, mode=AES.MODE_GCM)
    return cipher_types


CIPHER_TYPES = _get_cipher_types()


def benchmark_hashtypes(hash_types, bufsize=1024*1024, count=512):
    block = nacl.utils.random(bufsize)
    if not hash_types:
        hash_types = HASH_TYPES.keys()

    l = max(len(e) for e in hash_types)
    format_desc = "%%%ds" % l

    for hash_type in hash_types:
        hsh = HASH_TYPES[hash_type]()
        with tqdm(total=bufsize * count, unit="B", unit_scale=True, desc=format_desc % hash_type) as pbar:
            for i in xrange(count):
                hsh.update(block)
                pbar.update(bufsize)


@click.group(context_settings={
    'help_option_names': ['-h', '--help'],
})
@click.pass_context
def cli(ctx):
    """A command line toolkit for encryption and signing of files based on libsodium."""
    pass


@cli.command(name='generate-key')
@click.option('--key-file', '-k', envvar='SODIUM11_KEY_FILE', default=DEFAULT_KEYPATH, prompt='Enter file in which to save the key')
@click.option('--passphrase', '-p', envvar='SODIUM11_PASSPHRASE', prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def cli_generate_key(ctx, key_file, passphrase):
    """Generate Public and Private Keys."""
    if os.path.isfile(key_file):
        raise click.UsageError("%s already exists." % key_file)

    key_file_pub = "%s.pub" % key_file
    if os.path.isfile(key_file_pub):
        raise click.UsageError("%s already exists." % key_file_pub)

    if len(passphrase) < 8:
        raise click.UsageError("Passphrase too short")

    key_file_dir = os.path.dirname(key_file)
    if not os.path.isdir(key_file_dir):
        os.mkdir(key_file_dir, 0700)

    if not os.access(key_file_dir, os.W_OK):
        raise click.UsageError("Directory '%s' not read and writeable" % key_file_dir)

    output_file_dir_stat = os.stat(key_file_dir).st_mode
    if output_file_dir_stat & stat.S_IRWXG:
        raise click.UsageError("Directory '%s' has group permissions and is insecure" % key_file_dir)
    if output_file_dir_stat & stat.S_IRWXO:
        raise click.UsageError("Directory '%s' has other permissions and is insecure" % key_file_dir)

    p = nacl.signing.SigningKey.generate()

    save_public_keyfile(key_file_pub, p.verify_key)
    save_private_keyfile(key_file, p, passphrase)


@cli.command(name='verify-hash')
@click.argument('filename', nargs=-1, type=click.File('rb'), required=True)
@click.option('--progress/--no-progress', '-p/-np', default=None, help='Show progress indicator')
@click.option('--fail-fast', '-f', default=False, is_flag=True, help="Fail command directly when error is detected")
@click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
@click.pass_context
def cli_verify_hash(ctx, filename, progress, fail_fast, leave_progress_bar):
    """Verify hash for file(s)."""

    files = []
    for f in filename:
        if not f.readline().strip() == SODIUM11_HEADER_HASHES:
            click.secho("%s is not a Sodium11 hash output file" % (f.name, ), fg='red')
            continue
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h, filename = line.split("  ", 1)
            hash_name, hash_hexdigest = h.split("=")
            if not os.path.isfile(filename):
                msg = "File does not exists: %s" % filename
                if fail_fast:
                    raise click.ClickException(msg)
                click.secho(msg, fg='red')
                continue
            files.append((filename, hash_name, hash_hexdigest))
        f.close()

    if progress is None:
        progress = sys.stdout.isatty()
    progress_indicator = tqdm if progress else dummy_tqdm
    failed = ""

    for filename, hash_name, hash_hexdigest in files:
        hsh = HASH_TYPES[hash_name]()
        with progress_indicator(total=os.path.getsize(filename), unit="B", unit_scale=True, desc=shorten_filename(filename), leave=leave_progress_bar) as pbar:
            with open(filename, "r") as f:
                while True:
                    block = f.read(BUFSIZE)
                    if not block:
                        break
                    hsh.update(block)
                    pbar.update(len(block))
        if hsh.hexdigest() == hash_hexdigest:
            click.secho("OK: %s %s" % (hash_name, filename), fg='green')
        else:
            msg = "FAILED: %s %s" % (hash_name, filename)
            failed = True
            if fail_fast:
                raise click.ClickException(msg)
            else:
                click.secho(msg, fg='red')
    if failed:
        raise click.ClickException("(Some) files failed to verify the hash")


@cli.command(name='hash')
@click.argument('filename', nargs=-1, type=click.File('rb'), required=True)
@click.option('--output-file', '-o', envvar='SODIUM11_OUTPUT_FILE', type=click.File('w'), default=None, help="File to write hash digests")
@click.option('--persist', '-p', default=False, is_flag=True, help="Persist hash digest to disk, writes .s1x file (not compatible with --output-file)")
@click.option('--force/--no-force', '-f', default=False, is_flag=True, help="Overwrite the output file if it already exists")
@click.option('--hash-type', '-t', type=click.Choice(HASH_TYPES.keys()), multiple=True, help="Type of hash algoritm(es) to use. Can be specified multiple times. (Default is SHA1)")
@click.option('--benchmark', default=False, is_flag=True, help="Benchmark the hash algoritmes")
@click.option('--progress/--no-progress', default=None, help='Show progress indicator')
@click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
@click.pass_context
def cli_hash(ctx, filename, output_file, persist, force, hash_type, benchmark, progress, leave_progress_bar):
    """Generate hash for file(s)."""
    if benchmark:
        return benchmark_hashtypes(hash_type)

    if output_file and not force and os.path.isfile(output_file.name):
        raise click.UsageError("Output file '%s' already exists" % output_file.name)

    if not hash_type:
        hash_type = ('SHA1', )

    if output_file and persist:
        raise click.UsageError("Cannot out --output-file and --persist at the same time")

    if not output_file:
        output_file = sys.stdout
    else:
        output_file.write(SODIUM11_HEADER_HASHES + "\n")

    if progress is None:
        progress = sys.stdout.isatty()
    progress_indicator = tqdm if progress else dummy_tqdm

    for f in filename:
        hshs = [HASH_TYPES[e]() for e in hash_type]
        with progress_indicator(total=os.path.getsize(f.name), unit="B", unit_scale=True, desc=shorten_filename(f.name), leave=leave_progress_bar) as pbar:
            while True:
                block = f.read(BUFSIZE)
                if not block:
                    break
                for hsh in hshs:
                    hsh.update(block)
                pbar.update(len(block))
        lines = ""
        for name, hsh in zip(hash_type, hshs):
            lines += "%s=%s  %s\n" % (name, hsh.hexdigest(), f.name)

        if persist:
            with open_for_writing(f.name + ".s1x") as wf:
                wf.write("# Sodium11 File Hashes\n")
                wf.write(lines)
        else:
            output_file.write(lines)
            output_file.flush()
        f.close()


@cli.command(name='encrypt')
@click.argument('filename', nargs=-1, type=click.File('rb'), required=True)
@click.option('--public-keyfile', '-i', envvar='SODIUM11_PUBLIC_KEY', default=DEFAULT_KEYPATH_PUB, help="Receiver public key file")
@click.option('--key-file', '-k', envvar='SODIUM11_KEY_FILE', default=DEFAULT_KEYPATH, help="Receiver private key file (only needed for verify)")
@click.option('--passphrase', '-p', envvar='SODIUM11_PASSPHRASE', default=None, help="Receiver private key passphrase")
@click.option('--include-sender-pubkey/--no-sender-pubkey', default=True, help="Add sender public key in encrypted file (Default is yes)")
@click.option('--verify/--no-verify', default=False, help="Verify the result")
@click.option('--keep/--no-keep', default=False, help='Keep the original file(s), default is to remove source files.')
@click.option('--progress/--no-progress', default=None, help='Show progress indicator')
@click.option('--sender-key-file', '-s', envvar='SODIUM11_SENDER_KEY_FILE', default=None, help="Sender private key file (optional)")
@click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
@click.option('--cipher-type', '-c', default="ChaCha20Blake2b", type=click.Choice(CIPHER_TYPES.keys()), help="Type of cipher to use. (Default is ChaCha20Blake2b)")
@click.option('--sender-passphrase', envvar='SODIUM11_SENDER_PASSPHRASE', default=None, help="Sender private key passphrase")
@click.pass_context
def cli_encrypt(ctx, filename, public_keyfile, key_file, passphrase, include_sender_pubkey, verify, keep, progress, sender_key_file, leave_progress_bar, cipher_type, sender_passphrase):
    """Encrypt file(s) with public key."""

    if verify and not os.path.isfile(key_file):
        raise click.UsageError("Private keyfile '%s' doet not exist" % key_file)

    if verify and passphrase is None:
        passphrase = click.prompt('Passphrase', hide_input=True)

    if sender_key_file and sender_passphrase is None:
        sender_passphrase = click.prompt('Sender Passphrase', hide_input=True)

    if cipher_type not in CIPHER_TYPES:
        raise click.UsageError("Cipher type '%s' does not exist" % cipher_type)

    if progress is None:
        progress = sys.stdout.isatty()

    progress_indicator = tqdm if progress else dummy_tqdm

    r_pub = load_public_keyfile(public_keyfile)
    r_pub_curve = r_pub.to_curve25519_public_key()

    if sender_key_file:
        _s_prv = load_private_keyfile(sender_key_file, sender_passphrase)
    else:
        _s_prv = None

    for f in filename:
        flags = 0  # integer used for specifying flags in file header

        s_prv = _s_prv if _s_prv else nacl.signing.SigningKey.generate()
        s_pub = s_prv.verify_key
        s_prv_curve = s_prv.to_curve25519_private_key()
        # s_pub_curve = s_pub.to_curve25519_public_key()

        box = nacl.public.Box(s_prv_curve, r_pub_curve)
        shared_key = box.shared_key()

        cipher_key_nonce = nacl.utils.random(32)
        cipher_key, cipher_key_salt = devired_key(cipher_key_nonce + shared_key)
        cipher_nonce = nacl.utils.random(32)

        aead_cipher = CIPHER_TYPES[cipher_type](key=cipher_key, nonce=cipher_nonce)

        output_filename = f.name + ".s11"
        with open_for_writing(output_filename) as wf:
            wf.write("_" * Version100.prefix_size)

            file_size = 0
            encrypted_file_size = 0
            with progress_indicator(total=os.path.getsize(f.name), unit="B", unit_scale=True, desc=shorten_filename(f.name), leave=leave_progress_bar) as pbar:
                while True:
                    block = f.read(BUFSIZE)
                    if not block:
                        break
                    block_size = len(block)
                    file_size += block_size
                    encrypted_block = aead_cipher.encrypt(block)
                    encrypted_file_size += len(encrypted_block)
                    wf.write(encrypted_block)
                    pbar.update(block_size)

            cipher_digest = aead_cipher.digest()
            version_and_flags = struct.pack(">II", flags, Version100.version)
            sender_pubkey_str = s_pub.encode(encoder=nacl.encoding.RawEncoder) if include_sender_pubkey else SECRET_SENDER_PUBLICKEY_MARKER

            metadata = [
                Version100.version_str(),                           # version string (8 bytes)
                pack_128bit_long(encrypted_file_size),              # file_size (16 bytes)
                pack_16bytes(cipher_type),                          # cipher type (17 bytes)
                pack_32bytes(cipher_key_nonce),                     # cipher key nonce (33 bytes)
                pack_16bytes(cipher_key_salt),                      # cipher key salt (17 bytes)
                pack_32bytes(cipher_nonce),                         # cipher nonde (33 bytes)
                pack_64bytes(cipher_digest),                        # cipher digest (65 bytes)
            ]
            encrypted = box.encrypt(''.join(metadata))              # encrypted (212 bytes)

            filestart = []
            filestart.append("s11x")                                # id (4 bytes)
            filestart.append(version_and_flags)                     # version (8 bytes)
            # NOTE: double check; we don't need to hash the pubkey here and put it in metadata to verify ?
            filestart.append(sender_pubkey_str)
            filestart.append(encrypted)
            signature = s_prv.sign(''.join(filestart)).signature
            filestart.append(signature)       # signature (64 bytes)

            filestart = ''.join(filestart)
            if len(filestart) != Version100.prefix_size:
                raise Sodium11Error("File header is not %d bytes long (found %s bytes)" % (Version100.prefix_size, len(filestart)))

            wf.seek(0)
            wf.write(filestart)
            wf.flush()
        f.close()

        if verify:
            ed_prv = load_private_keyfile(key_file, passphrase)

            sender_pubkey = None
            if sender_key_file:
                sender_pubkey = load_public_keyfile(sender_key_file + ".pub")

            with open(output_filename, "r") as encrypted_fh:
                _decrypt(
                    f=encrypted_fh,
                    ed_prv=ed_prv,
                    sender_pubkey=sender_pubkey,
                    verify=True,
                    progress=progress,
                    leave_progress_bar=leave_progress_bar,
                    output_filename=None,
                )

        if not keep:
            os.unlink(f.name)


@cli.command(name='decrypt')
@click.argument('filename', nargs=-1, type=click.File('rb'), required=True)
@click.option('--key-file', '-k', envvar='SODIUM11_KEY_FILE', default=DEFAULT_KEYPATH, help="Receiver private key file")
@click.option('--passphrase', '-p', envvar='SODIUM11_PASSPHRASE', prompt=True, hide_input=True)
@click.option('--public-keyfile', '-i', envvar='SODIUM11_SENDER_PUBLIC_KEY', default=None, help="Sender public key file")
@click.option('--verify/--no-verify', default=False, help="Only verify don't store decrypted file")
@click.option('--keep/--no-keep', default=False, help='Keep the encrypted file(s), default is to remove encrypted files.')
@click.option('--progress/--no-progress', default=None, help='Show progress indicator')
@click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
@click.pass_context
def cli_decrypt(ctx, filename, key_file, passphrase, public_keyfile, verify, keep, progress, leave_progress_bar):
    """Decrypt file(s) with private key."""
    ed_prv = load_private_keyfile(key_file, passphrase)

    sender_pubkey = None
    if public_keyfile:
        sender_pubkey = load_public_keyfile(public_keyfile)

    if progress is None:
        progress = sys.stdout.isatty()

    for fh in filename:
        if not fh.name.endswith(".s11"):
            # TODO: implement output-filename as cli option
            raise click.UsageError("File '%s' does not end with .s11" % fh.name)
        output_filename = fh.name[:-4]

        _decrypt(
            f=fh,
            ed_prv=ed_prv,
            sender_pubkey=sender_pubkey,
            verify=verify,
            progress=progress,
            leave_progress_bar=leave_progress_bar,
            output_filename=output_filename,
        )
        fh.close()
        if verify is False and not keep:
            os.unlink(fh.name)


def _decrypt(f, ed_prv, sender_pubkey, verify, progress, leave_progress_bar, output_filename):
    progress_indicator = tqdm if progress else dummy_tqdm
    filesize = os.path.getsize(f.name)

    def header_check(f, sender_pubkey):
        _magic_header = f.read(4)
        if _magic_header != "s11x":
            raise click.UsageError("File '%s' is not a Sodium11 Encrypted file" % f.name)

        _flags, _version = struct.unpack(">II", f.read(8))
        if _flags != 0:
            raise click.UsageError("File '%s' has invalid flags" % f.name)

        if _version != 100:
            raise click.UsageError("File '%s' has invalid version" % f.name)

        _sender_pubkey = f.read(32)
        if _sender_pubkey == SECRET_SENDER_PUBLICKEY_MARKER and not sender_pubkey:
            raise click.UsageError("File '%s' needs --public-keyfile to specify sender pubkey" % f.name)

        if _sender_pubkey != SECRET_SENDER_PUBLICKEY_MARKER and not sender_pubkey:
            # use sender public key from encrypted file if none is given from the cli
            sender_pubkey = nacl.signing.VerifyKey(_sender_pubkey, encoder=nacl.encoding.RawEncoder)

        _raw_metadata = f.read(229)
        return _version, sender_pubkey, _raw_metadata
    _version, sender_pubkey, _raw_metadata = header_check(f, sender_pubkey)

    _signature = f.read(64)
    f.seek(0)

    with progress_indicator(total=filesize, unit="B", unit_scale=True, desc=shorten_filename(f.name), leave=leave_progress_bar) as pbar:
        filestart = f.read(Version100.prefix_size)
        pbar.update(Version100.prefix_size)
        if len(filestart) != Version100.prefix_size:
            raise click.UsageError("File '%s' is too short to be Sodium11 Encrypted file" % f.name)

        filestart = sender_pubkey.verify(filestart[:Version100.prefix_size - 64], _signature)
        _version, sender_pubkey, _raw_metadata = header_check(StringIO(filestart), sender_pubkey)

        s_pub_curve = sender_pubkey.to_curve25519_public_key()
        r_prv_curve = ed_prv.to_curve25519_private_key()

        box = nacl.public.Box(r_prv_curve, s_pub_curve)
        metadata_io = StringIO(box.decrypt(_raw_metadata))

        version = int(metadata_io.read(8))
        enc_filesize = unpack_128bit_long(metadata_io.read(16))
        cipher_type = unpack_16bytes(metadata_io.read(17))
        cipher_key_nonce = unpack_32bytes(metadata_io.read(33))
        cipher_key_salt = unpack_16bytes(metadata_io.read(17))
        cipher_nonce = unpack_32bytes(metadata_io.read(33))
        cipher_digest = unpack_64bytes(metadata_io.read(65))

        if version != _version:
            raise click.UsageError("File '%s' metadata version does not match version in header" % f.name)

        if filesize != Version100.prefix_size + enc_filesize:
            raise click.UsageError("File '%s' metadata size does not match filesize" % f.name)

        if cipher_type not in CIPHER_TYPES:
            raise click.UsageError("File '%s' unknown cipher type '%s'" % (f.name, cipher_type))

        shared_key = box.shared_key()
        cipher_key, _ = devired_key(cipher_key_nonce + shared_key, salt=cipher_key_salt)

        aead_cipher = CIPHER_TYPES[cipher_type](key=cipher_key, nonce=cipher_nonce)

        filewrite_ctx_manager = dummy_for_writing if verify else open_for_writing

        with filewrite_ctx_manager(output_filename) as pf:
            while True:
                block = f.read(BUFSIZE)
                if not block:
                    break
                block_size = len(block)
                plain_block = aead_cipher.decrypt(block)
                pf.write(plain_block)
                pbar.update(block_size)

        if cipher_digest != aead_cipher.digest():
            raise click.UsageError("File '%s' failed checksum '%s' != '%s'" % (f.name, cipher_digest, aead_cipher.digest()))


# @cli.command(name='encode-rs')
# @click.argument('filename', nargs=-1, type=click.File('rb'), required=True)
# @click.option('--verify/--no-verify', default=False, help="Verify result")
# @click.option('--keep/--no-keep', default=False, help='Keep the source file(s), default is to remove source files.')
# @click.option('--progress/--no-progress', default=None, help='Show progress indicator')
# @click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
# @click.option('--errasure-type', default="jerasure_rs_vand", type=click.Choice(ERRASURE_TYPES), help="Type of errasurecode to use. (Default is jerasure_rs_vand)")
# @click.pass_context
# def cli_encode_rs(ctx, filename, verify, keep, progress, leave_progress_bar, errasure_type):
#     """Encode file(s) with reed solomon encoding. (It's recommended to use PAR2 though.)"""

#     #
#     # Serious problem we have is that encoding the reed-solomon archives gets messed up easily
#     # when the file get scrambled... We can protect against bit flips easily but once alignment
#     # screws up we lose everything. To project against that we write out k + m number of files.
#     # now we can survive bit flips and size corruption up to 3 files.
#     #

#     #
#     # Another issue with chunking is that when the fragment headers are corrupted we get a hard
#     # time to reconstruct the file.
#     #

#     #
#     # TODO: While corrupting one of the fragment files on purpose the decode-rs restore pass yieled
#     #       the wrong file ! Need to fix this... for now commenting out the RS commands.
#     #

#     if not HAS_PYECLIB:
#         raise click.UsageError("Please install pyeclib. (pip install pyeclib)")

#     if progress is None:
#         progress = sys.stdout.isatty()

#     progress_indicator = tqdm if progress else dummy_tqdm

#     # about 20% recovery data
#     k = 12
#     m = 3
#     km = k + m
#     segment_size = 1*1024*1024  # 64MB means we can tolerate 1mb * 3 consequative lost data
#     fragment_size = 87462  # fragment size except last one ( ec.get_segment_info(200*1024*1025, segment_size) )

#     if verify:
#         source_hsh = hashlib.sha1()

#     for f in filename:
#         ec = ECDriver(k=k, m=m, ec_type=errasure_type)

#         segment_files = [f.name + ".s11rs.part%d" % (i + 1) for i in xrange(km)]

#         for segment_file in segment_files:
#             with open_for_writing(segment_file) as wf:
#                 pass

#         wfs = [open(segment_file, "w") for segment_file in segment_files]
#         with progress_indicator(total=os.path.getsize(f.name), unit="B", unit_scale=True, desc=shorten_filename(f.name), leave=leave_progress_bar) as pbar:
#             while True:
#                 block = f.read(segment_size)
#                 if not block:
#                     break
#                 if verify:
#                     source_hsh.update(block)
#                 block_size = len(block)
#                 fragments = ec.encode(block)
#                 for i in xrange(km):
#                     wfs[i].write(fragments[i])
#                 pbar.update(block_size)
#         for wf in wfs:
#             wf.close()

#         if len(set(os.path.getsize(segment_file) for segment_file in segment_files)) != 1:
#             raise Sodium11Error("Not all segment files are equal in length")

#         if verify:
#             verify_hsh = hashlib.sha1()
#             filesizes = [os.path.getsize(segment_file) for segment_file in segment_files]
#             if len(set(filesizes)) != 1:
#                 raise Sodium11Error("Not all segment files are equal in length")
#             wfs = [open(segment_file, "r") for segment_file in segment_files]
#             total_size = filesizes[0] * km
#             with progress_indicator(total=total_size, unit="B", unit_scale=True, desc=shorten_filename(f.name), leave=leave_progress_bar) as pbar:
#                 while True:
#                     blocks = [wf.read(fragment_size) for wf in wfs]
#                     total_len = sum(len(e) for e in blocks)
#                     if total_len == 0:
#                         break
#                     source_data = ec.decode(blocks, force_metadata_checks=True)
#                     verify_hsh.update(source_data)
#                     pbar.update(total_len)

#             for wf in wfs:
#                 wf.close()

#             if source_hsh.hexdigest() != verify_hsh.hexdigest():
#                 raise Sodium11Error("Source and Verification Hash mismatched")

#         if not keep:
#             os.unlink(f.name)


# @cli.command(name='decode-rs')
# @click.argument('filename', nargs=-1, type=click.Path(exists=True), required=True)
# @click.option('--keep/--no-keep', default=False, help='Keep the source file(s), default is to remove source files.')
# @click.option('--progress/--no-progress', default=None, help='Show progress indicator')
# @click.option('--leave-progress-bar', default=False, is_flag=True, help="Leave progress bar on terminal")
# @click.option('--errasure-type', default="jerasure_rs_vand", type=click.Choice(ERRASURE_TYPES), help="Type of errasurecode to use. (Default is jerasure_rs_vand)")
# @click.pass_context
# def cli_decode_rs(ctx, filename, keep, progress, leave_progress_bar, errasure_type):
#     """Decode file(s) with reed solomon encoding. (It's recommended to use PAR2 though.)"""

#     if not HAS_PYECLIB:
#         raise click.UsageError("Please install pyeclib. (pip install pyeclib)")

#     if progress is None:
#         progress = sys.stdout.isatty()

#     progress_indicator = tqdm if progress else dummy_tqdm

#     # about 20% recovery data
#     k = 12
#     m = 3
#     km = k + m
#     segment_size = 1*1024*1024  # 64MB means we can tolerate 1mb * 3 consequative lost data
#     fragment_size = 87462  # fragment size except last one ( ec.get_segment_info(200*1024*1025, segment_size) )

#     filenames = []
#     for f in filename:
#         if 's11rs.part' in f:
#             f = f.split('.s11rs.part', 1)[0]
#             if f not in filenames:
#                 for i in xrange(km):
#                     part_filename = f + ".s11rs.part%d" % (i + 1)
#                     if not os.path.isfile(part_filename):
#                         click.secho("%s not found" % part_filename, fg='red')
#                         return
#                 filenames.append(f)

#     for f in filenames:
#         ec = ECDriver(k=k, m=m, ec_type=errasure_type)

#         segment_files = [f + ".s11rs.part%d" % (i + 1) for i in xrange(km)]

#         filesizes = [os.path.getsize(segment_file) for segment_file in segment_files]
#         if len(set(filesizes)) != 1:
#             raise Sodium11Error("Not all segment files are equal in length")
#         wfs = [open(segment_file, "r") for segment_file in segment_files]
#         total_size = filesizes[0] * km

#         with open_for_writing(f) as sf:
#             with progress_indicator(total=total_size, unit="B", unit_scale=True, desc=shorten_filename(f), leave=leave_progress_bar) as pbar:
#                 while True:
#                     blocks = [wf.read(fragment_size) for wf in wfs]
#                     total_len = sum(len(e) for e in blocks)
#                     if total_len == 0:
#                         break
#                     source_data = ec.decode(blocks)  # , force_metadata_checks=True)
#                     sf.write(source_data)
#                     pbar.update(total_len)

#         for wf in wfs:
#             wf.close()

#         if not keep:
#             for segment_file in segment_files:
#                 os.unlink(segment_file)
