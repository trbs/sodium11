from sodium11 import cli
from .utils import common_asserts

TEST_FILES = [
    ("zeros_16MB.dat", "MD5", "50838bbf29aec4c6e62bee320d5c9138"),
    ("zeros_16MB.dat", "SHA1", "4fd1525074dff79cd0d4d5b36239f94f8ecbbc79"),
    ("zeros_16MB.dat", "BLAKE2b_512", "8792c33e91db780ca2508d557095f7a3906ba86070ce625d155997d8d1a90829d75d7073a3cb529f50c652db380dba8b0574f7a7f33620dffcc29ab06a6fe770"),
    ("zeros_16MB.dat", "SHA3_512", "cb225ee4f37dbb0ec33ba814dfeefbbba372ee93b3e6dd0db48ad8a239117c64e02a2ca71938b2d597a4648ef455915391c76c36e8fba90e264bb11f50c94e2a"),
    ("zeros_32MB.dat", "MD5", "cbe9e6d3492cfd5ec666602628396bb6"),
    ("zeros_32MB.dat", "SHA1", "53a9d7834c28444947c866064ab0e3c537ca0732"),
    ("zeros_32MB.dat", "BLAKE2b_512", "84be3c85c9132a39a6bfe1443b706de4a4cd882f5ad3ea359b3cda4e2d90695855aa2a62eef8b4de9c0b6db4bc4bade78c37e333b2f0301ed3c3276cf1f2e136"),
    ("zeros_32MB.dat", "SHA3_512", "87ed3aeda8a147d8394fe58fa06f2ccdc314cd6f3111086a40606e014d00b7134681b17bf87e0fadc89942ab474706d9c68f6e51393ecb08ee6f472b5e35b8eb"),
    ("repeat_16MB.dat", "MD5", "c17ce15165515484844a69a765d89808"),
    ("repeat_16MB.dat", "SHA1", "a6005408dfd34b7d6c93e96d51d89808c9159f25"),
    ("repeat_16MB.dat", "BLAKE2b_512", "c5f3bf2e04f538a636d6e97b21b021c0714da188317309c32b1319710de82f0f20e7aa73066d511759b862b670a517c64abd55041b532a72c31d6db3ce124938"),
    ("repeat_16MB.dat", "SHA3_512", "d692f5b61012927d232e4607613558ecc92a09fdc47c3df2557d8828861385ca0522ba6bdf5611e7a0b24f1caf5ff5dfed9e7a95ccfd45c1545047ace4b2a543"),
    ("bin_1MB.dat", "MD5", "5feffde334fc829b0fe27f185b04fdb7"),
    ("bin_1MB.dat", "SHA1", "daa342153ff05a6aa0f5c11965601c6bedda2803"),
    ("bin_1MB.dat", "BLAKE2b_512", "096bb937e5f9038b27c51c538b5f1fe5efce7ca363df23ded6c2d88855c32f7e0e8c3419a758e375347f3b5649b9dee2443bc3665f412dd7b6be37d03f8adccc"),
    ("bin_1MB.dat", "SHA3_512", "faa7afb6adb1dc38411114f347e1051efb669a2e9698ffde22b10dd57f201d32977df6cd3a2f7918ea78a9b71cbc54a78e6e8217fcc04c9b69eba023871269a9"),
]


def test_cli_hash_single_hashtype(runner_factory):
    with runner_factory() as runner:
        cli_args = ["hash"]
        files = []
        hash_types = []
        hash_map = {}
        for filename, hsh, hsh_value in TEST_FILES:
            if filename not in files:
                files.append(filename)
            if hsh not in hash_types:
                cli_args.append("-t")
                cli_args.append(hsh)
                hash_types.append(hsh)
            if (filename, hsh) in hash_map:
                raise Exception("Duplicate hash value found.")
            hash_map[(filename, hsh)] = hsh_value
        cli_args.extend(files)

        result = runner.invoke(cli, cli_args, catch_exceptions=False)
        common_asserts(result)

        output = ""
        for filename in files:
            for hsh in hash_types:
                hsh_value = hash_map[(filename, hsh)]
                output += "%s=%s  %s\n" % (hsh, hsh_value, filename)
        assert result.output == output


def test_cli_hash_multiple_hashtype(runner_factory):
    with runner_factory() as runner:
        for filename, hsh, hsh_value in TEST_FILES:
            result = runner.invoke(cli, ['hash', "-t", hsh, filename], catch_exceptions=False)
            common_asserts(result)
            assert result.output == "%s=%s  %s\n" % (hsh, hsh_value, filename)


def test_cli_verify_hash_stdin(runner_factory):
    with runner_factory() as runner:
        for filename, hsh, hsh_value in TEST_FILES:
            result = runner.invoke(cli, ['hash', "-t", hsh, filename], catch_exceptions=False)
            common_asserts(result)
            result = runner.invoke(cli, ['verify-hash', "-"], input=result.output, catch_exceptions=False)
            common_asserts(result)


def test_cli_verify_hash_stdin_fail(runner_factory):
    with runner_factory() as runner:
        for filename, hsh, hsh_value in TEST_FILES:
            result = runner.invoke(cli, ['hash', "-t", hsh, filename], catch_exceptions=False)
            common_asserts(result)
            input_data = result.output
            input_data = input_data.replace("f", "0").replace("0", "1")
            result = runner.invoke(cli, ['verify-hash', "-"], input=input_data, catch_exceptions=False)
            assert result.exit_code == 1, result.output


def test_cli_verify_hash_persistant(runner_factory):
    with runner_factory() as runner:
        files = list(set([e[0] for e in TEST_FILES]))
        result = runner.invoke(cli, ['hash', "-p", "-t", "MD5", "-t", "SHA1", "-t", "BLAKE2b_512", "-t", "SHA3_512"] + files, catch_exceptions=False)
        common_asserts(result)
        result = runner.invoke(cli, ['verify-hash'] + [e + ".s1x" for e in files], catch_exceptions=False)
        common_asserts(result)


