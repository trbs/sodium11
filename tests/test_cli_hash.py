from sodium11 import cli
from .utils import common_asserts

TEST_FILES = [
    ("zeros_16MB.dat", "MD5", "50838bbf29aec4c6e62bee320d5c9138"),
    ("zeros_16MB.dat", "SHA1", "4fd1525074dff79cd0d4d5b36239f94f8ecbbc79"),
    ("zeros_16MB.dat", "BLAKE2b_512", "8792c33e91db780ca2508d557095f7a3906ba86070ce625d155997d8d1a90829d75d7073a3cb529f50c652db380dba8b0574f7a7f33620dffcc29ab06a6fe770"),
    ("zeros_16MB.dat", "SHA3_512", "cb225ee4f37dbb0ec33ba814dfeefbbba372ee93b3e6dd0db48ad8a239117c64e02a2ca71938b2d597a4648ef455915391c76c36e8fba90e264bb11f50c94e2a"),
    ("zeros_64MB.dat", "MD5", "10d78366cd4b9de580625e7c67133696"),
    ("zeros_64MB.dat", "SHA1", "bb02f77d8fb4e9569325e27ba3d0313be739bad0"),
    ("zeros_64MB.dat", "BLAKE2b_512", "3ce31c256decb2274a7ab9037240e5febb059b7438a110aeb458ccd84b108c2bc101d90def0766e403bbf4f53844d42e816354bf87de8454f762bd50a0fbe20a"),
    ("zeros_64MB.dat", "SHA3_512", "83dfb2455ecfbb9738ee9f15bff39e03d519d4def88a690808d114f796764a1cfcf30828216e97d409a7a0b97290bbd7605f8b7365b04e5e5f480a6591aa93b1"),
    ("repeat_64MB.dat", "MD5", "f0729a075c479345f2154bda70ed7b38"),
    ("repeat_64MB.dat", "SHA1", "a4f6d454c55de029d36f07775cd10d55d4c358e8"),
    ("repeat_64MB.dat", "BLAKE2b_512", "0918e241699ffb7dcaf877e3b73ef87d87a31cbed16e6264438b75a122022f9d090e19313255f9cc245e787283b70a7968501b9bea20c7202ac466a52dcf416b"),
    ("repeat_64MB.dat", "SHA3_512", "524d7283f72af0670fc9089c14adb79e3db7f379569b997f7862828b220016baf4ea06bbc74485dcd993667368c763f89f510bdf969a2f5d56369e9d167195dd"),
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
