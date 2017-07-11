
def common_asserts(result):
    assert not result.exception, result.output
    assert result.exit_code == 0, result.output
