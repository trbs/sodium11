
def common_asserts(result, exit_code=0):
    assert not result.exception, result.output
    assert result.exit_code == exit_code, result.output
