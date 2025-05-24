import json
from pathlib import Path
from unittest.mock import Mock
import pytest
from click.testing import CliRunner
import re

from laut import cli as cli_file
from laut.nix import commands

sign = cli_file.sign
cli = cli_file.cli

@pytest.fixture
def mock_derivation_lookup(monkeypatch):

    def _get_derivation_mock(drv_path, recursive):
        assert(recursive == False)

        if drv_path == "/nix/store/jy80sl8j6218d6mwnqlyirmhskxibags-bootstrap-tools.drv":
            drv_file_name = "resolved.drv"
        elif drv_path == "/nix/store/w14fhgwzx0421c2ry4d9hx1cpsfsjlf5-bootstrap-tools.drv":
            drv_file_name = "unresolved.drv"
        elif drv_path == '/nix/store/5gwiavq50bzhsfr71r12qzl9a32njsb8-bootstrap-stage0-binutils-wrapper-.drv':
            drv_file_name = "resolved-problematic.drv"
        elif drv_path == "/nix/store/jpvka5j1mc84byi7czzdrlr8rdib0fck-bootstrap-stage0-binutils-wrapper-.drv":
            drv_file_name = "resolved-problematic-fixed.drv"
        elif drv_path == "/nix/store/0685sic9d3nzvf940sj4aflllsq99pqk-zlib-1.3.1.drv":
            drv_file_name = "multiple-outputs.drv"
        elif drv_path == "/nix/store/23xwpgqwja339ljkq4zqgymwyawnlhar-gettext-0.22.5.drv":
            drv_file_name = "not-ascii.drv"
        else:
            ValueError("invalid input to mock")

        drv_file = Path(__file__).parent / "data" / "example_drvs" / drv_file_name
        drv = json.loads(drv_file.read_text())
        return drv

    def _get_output_hash_mock(out_path):
        return "sha256:0000000000000000000000000000000000000000000000000000000000000000"

    derivation_mock = Mock(side_effect=_get_derivation_mock)
    output_hash_mock = Mock(side_effect=_get_output_hash_mock)

    from laut import signing

    def _mock_compute_aterm(drv_name: str, drv_path: str):
        dummy_path = drv_path
        dummy_aterm = f'Derive([("out","/nix/store/dummy-{drv_name}","","")],[],[],"x86_64-linux","/nix/store/dummy-builder",[("name","{drv_name}")])'
        return dummy_path, dummy_aterm

    def _mock_create_castore_entry(path):
        return {"type": "directory", "size": 1024}

    import click.types
    original_convert = click.types.Path.convert

    def _mock_click_path_convert(self, value, param, ctx):
        # For our test derivation paths, bypass the file existence check
        test_drv_paths = [
            "/nix/store/jy80sl8j6218d6mwnqlyirmhskxibags-bootstrap-tools.drv",
            "/nix/store/w14fhgwzx0421c2ry4d9hx1cpsfsjlf5-bootstrap-tools.drv",
            "/nix/store/5gwiavq50bzhsfr71r12qzl9a32njsb8-bootstrap-stage0-binutils-wrapper-.drv",
            "/nix/store/jpvka5j1mc84byi7czzdrlr8rdib0fck-bootstrap-stage0-binutils-wrapper-.drv",
            "/nix/store/0685sic9d3nzvf940sj4aflllsq99pqk-zlib-1.3.1.drv",
            "/nix/store/23xwpgqwja339ljkq4zqgymwyawnlhar-gettext-0.22.5.drv"
        ]

        if str(value) in test_drv_paths:
            # Skip existence check for our test paths, just return the path
            return self.coerce_path_result(value)
        else:
            # Use original validation for all other paths (like key files)
            return original_convert(self, value, param, ctx)

    monkeypatch.setattr(commands, "get_derivation", derivation_mock)
    monkeypatch.setattr(signing, "get_output_hash_from_disk", output_hash_mock)
    monkeypatch.setattr(signing, "compute_ATERMbased_resolved_input_hash_like_nix", _mock_compute_aterm)
    monkeypatch.setattr(signing, "create_castore_entry", _mock_create_castore_entry)
    monkeypatch.setattr(click.types.Path, "convert", _mock_click_path_convert)

    return derivation_mock

@pytest.fixture
def runner():
    """Provides a Click CLI test runner."""
    return CliRunner(mix_stderr=False)

def test_sign_resolved_hook(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/jy80sl8j6218d6mwnqlyirmhskxibags-bootstrap-tools.drv"
        ],
        env = {
            'OUT_PATHS': '/nix/store/n7cxavpfzzz2pb1a71fg5hy1mqf1xlf2-bootstrap-tools',
            'DRV_PATH': '/nix/store/jy80sl8j6218d6mwnqlyirmhskxibags-bootstrap-tools.drv',
        }
    )
    assert result.exit_code == 0
    assert mock_derivation_lookup.call_count == 2 # TODO: make this 1
    mock_derivation_lookup.assert_called_with('/nix/store/jy80sl8j6218d6mwnqlyirmhskxibags-bootstrap-tools.drv', False)
    pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    assert re.match(pattern, result.stdout), f"String '{result.stdout}' does not look like a JWS"

def test_sign_multi_output(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/0685sic9d3nzvf940sj4aflllsq99pqk-zlib-1.3.1.drv"
        ],
        env = {
            'OUT_PATHS': '/nix/store/75bq8gasrvjw6k4ss2y1n2z6cbqaih68-zlib-1.3.1-static /nix/store/95d8zqx3nx5gbha1dlcspwz8sncz84y4-zlib-1.3.1 /nix/store/pmazrl3wschw3rnzk107x81lh2ai87cz-zlib-1.3.1-dev',
            'DRV_PATH': '/nix/store/0685sic9d3nzvf940sj4aflllsq99pqk-zlib-1.3.1.drv',
        }
    )
    assert result.exit_code == 0
    assert mock_derivation_lookup.call_count == 2 # TODO: make this 1
    mock_derivation_lookup.assert_called_with('/nix/store/0685sic9d3nzvf940sj4aflllsq99pqk-zlib-1.3.1.drv', False)
    pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    assert re.match(pattern, result.stdout), f"String '{result.stdout}' does not look like a JWS"

def test_ascii(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/23xwpgqwja339ljkq4zqgymwyawnlhar-gettext-0.22.5.drv"
        ],
        env = {
            'OUT_PATHS': '/nix/store/75bq8gasrvjw6k4ss2y1n2z6cbqaih68-gettext-0.22.5-doc /nix/store/95d8zqx3nx5gbha1dlcspwz8sncz84y4-gettext-0.22.5 /nix/store/pmazrl3wschw3rnzk107x81lh2ai87cz-gettext-0.22.5-info /nix/store/75bq8gasrvjw6k4ss2y1n2z6cbqaih68-gettext-0.22.5-man',
            'DRV_PATH': '/nix/store/23xwpgqwja339ljkq4zqgymwyawnlhar-gettext-0.22.5.drv',
        }
    )
    assert result.exit_code == 0
    assert mock_derivation_lookup.call_count == 2 # TODO: make this 1
    mock_derivation_lookup.assert_called_with('/nix/store/23xwpgqwja339ljkq4zqgymwyawnlhar-gettext-0.22.5.drv', False)
    pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    assert re.match(pattern, result.stdout), f"String '{result.stdout}' does not look like a JWS"

@pytest.mark.skip(reason='''
fails test becauese it is a deferred IA derivation
does not work in sandbox for some unknown reason
''')
def test_sign_resolved_problematic_derivaion_hook(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/5gwiavq50bzhsfr71r12qzl9a32njsb8-bootstrap-stage0-binutils-wrapper-.drv"
        ],
        env = {
            'OUT_PATHS': '/nix/store/bnyyaql5yvcrfw42k9kd5d10c2f10mnp-bootstrap-stage0-binutils-wrapper-',
            'DRV_PATH': '/nix/store/5gwiavq50bzhsfr71r12qzl9a32njsb8-bootstrap-stage0-binutils-wrapper-.drv',
        }
    )
    assert mock_derivation_lookup.call_count == 1
    mock_derivation_lookup.assert_called_with('/nix/store/5gwiavq50bzhsfr71r12qzl9a32njsb8-bootstrap-stage0-binutils-wrapper-.drv', False)
    assert result.exit_code == 0
    pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    assert re.match(pattern, result.stdout), f"String '{result.stdout}' does not look like a JWS"

def test_sign_resolved_problematic_derivaion_fixed_hook(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/jpvka5j1mc84byi7czzdrlr8rdib0fck-bootstrap-stage0-binutils-wrapper-.drv"
        ],
        env = {
            'OUT_PATHS': '/nix/store/bnyyaql5yvcrfw42k9kd5d10c2f10mnp-bootstrap-stage0-binutils-wrapper-',
            'DRV_PATH': '/nix/store/jpvka5j1mc84byi7czzdrlr8rdib0fck-bootstrap-stage0-binutils-wrapper-.drv',
        }
    )
    assert mock_derivation_lookup.call_count == 2 # TODO: make this 1
    mock_derivation_lookup.assert_called_with('/nix/store/jpvka5j1mc84byi7czzdrlr8rdib0fck-bootstrap-stage0-binutils-wrapper-.drv', False)
    assert result.exit_code == 0
    pattern = r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
    assert re.match(pattern, result.stdout), f"String '{result.stdout}' does not look like a JWS"

def test_sign_unresolved_hook(runner, mock_derivation_lookup):
    result = runner.invoke(sign, [
            '--secret-key-file', str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"),
            "/nix/store/w14fhgwzx0421c2ry4d9hx1cpsfsjlf5-bootstrap-tools.drv"
        ],
        env = {
            'OUT_PATHS': '',
            'DRV_PATH': '/nix/store/w14fhgwzx0421c2ry4d9hx1cpsfsjlf5-bootstrap-tools.drv',
        }
    )
    assert mock_derivation_lookup.call_count == 1
    mock_derivation_lookup.assert_called_with('/nix/store/w14fhgwzx0421c2ry4d9hx1cpsfsjlf5-bootstrap-tools.drv', False)
    assert result.stdout == ''
    assert result.exit_code == 117

# def test_sign_unresolved_hook(runner):
#     """Test the add command."""
#     result = runner.invoke(sign, ['5', '7'])
#     assert result.exit_code == 0
#     assert 'Result: 12' in result.output

# def test_sign_error(runner):
#     """Test the add command."""
#     result = runner.invoke(sign, ['5', '7'])
#     assert result.exit_code == 0
#     assert 'Result: 12' in result.output

def test_sign_no_args(runner):
    """Test the add command."""
    result = runner.invoke(sign)
    pass

# To run these tests:
# pytest -xvs tests/test_cli.py

# For more complex applications, you might want to use:

# Advanced pattern with external process simulation
# @pytest.fixture
# def isolated_filesystem(runner):
#     """Provides an isolated filesystem for testing file operations."""
#     with runner.isolated_filesystem() as fs:
#         yield fs

# def test_command_with_file_output(runner, isolated_filesystem):
#     """Test a command that outputs to a file."""
#     # Example only - assumes you have a command that writes to a file
#     result = runner.invoke(cli, ['export', '--output', 'output.txt'])
#     assert result.exit_code == 0

#     with open('output.txt', 'r') as f:
#         content = f.read()
#     assert 'Expected content' in content

# # For testing environment variables
# def test_with_env_vars(runner):
#     """Test behavior with environment variables."""
#     result = runner.invoke(cli, ['env-dependent-command'], env={'API_KEY': 'test-key'})
#     assert result.exit_code == 0
#     assert 'Using API key: test-key' in result.output

# # For testing interactive commands
# def test_interactive_command(runner):
#     """Test an interactive command with input."""
#     result = runner.invoke(cli, ['interactive'], input='y\n')
#     assert result.exit_code == 0
#     assert 'You confirmed' in result.output
