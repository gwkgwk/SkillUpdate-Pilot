from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_required_safety_files_exist():
    for path in ('AGENTS.md','README.md','docs/governance/SECURITY_BOUNDARIES.md','pytest.ini'):
        assert (ROOT/path).is_file()


def test_downloaded_tests_are_excluded():
    configuration=(ROOT/'pytest.ini').read_text()
    assert 'testpaths = tests' in configuration
    assert 'data' in configuration.split('norecursedirs =',1)[1]


def test_secret_and_raw_paths_are_ignored():
    ignore=(ROOT/'.gitignore').read_text().splitlines()
    for path in ('.env','*.key','artifacts/raw/','artifacts/sandboxes/'):
        assert path in ignore
