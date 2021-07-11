from reinkuro import __version__
from reinkuro.kuro import cryptbystring
from pathlib import Path


def test_version():
    assert __version__ == "0.1.0"


def test_cryptbystring():
    testasset = Path("tests/sample.bin").read_bytes()

    mask = "al)built_in"
    testcrypted = cryptbystring(input=testasset, mask=mask)
    assert testcrypted[0:7] == b"UnityFS"
