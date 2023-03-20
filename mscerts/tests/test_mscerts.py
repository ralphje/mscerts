import os

import mscerts


def test_cabundle_exists() -> None:
    assert os.path.exists(mscerts.where())


def test_read_contents() -> None:
    content = mscerts.contents()
    assert "-----BEGIN CERTIFICATE-----" in content


def test_py_typed_exists() -> None:
    assert os.path.exists(
        os.path.join(os.path.dirname(mscerts.__file__), 'py.typed')
    )
