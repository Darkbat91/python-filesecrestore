import pytest
from filesecretstore import FileSecrets, BadPassword
import random
import string


def password_helper(length=10) -> str:
    """
    Returns an alpha numeric string of length
    """
    return "".join(
        [random.choice(string.digits + string.ascii_letters) for n in range(length)]
    )


def test_write_secret(tmp_path):
    test_secret = FileSecrets(tmp_path, password_helper())
    test_secret.set_secret(
        secret_name="my_secret", secret_value="secret value", overwrite=False
    )


def test_return_same_value(tmp_path):
    test_secret_name = "my_secret"
    test_secret_value = "secret value"
    test_secret = FileSecrets(tmp_path, password_helper())

    test_secret.set_secret(
        secret_name=test_secret_name, secret_value=test_secret_value, overwrite=False
    )

    return_secret = test_secret.get_secret(test_secret_name)

    assert return_secret == test_secret_value


def test_return_same_multiline_value(tmp_path):
    test_secret_name = "my_secret"
    test_secret_value = """secret value
    With
    Some
    Extra Lines
    """
    test_secret = FileSecrets(tmp_path, password_helper())

    test_secret.set_secret(
        secret_name=test_secret_name, secret_value=test_secret_value, overwrite=False
    )

    return_secret = test_secret.get_secret(test_secret_name)

    assert return_secret == test_secret_value


def test_salt_maintained(tmp_path):
    testone = FileSecrets(tmp_path, password_helper())
    saltone = testone._get_salt()
    testtwo = FileSecrets(tmp_path, password_helper())
    salttwo = testtwo._get_salt()
    assert saltone == salttwo


def test_bad_password(tmp_path):
    test_secret_name = "my_secret"
    testone = FileSecrets(tmp_path, password_helper())
    testtwo = FileSecrets(tmp_path, password_helper())
    testone.set_secret(test_secret_name, "myvalue")
    with pytest.raises(BadPassword):
        testtwo.get_secret(test_secret_name)


def test_space_in_secret(tmp_path):
    test_secret_name = "my special secret"
    test_secret_value = "secret value"
    test_secret = FileSecrets(tmp_path, password_helper())
    test_secret.set_secret(
        secret_name=test_secret_name, secret_value=test_secret_value, overwrite=False
    )
    return_secret = test_secret.get_secret(test_secret_name)
    assert return_secret == test_secret_value
