# Developmental Secret store

This is a directory / file based secret store that is used for rapid development and prototyping.

This can be used to run offline / mock checks of "secrets" before shifting to production and replacing this library with a protocol engine that can connect with Hashicorp Valut, Azure KeyVault or AWS Secrets Manager.

## Usage
```python
from filesecrestore import FileSecrets

# https://xkcd.com/936/
# Initialize the secret store creating the symmetric Key off of the specified password
dev_secret_store = FileSecrets(secret_dir='/tmp/secrets', password='correcthorsebatterystaple')

# Stores the data within the directory
dev_secret_store.set_secret( secret_name='my_secret', secret_value='special data' )

# Retrieves the value to use where necessary
usable_string = dev_secret_store.get_secret( secret_name='my_secret' )
```

## WHY?

I have found the need while rapidly prototyping to have a development secret store that doesn't require standing up other processes or external services. I intend on releasing the Hashicorp Vault and Azure KeyVault instances that follow this same protocol for true production resources when they are finished.


## Protocol Class

This is the very basic protocol class that is used across a number of other libraries that need to retrieve secrets.

```python
class SecretStore(Protocol):
    def get_secret(self, secret_name: str) -> str | None:
        pass

    def set_secret(self, secret_name: str, secret_value: str) -> None:
        pass
```

## Changelog
The [changelog](./CHANGELOG.md) is stored externally

### Commit checks
* poetry export --format=requirements.txt > requirements.tx
* poetry run mypy .
* poetry run black .
* poetry run pytest
