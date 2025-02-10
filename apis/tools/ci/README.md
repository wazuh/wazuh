## PyServer CI setup

We use pre-commit along with ruff to lint and format our code.

This combination gives us auto-formatting on save, lint warnings and prevents us from uploading non-compliant code when committing changes.

The configurations can be found at the `apis/tools/ci/.pre-commit-config.yaml` and `.ruff.toml` files.

To start using them, just install the tools following the steps below.

### Ruff

Install ruff:

```console
pip install ruff
```

> [!Note]
> Python version +3.11 requires specifying the flag `--break-system-packages` to install a package outside of a virtual environment.

You can now use `ruff check` and `ruff format` commands to look for or fix issues present in the code.

### Pre-commit

Install pre-commit:

```console
pip install pre-commit
```

> [!Note]
> Python version +3.11 requires specifying the flag `--break-system-packages` to install a package outside of a virtual environment.

Install the pre-commit configuration:

```
pre-commit install --config ./apis/tools/ci/.pre-commit-config.yaml
```

#### IDE

Install and configure your IDE extension following the steps from the official guide: https://docs.astral.sh/ruff/editors/setup/

##### VSCode configuration

We can configure VSCode to format and fix lint issues on save, for that, include the following configuration in your `settings.json` file.

```json
{
    "[python]": {
      "editor.formatOnSave": true,
      "editor.defaultFormatter": "charliermarsh.ruff",
      "editor.codeActionsOnSave": {
          "source.fixAll": "explicit"
        }
    }
}
```
