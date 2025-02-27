import os

from pydantic import BaseModel, ConfigDict


class WazuhConfigBaseModel(BaseModel):
    """Main model for the configuration sections."""

    model_config = ConfigDict(use_enum_values=True)


class ValidateFilePathMixin:
    """Mixin to validate configuration file paths."""

    @classmethod
    def _validate_file_path(cls, path: str, field_name: str):
        """Validate that a single file path is non-empty and points to an existing file.

        Parameters
        ----------
        path : str
            File path to validate.
        field_name : str
            Name of the field being validated.

        Raises
        ------
        ValueError
            If the file path is empty or the file does not exist.
        """
        if path == '':
            raise ValueError(f'{field_name}: no file path specified')

        if not os.path.isfile(path):
            raise ValueError(f"{field_name}: the file '{path}' does not exist")
