from pydantic import BaseModel, ConfigDict


class WazuhConfigBaseModel(BaseModel):
    """Main model for the configuration sections."""

    model_config = ConfigDict(use_enum_values=True)
