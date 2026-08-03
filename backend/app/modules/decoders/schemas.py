from pydantic import BaseModel, Field


class RoundcubeDesIn(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    value: str = Field(min_length=1, max_length=20_000)
