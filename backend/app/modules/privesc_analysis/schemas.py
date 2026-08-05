from pydantic import BaseModel, Field


class LinpeasIn(BaseModel):
    output: str = Field(min_length=1, max_length=20_000_000)


class SuidScanIn(BaseModel):
    output: str = Field(min_length=1, max_length=5_000_000)
