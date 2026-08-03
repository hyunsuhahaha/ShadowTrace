from pydantic import BaseModel, Field


class RoundcubeDesIn(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    value: str = Field(min_length=1, max_length=20_000)


class DpapiMasterkeyIn(BaseModel):
    masterkey_b64: str = Field(min_length=1, max_length=2_000_000)
    sid: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=500)


class DpapiCredentialIn(BaseModel):
    credential_b64: str = Field(min_length=1, max_length=2_000_000)
    key_hex: str = Field(min_length=1, max_length=200)
