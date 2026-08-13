from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class JobIn(BaseModel):
    project_id: int
    target_id: int | None = None
    label: str = Field(default="", max_length=200)
    hash_mode_id: str = Field(min_length=1, max_length=40)
    hashes: str = Field(min_length=1, max_length=2_000_000)
    # hashcat -a: 0 straight, 1 combination, 3 brute-force/mask,
    # 6 hybrid wordlist+mask, 7 hybrid mask+wordlist.
    attack_mode: str = Field(default="0", pattern=r"^[01367]$")
    wordlist_id: str = Field(default="", max_length=80)
    wordlist2_id: str = Field(default="", max_length=80)
    rule_id: str = Field(default="", max_length=80)
    mask: str = Field(default="", max_length=64)


class PromoteIn(BaseModel):
    credential_id: int | None = None
    username: str = Field(default="", max_length=200)
    secret: str = Field(min_length=1, max_length=4000)
    domain: str = Field(default="", max_length=253)
    notes: str = Field(default="", max_length=2000)


class JobOut(ORM):
    id: int; project_id: int; target_id: int | None
    label: str; hash_mode_id: str; hash_mode: str; hash_type_name: str
    attack_mode: str; wordlist_id: str; wordlist2_id: str; rule_id: str
    mask: str; hash_count: int
    command_display: str; status: str; exit_code: int | None
    cracked_count: int; cancelled: bool; error: str
    started_at: datetime | None; ended_at: datetime | None
    evidence_id: int | None; created_at: datetime
