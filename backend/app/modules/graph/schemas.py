from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: int
    type: str
    label: str
    status: str
    created_at: datetime
    updated_at: datetime
    source_ref: str
    notes: str
    tags: str
    pinned: bool
    position: str
    meta: str
    pinned_canonical_edge_id: str | None


class EdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: int
    source: str
    target: str
    relation: str
    status: str
    created_at: datetime
    updated_at: datetime
    label: str
    meta: str


class GraphOut(BaseModel):
    root_node_id: str | None
    nodes: list[NodeOut]
    edges: list[EdgeOut]


class NodeIn(BaseModel):
    type: str
    label: str = ""
    status: str = "untried"
    notes: str = ""
    tags: str = "[]"
    source_ref: str = ""
    meta: str = "{}"


class NodePatch(BaseModel):
    label: str | None = None
    status: str | None = None
    notes: str | None = None
    tags: str | None = None
    position: str | None = None
    pinned: bool | None = None
    meta: str | None = None


class EdgeIn(BaseModel):
    source: str
    target: str
    relation: str
    status: str = "untried"
    label: str = ""
    meta: str = "{}"


class EdgePatch(BaseModel):
    status: str | None = None
    label: str | None = None
    meta: str | None = None


class CanonicalPatch(BaseModel):
    pinned_canonical_edge_id: str | None = Field(default=None)
