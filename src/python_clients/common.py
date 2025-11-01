from typing import List, Annotated, Dict, Any, Optional
from uuid import UUID
from datetime import datetime, timezone

from pydantic import BaseModel, EmailStr, StringConstraints, field_validator
from pydantic.types import StrictStr
from pydantic.config import ConfigDict

MINIMAL_PASSWORD_LENGTH = 15
Password = Annotated[StrictStr, StringConstraints(min_length=MINIMAL_PASSWORD_LENGTH, strip_whitespace=False)]

class LoginRequest(BaseModel):
    email: EmailStr
    password: Password

class UpsertItemRequest(BaseModel):
    item_id: str
    capsule_b64: str
    ciphertext_b64: str
    provider_public_key_b64: str
    provider_verifying_key_b64: str

class EraseItemRequest(BaseModel):
    item_id: str

class GrantAccessRequest(BaseModel):
    requester_id: UUID
    provider_item_id: str
    requester_item_id: str
    kfrags_b64: List[str]

class RevokeAccessRequest(BaseModel):
    requester_id: UUID
    provider_item_id: str

class RequestItemRequest(BaseModel):
    provider_id: UUID
    requester_item_id: str
    requester_public_key_b64: str

class SaveToVaultRequest(BaseModel):
    encrypted_localstore_b64: str

class PushSolicitationRequest(BaseModel):
    provider_id: UUID
    request_id: Optional[UUID] = None
    payload: Dict[str, Any]

class PullSolicitationBundleRequest(BaseModel):
    pass

class AckSolicitationBundleRequest(BaseModel):
    requester_id: UUID
    max_created_at: datetime
    max_request_id: UUID

    model_config = ConfigDict(extra="forbid")

    @field_validator("max_created_at", mode="before")
    @classmethod
    def _parse_dt(cls, v):
        if isinstance(v, str) and v.endswith("Z"):
            return v[:-1] + "+00:00"
        return v

    @field_validator("max_created_at")
    @classmethod
    def _ensure_tzaware(cls, v: datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v