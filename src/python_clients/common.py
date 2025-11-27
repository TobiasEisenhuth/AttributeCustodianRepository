from typing import List, Annotated
from uuid import UUID

from pydantic import BaseModel, EmailStr, StringConstraints
from pydantic.types import StrictStr

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

class ResolveRequesterItemRequest(BaseModel):
    provider_id: UUID
    requester_item_id: str

class RequestItemRequest(BaseModel):
    provider_id: UUID
    requester_item_id: str
    requester_public_key_b64: str

class DismissGrantRequest(BaseModel):
    provider_id: UUID
    requester_item_id: str

class SaveToVaultRequest(BaseModel):
    envelope_b64: str

class PushSolicitationRequest(BaseModel):
    provider_id: UUID
    payload_b64: str

class PullSolicitationBundleRequest(BaseModel):
    pass

class SolicitationStatusRequest(BaseModel):
    request_id: UUID

class AckSolicitationRequest(BaseModel):
    request_id: UUID
