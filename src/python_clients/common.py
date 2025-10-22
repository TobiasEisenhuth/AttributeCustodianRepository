import os
import sys
import msgpack
import tempfile
import getpass
import base64
import requests
from typing import List, Optional, Annotated
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
    sender_public_key_b64: str
    sender_verifying_key_b64: str

class EraseItemRequest(BaseModel):
    item_id: str

class GrantAccessRequest(BaseModel):
    receiver_id: UUID
    sender_item_id: str
    receiver_item_id: str
    kfrags_b64: List[str]

class RevokeAccessRequest(BaseModel):
    receiver_id: UUID
    sender_item_id: str

class RequestItemRequest(BaseModel):
    sender_id: UUID
    receiver_item_id: str
    receiver_public_key_b64: str
