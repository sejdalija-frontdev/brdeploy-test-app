from pydantic import BaseModel, Field
from typing import Optional


class SecretCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    value: str = Field(..., min_length=1)


class SecretUpdateRequest(BaseModel):
    value: str = Field(..., min_length=1)


class SecretMetadataResponse(BaseModel):
    name: str
    created_at: str
    updated_at: Optional[str] = None


class SecretValueResponse(BaseModel):
    name: str
    value: str


class HealthResponse(BaseModel):
    status: str
    storage_path: str
    encryption_configured: bool