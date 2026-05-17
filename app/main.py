import os

from fastapi import FastAPI, HTTPException, status

from app.models import (
    HealthResponse,
    SecretCreateRequest,
    SecretMetadataResponse,
    SecretUpdateRequest,
    SecretValueResponse,
)
from app.secret_store import SecretStore


app = FastAPI(
    title="brdeploy Test Secret API",
    version="1.0.0",
)


def get_store() -> SecretStore:
    return SecretStore()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    storage_path = os.getenv("SECRETS_STORAGE_PATH", "/app/data/secrets.db")
    encryption_key = os.getenv("SECRETS_ENCRYPTION_KEY", "")

    return HealthResponse(
        status="ok",
        storage_path=storage_path,
        encryption_configured=bool(encryption_key),
    )


@app.post(
    "/secrets",
    response_model=SecretMetadataResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_secret(request: SecretCreateRequest) -> SecretMetadataResponse:
    store = get_store()

    try:
        result = store.create_secret(request.name, request.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    return SecretMetadataResponse(**result)


@app.get("/secrets", response_model=list[SecretMetadataResponse])
def list_secrets() -> list[SecretMetadataResponse]:
    store = get_store()
    return [SecretMetadataResponse(**item) for item in store.list_secrets()]


@app.get("/secrets/{name}", response_model=SecretMetadataResponse)
def get_secret_metadata(name: str) -> SecretMetadataResponse:
    store = get_store()
    result = store.get_secret_metadata(name)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{name}' not found.",
        )

    return SecretMetadataResponse(**result)


@app.get("/secrets/{name}/value", response_model=SecretValueResponse)
def get_secret_value(name: str) -> SecretValueResponse:
    store = get_store()
    value = store.get_secret_value(name)

    if value is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{name}' not found.",
        )

    return SecretValueResponse(
        name=name,
        value=value,
    )


@app.put("/secrets/{name}", response_model=SecretMetadataResponse)
def update_secret(name: str, request: SecretUpdateRequest) -> SecretMetadataResponse:
    store = get_store()
    result = store.update_secret(name, request.value)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{name}' not found.",
        )

    return SecretMetadataResponse(**result)


@app.delete("/secrets/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_secret(name: str) -> None:
    store = get_store()
    deleted = store.delete_secret(name)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret '{name}' not found.",
        )