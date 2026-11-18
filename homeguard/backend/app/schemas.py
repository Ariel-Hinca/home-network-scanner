"""Pydantic response and request models."""

from datetime import datetime

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str


class ScopePolicy(BaseModel):
    address_family: str
    allowed_ranges: list[str]
    max_scope: str
    default_scope: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    api_host: str
    api_port: int
    scope_policy: ScopePolicy


class SetupStatus(BaseModel):
    setup_completed: bool
    authenticated: bool


class PassphraseBody(BaseModel):
    passphrase: str = Field(min_length=12, max_length=128)


class CidrBody(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)


class NetworkCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    cidr: str = Field(min_length=1, max_length=64)
    interface_name: str | None = Field(default=None, max_length=128)


class ValidatedCidr(BaseModel):
    cidr: str
    prefix_length: int
    num_addresses: int
    private: bool
    within_max_scope: bool
    host_bits_normalized: bool
    max_scope: str
    default_scope: str


class NetworkOut(BaseModel):
    id: int
    name: str
    cidr: str
    prefix_length: int
    interface_name: str | None
    ownership_confirmed: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class InterfaceOut(BaseModel):
    name: str
    address: str
    netmask: str
    interface_cidr: str
    interface_allowed: bool
    suggested_scan_cidr: str | None
    detail: str | None


class AuditOut(BaseModel):
    id: int
    created_at: datetime
    action: str
    subject: str
    detail: str

    model_config = {"from_attributes": True}
