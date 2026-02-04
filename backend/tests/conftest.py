"""Shared pytest fixtures for all tests."""

import pytest


@pytest.fixture
def sample_subject_attributes():
    """Return sample subject attributes for testing."""
    return {
        "user_id": "test-user-1",
        "tenant_id": "test-tenant-1",
        "role": "developer",
        "username": "testuser",
    }


@pytest.fixture
def sample_resource_fields():
    """Return sample resource field classifications."""
    return {
        "name": {"classification": "PII"},
        "age": {"classification": "SENSITIVE"},
        "external_id": {"classification": "PII"},
    }
