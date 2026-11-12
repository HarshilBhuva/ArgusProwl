"""PostgreSQL adapter integration tests.

These tests run against the ephemeral PostgreSQL service in backend CI and are
skipped for local test runs without ARGUSPROWL_TEST_DATABASE_URL.
"""

import os
from uuid import uuid4

import pytest

from argusprowl.storage.postgresql_adapter import PostgreSQLAdapter


@pytest.fixture
def postgres_storage():
    connection_string = os.getenv("ARGUSPROWL_TEST_DATABASE_URL")
    if not connection_string:
        pytest.skip("ARGUSPROWL_TEST_DATABASE_URL is not configured.")
    storage = PostgreSQLAdapter(connection_string, min_size=1, max_size=3)
    yield storage
    storage.close()


def test_postgresql_storage_round_trip_and_update(postgres_storage):
    record_id = uuid4()
    postgres_storage.save("adapter_test", record_id, {"status": "new", "count": 1})

    assert postgres_storage.load("adapter_test", record_id) == {
        "status": "new",
        "count": 1,
    }

    postgres_storage.save("adapter_test", record_id, {"status": "updated", "count": 2})
    assert postgres_storage.load("adapter_test", record_id) == {
        "status": "updated",
        "count": 2,
    }


def test_postgresql_storage_list_is_collection_scoped(postgres_storage):
    first_id, second_id = uuid4(), uuid4()
    postgres_storage.save("adapter_list_a", first_id, {"value": "a"})
    postgres_storage.save("adapter_list_b", second_id, {"value": "b"})

    assert postgres_storage.list_records("adapter_list_a") == [{"value": "a"}]


def test_postgresql_storage_delete_is_idempotent(postgres_storage):
    record_id = uuid4()
    postgres_storage.save("adapter_delete", record_id, {"value": True})

    assert postgres_storage.delete("adapter_delete", record_id) is True
    assert postgres_storage.delete("adapter_delete", record_id) is False
    assert postgres_storage.load("adapter_delete", record_id) is None


def test_postgresql_storage_health_check(postgres_storage):
    assert postgres_storage.health_check() is True


def test_postgresql_storage_rejects_invalid_pool_configuration():
    with pytest.raises(ValueError, match="Pool sizes"):
        PostgreSQLAdapter("postgresql://invalid", min_size=4, max_size=2)
