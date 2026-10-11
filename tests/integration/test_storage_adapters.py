from uuid import uuid4

import pytest

from argusprowl.interfaces.storage import Storage
from argusprowl.storage import ClickHouseAdapter, PostgreSQLAdapter, RedisAdapter, SQLiteAdapter


def test_sqlite_adapter_implements_storage(tmp_path) -> None:
    adapter = SQLiteAdapter(tmp_path / "platform.db")
    record_id = uuid4()
    adapter.save("events", record_id, {"event_type": "login"})
    assert isinstance(adapter, Storage)
    assert adapter.load("events", record_id) == {"event_type": "login"}
    adapter.close()


@pytest.mark.parametrize("adapter_type", [PostgreSQLAdapter, ClickHouseAdapter, RedisAdapter])
def test_future_storage_adapters_are_explicit_skeletons(adapter_type) -> None:
    adapter = adapter_type()
    assert isinstance(adapter, Storage)
    with pytest.raises(NotImplementedError):
        adapter.list_records("events")
