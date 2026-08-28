"""Notification metadata must reach the column, not a shadowing instance attribute.

``CaseNotificationService.create_notification`` constructed ``CaseNotification``
with ``metadata=...``, but the column is ``notification_metadata`` — renamed to
dodge SQLAlchemy's reserved name. The call was never updated.

It did not raise. SQLAlchemy's declarative constructor rejects a kwarg only when
``hasattr(type(self), key)`` is false, and ``CaseNotification.metadata`` exists as
the declarative ``MetaData`` inherited from ``Base``. So ``setattr`` succeeded,
created an instance attribute that shadowed the class attribute, and the payload
never reached a column: it committed cleanly and landed nowhere.

``Base.__init__`` now refuses ``metadata=`` outright, so the mistake is loud for
every model rather than invisible for all of them. These tests pin both halves —
the refusal, and the payload actually arriving on the mapped attribute. They need
no database, so they run in the main PR gate. See #559.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------


class _FakeCase:
    def __init__(self, case_id, assignee=None):
        self.case_id = case_id
        self.title = "a case"
        self.assignee = assignee


class _FakeQuery:
    def __init__(self, first_result=None, all_result=()):
        self._first = first_result
        self._all = all_result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._first

    def all(self):
        return list(self._all)


class _FakeSession:
    """Captures what would have been written, without a database.

    ``unit_of_work`` yields a caller-supplied session unchanged, so passing this
    in is enough to keep the whole path off Postgres.
    """

    def __init__(self, case=None, watchers=()):
        self.added = []
        self._case = case
        self._watchers = watchers

    def query(self, model):
        # notify_sla_warning queries Case (.first()) and then fans out to
        # watchers (.all()); one double has to serve both.
        if getattr(model, "__name__", "") == "CaseWatcher":
            return _FakeQuery(all_result=self._watchers)
        return _FakeQuery(first_result=self._case)

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


def _service():
    from core.cases.case_notification_service import CaseNotificationService

    return CaseNotificationService()


# --------------------------------------------------------------------------
# The model refuses the kwarg that used to be silently dropped
# --------------------------------------------------------------------------


def test_constructing_a_model_with_metadata_raises():
    """The precise failure mode, now loud.

    Before this, ``metadata=`` was accepted by every model and dropped by every
    model. Nothing at runtime flagged it; nothing at rest could see it.
    """
    from core.storage.models import CaseNotification

    with pytest.raises(TypeError, match="shadows the declarative MetaData"):
        CaseNotification(
            user_id="analyst-1",
            notification_type="sla_warning",
            title="t",
            message="m",
            metadata={"threshold_percent": 90},
        )


def test_the_renamed_column_is_still_accepted():
    """The refusal must reject only the shadowing name, not the real column."""
    from core.storage.models import CaseNotification

    notification = CaseNotification(
        user_id="analyst-1",
        notification_type="sla_warning",
        title="t",
        message="m",
        notification_metadata={"threshold_percent": 90},
    )

    assert notification.notification_metadata == {"threshold_percent": 90}


def test_unknown_kwargs_are_still_rejected():
    """Overriding the declarative constructor must not lose its own guarantee."""
    from core.storage.models import CaseNotification

    with pytest.raises(TypeError, match="invalid keyword argument"):
        CaseNotification(user_id="analyst-1", not_a_column=1)


# --------------------------------------------------------------------------
# The payload must land on the mapped column
# --------------------------------------------------------------------------


def test_create_notification_puts_metadata_on_the_column():
    session = _FakeSession()

    notification = _service().create_notification(
        user_id="analyst-1",
        notification_type="sla_warning",
        title="t",
        message="m",
        metadata={"threshold_percent": 90, "sla_type": "response"},
        session=session,
    )

    assert notification is not None, "create_notification returned None"
    assert notification.notification_metadata == {
        "threshold_percent": 90,
        "sla_type": "response",
    }


def test_metadata_is_not_stashed_on_a_shadowing_instance_attribute():
    """Asserting only the column is not enough.

    A refactor could set both and still be wrong. ``metadata`` on the instance
    must stay the class-level ``MetaData``, never a payload.
    """
    from sqlalchemy import MetaData

    session = _FakeSession()

    notification = _service().create_notification(
        user_id="analyst-1",
        notification_type="sla_warning",
        title="t",
        message="m",
        metadata={"threshold_percent": 90},
        session=session,
    )

    assert notification is not None
    assert "metadata" not in notification.__dict__, (
        "payload was set as an instance attribute shadowing the declarative "
        "MetaData — this is the #559 bug"
    )
    assert isinstance(notification.metadata, MetaData)


def test_absent_metadata_does_not_raise():
    """Both of the remaining literal call sites pass a payload; stale_case does not."""
    session = _FakeSession()

    notification = _service().create_notification(
        user_id="analyst-1",
        notification_type="stale_case",
        title="t",
        message="m",
        session=session,
    )

    assert notification is not None
    assert notification.notification_metadata == {}


# --------------------------------------------------------------------------
# The call sites that pass a literal payload
# --------------------------------------------------------------------------


def test_comment_mention_records_author_and_content():
    session = _FakeSession(case=_FakeCase("CASE-1"))

    assert _service().notify_comment_mention(
        case_id="CASE-1",
        mentioned_user="analyst-1",
        comment_author="analyst-2",
        comment_content="take a look",
        session=session,
    )

    assert len(session.added) == 1
    assert session.added[0].notification_metadata == {
        "comment_author": "analyst-2",
        "comment_content": "take a look",
    }


def test_sla_warning_records_threshold_and_type():
    # The assignee notification is the one carrying metadata; it is only created
    # when the case has an assignee. No watchers, so nothing is added by the
    # fan-out and the direct notification is the only row.
    session = _FakeSession(case=_FakeCase("CASE-1", assignee="analyst-1"))

    assert _service().notify_sla_warning(
        case_id="CASE-1", threshold_percent=90, sla_type="response", session=session
    )

    assert len(session.added) == 1
    assert session.added[0].notification_metadata == {
        "threshold_percent": 90,
        "sla_type": "response",
    }
