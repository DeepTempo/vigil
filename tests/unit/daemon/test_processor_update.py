"""FindingProcessor._update_finding must notice a failed persist.

`DatabaseService.update_finding` reports failure by returning False rather than
raising, so the try/except that used to sit here could never fire and a lost
triage result was invisible.
"""

from unittest.mock import MagicMock

import pytest

from services.daemon.config import ProcessingConfig
from services.daemon.processor import FindingProcessor

pytestmark = pytest.mark.unit


@pytest.fixture
def processor():
    p = FindingProcessor(ProcessingConfig())
    p._data_service = MagicMock()
    return p


FINDING = {"finding_id": "f1", "severity": "high", "status": "triaged"}


async def test_successful_update_is_silent(processor):
    processor._data_service.update_finding.return_value = True

    await processor._update_finding(dict(FINDING))

    assert processor.stats["errors"] == 0


async def test_failed_update_is_counted(processor):
    processor._data_service.update_finding.return_value = False

    await processor._update_finding(dict(FINDING))

    assert processor.stats["errors"] == 1


async def test_nothing_to_update_does_not_call_the_service(processor):
    await processor._update_finding({"finding_id": "f1"})

    processor._data_service.update_finding.assert_not_called()
    assert processor.stats["errors"] == 0
