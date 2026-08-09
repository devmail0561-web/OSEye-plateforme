from __future__ import annotations

import logging

from oseye_sdk.event import Event
from oseye_sdk.plugin import ExporterPlugin

logger = logging.getLogger(__name__)


class S3Exporter(ExporterPlugin):
    """Export events to S3 as NDJSON (stub).

    Production implementation would buffer events in memory and flush
    them to an S3 bucket as a NDJSON object every N seconds using boto3.
    """

    name = "exporter_s3"
    description = "Export events to S3 as NDJSON (stub)"

    def on_start(self) -> None:
        # In prod: load bucket, prefix, flush_interval from config; start flush timer
        logger.info("S3Exporter started (stub mode)")

    def on_stop(self) -> None:
        # In prod: flush remaining buffered events before stopping
        logger.info("S3Exporter stopped")

    def export(self, event: Event) -> None:
        # In prod: buffer events and flush to S3 every N seconds
        # self._buffer.append(event)
        # if len(self._buffer) >= self._batch_size or time_since_last_flush > self._interval:
        #     self._flush()
        logger.debug(
            "S3Exporter: would buffer event %s for S3 export", event.event_id
        )
