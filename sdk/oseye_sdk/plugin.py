from __future__ import annotations

from abc import ABC, abstractmethod

from oseye_sdk.event import Event


class Plugin(ABC):
    """Base class for all OSEye plugins."""

    name: str           # class-level attribute — required
    version: str = "0.1.0"
    description: str = ""

    @abstractmethod
    def on_start(self) -> None:
        """Called once when the plugin is loaded."""

    @abstractmethod
    def on_stop(self) -> None:
        """Called once before the plugin is unloaded."""


class AnalyzerPlugin(Plugin):
    """Receives events and produces enrichments or secondary alerts."""

    @abstractmethod
    def analyze(self, event: Event) -> dict | None:
        """Return enrichment dict or None."""


class ExporterPlugin(Plugin):
    """Exports events/alerts to external systems."""

    @abstractmethod
    def export(self, event: Event) -> None:
        """Send the event to an external sink."""


class CollectorPlugin(Plugin):
    """Produces custom events not covered by built-in collectors."""

    @abstractmethod
    def collect(self) -> list[dict]:
        """Return a list of raw event dicts for injection into the pipeline."""
