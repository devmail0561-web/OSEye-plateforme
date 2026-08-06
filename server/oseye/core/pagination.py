"""Pagination types shared across repositories."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PageResult[T]:
    """Generic paginated result container.

    Used by all repository list() methods that support pagination.
    """

    items: list[T]
    total: int
    limit: int
    offset: int
