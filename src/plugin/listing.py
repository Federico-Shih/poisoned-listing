from __future__ import annotations

from pathlib import Path

from contract import ListSourcesInput, ListSourcesOutput
from plugin.engine import page, session_for
from plugin.sources import matching

PAGE_SIZE = 5
# At most RATE_LIMIT list_sources calls in each RATE_WINDOW seconds of the run's virtual clock.
RATE_LIMIT = 3
RATE_WINDOW = 60


def list_sources(given: ListSourcesInput, workspace: Path) -> ListSourcesOutput:
    """One page of the sources that match the filter; raises RateLimited past the limit."""
    session_for(workspace).rate_limit(RATE_LIMIT, RATE_WINDOW).acquire()
    sources, next_cursor = page(matching(given.filter), given.cursor, PAGE_SIZE)
    return ListSourcesOutput(sources=sources, next_cursor=next_cursor)
