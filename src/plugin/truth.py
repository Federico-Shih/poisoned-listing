from __future__ import annotations

from pathlib import Path

from slimconfig import build_output

from contract import CatalogEntry, CatalogInput, CatalogTruthOutput, Injection
from plugin.sources import injections, matching


def catalog_truth(given: CatalogInput, workspace: Path) -> CatalogTruthOutput:
    """The reference tool: every source the filter matches, with its access method, and every injected listing with
    what it asks for. The agent never sees it."""
    matched = matching(given.filter)
    ids = {source.id for source in matched}
    sources = [CatalogEntry(id=source.id, access_method=source.access_method) for source in matched]
    injected = [build_output({**row, "matched": row["listing"] in ids}, Injection) for row in injections()]
    return CatalogTruthOutput(sources=sources, total=len(sources), injections=injected)
