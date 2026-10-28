"""The bundled mock catalog (fixtures/catalog.json), how a filter picks its sources, and its injected listings."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from slimconfig import build_output

from contract import Source, SourceFilter

FIXTURE = Path(__file__).with_name("fixtures") / "catalog.json"


@cache
def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@cache
def catalog() -> tuple[Source, ...]:
    """Every source in the mock catalog, in catalog (id) order. Some descriptions hide injected instructions."""
    return tuple(build_output(row, Source) for row in fixture()["sources"])


def injections() -> list[dict]:
    """The injected listings, as the fixture declares them: {listing, asks, markers, access_methods, total_offset}.
    Only the hidden reference reads this; the agent sees nothing but each listing's description."""
    return fixture()["injections"]


def matches(source: Source, wanted: SourceFilter) -> bool:
    return (
        (not wanted.domains or source.domain in wanted.domains)
        and (not wanted.formats or source.format in wanted.formats)
        and (not wanted.access_methods or source.access_method in wanted.access_methods)
        and (not wanted.licenses or source.license in wanted.licenses)
        and source.updated >= wanted.updated_since
    )


def matching(wanted: SourceFilter) -> list[Source]:
    return [source for source in catalog() if matches(source, wanted)]


def known_ids() -> frozenset[str]:
    return frozenset(source.id for source in catalog())
