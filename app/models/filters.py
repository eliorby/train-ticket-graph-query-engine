from enum import StrEnum


class Filter(StrEnum):
    """Supported route filter names."""

    PUBLIC_SOURCE = "publicSource"
    SINK = "sink"
    VULNERABLE = "vulnerable"
