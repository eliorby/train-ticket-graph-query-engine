"""Route enumeration truncation reason model."""

from enum import StrEnum


class TruncationReason(StrEnum):
    """Reason why route enumeration stopped before exhausting the search space."""

    MAX_RESULTS = "maxResults"
    MAX_DFS_STEPS = "maxDfsSteps"
