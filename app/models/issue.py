"""Validation issue model surfaced by graph integrity checks."""

from enum import StrEnum

from pydantic import BaseModel, computed_field


class IssueCode(StrEnum):
    """Recognized validation issue codes."""

    DANGLING_NODE_REFERENCE = "dangling-node-reference"
    NORMALIZED_TO_FIELD = "normalized-to-field"


class IssueSeverity(StrEnum):
    """Validation issue severity levels."""

    ERROR = "error"
    INFO = "info"


_DEFAULT_SEVERITY: dict[IssueCode, IssueSeverity] = {
    IssueCode.DANGLING_NODE_REFERENCE: IssueSeverity.ERROR,
    IssueCode.NORMALIZED_TO_FIELD: IssueSeverity.INFO,
}


class Issue(BaseModel):
    """A structural or data-integrity finding from graph validation."""

    code: IssueCode
    message: str

    @computed_field
    @property
    def severity(self) -> IssueSeverity:
        """Severity derived from the issue code."""
        return _DEFAULT_SEVERITY[self.code]

    @classmethod
    def normalized_to_field(cls, from_node: str) -> "Issue":
        return cls(
            code=IssueCode.NORMALIZED_TO_FIELD,
            message=(
                f"Edge from '{from_node}' had a string 'to' field; "
                "normalized to a single-element array."
            ),
        )

    @classmethod
    def dangling_node_reference(cls, from_node: str, target: str) -> "Issue":
        return cls(
            code=IssueCode.DANGLING_NODE_REFERENCE,
            message=f"Edge from '{from_node}' references undefined node '{target}'.",
        )
