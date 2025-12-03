"""Internal data models for CSAF VEX documents."""

from collections.abc import Callable
from typing import Any

import attrs


def conditional_verifier(func: Callable) -> Callable:
    """Decorator to make verifiers respect the verify flag."""

    def wrapper(self, attribute: attrs.Attribute, value: Any) -> None:
        if self.verify:
            func(self, attribute, value)

    return wrapper


@attrs.define
class Document:
    """Represents the 'document' section of a CSAF VEX file."""

    title: str | None = attrs.field(default=None)
    category: str | None = attrs.field(default=None)
    tracking_id: str | None = attrs.field(default=None)
    verify: bool = attrs.field(default=True, kw_only=True, repr=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any], verify: bool = True) -> "Document":
        """Create a Document from a dictionary.

        Args:
            data: The 'document' section from parsed JSON
            verify: Whether to run verifiers (default: True)
        """
        return cls(
            title=data.get("title"),
            category=data.get("category"),
            tracking_id=data.get("tracking", {}).get("id"),
            verify=verify,
        )

    @title.validator
    @conditional_verifier
    def _verify_title(self, attribute: attrs.Attribute, value: str | None) -> None:
        """Verify that title is not empty if provided."""
        if value is not None and not value.strip():
            raise ValueError("Title cannot be empty")

    @category.validator
    @conditional_verifier
    def _verify_category(self, attribute: attrs.Attribute, value: str | None) -> None:
        """Verify that category is csaf_vex if provided."""
        if value is not None and value not in ("csaf_vex", "csaf_security_advisory"):
            raise ValueError(f"Invalid category: {value}")


@attrs.define
class CSAFVEXDocument:
    """Represents a complete CSAF VEX file."""

    document: Document
    product_tree: dict[str, Any] = attrs.field(factory=dict)
    vulnerabilities: list[dict[str, Any]] = attrs.field(factory=list)
    verify: bool = attrs.field(default=True, kw_only=True, repr=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any], verify: bool = True) -> "CSAFVEXDocument":
        """Create a CSAFVEXDocument from a dictionary (parsed JSON).

        Args:
            data: The complete parsed CSAF VEX JSON data
            verify: Whether to run verifiers (default: True)
        """
        return cls(
            document=Document.from_dict(data.get("document", {}), verify=verify),
            product_tree=data.get("product_tree", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            verify=verify,
        )
