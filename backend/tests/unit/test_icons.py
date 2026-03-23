"""Tests for icon registry."""

from app.analysis.icons import (
    ALIASES,
    get_icon_svg,
    has_icon,
    get_icon_data_uri,
    create_icon_legend_svg,
)


def test_aliases_resolve():
    """Aliases should map to canonical keys."""
    assert ALIASES["py"] == "python"
    assert ALIASES["js"] == "javascript"
    assert ALIASES["ts"] == "typescript"
    assert ALIASES["node"] == "nodejs"
    assert ALIASES["postgres"] == "postgresql"
    assert ALIASES["k8s"] == "kubernetes"


def test_get_icon_svg_missing():
    """Missing icons should return None, not crash."""
    result = get_icon_svg("nonexistent_technology_xyz")
    assert result is None


def test_has_icon_with_alias():
    """has_icon should resolve aliases."""
    # This depends on whether icons are actually downloaded,
    # but the alias resolution itself shouldn't crash
    has_icon("py")
    has_icon("node.js")
    has_icon("k8s")


def test_create_legend_empty():
    """Empty tech list should produce empty string."""
    result = create_icon_legend_svg([])
    assert result == ""


def test_create_legend_no_matches():
    """Techs with no matching icons should produce empty string."""
    result = create_icon_legend_svg(["nonexistent_abc", "nonexistent_xyz"])
    assert result == ""


def test_get_icon_data_uri_missing():
    """Missing icons should return None for data URI."""
    result = get_icon_data_uri("nonexistent_xyz")
    assert result is None
