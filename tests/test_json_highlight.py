"""Sanity check for the json_highlight Jinja filter used on the audit page."""

from __future__ import annotations

from app.templating import _json_highlight


def test_basic_tokens_get_classed():
    out = str(_json_highlight({"key": "value", "n": 42, "b": True, "x": None}))
    assert '<span class="jsx-key">' in out
    assert '<span class="jsx-str">&#34;value&#34;</span>' in out
    assert '<span class="jsx-num">42</span>' in out
    assert '<span class="jsx-lit">true</span>' in out
    assert '<span class="jsx-lit">null</span>' in out
    assert '<span class="jsx-pun">{</span>' in out


def test_xss_payloads_are_escaped():
    # Keys and string values containing HTML must come out escaped — the
    # filter renders its own spans but never trusts payload bytes.
    out = str(_json_highlight({"<script>": "</span><img src=x>"}))
    assert "<script>" not in out
    assert "</span><img" not in out
    assert "&lt;script&gt;" in out
    assert "&lt;/span&gt;&lt;img" in out


def test_none_and_malformed_string_inputs():
    assert str(_json_highlight(None)) == ""
    # A non-JSON string round-trips as a single escaped string span.
    out = str(_json_highlight("not json at all <b>"))
    assert 'class="jsx-str"' in out
    assert "<b>" not in out


def test_list_input_and_nested():
    out = str(_json_highlight([{"a": 1}, {"b": [2, 3]}]))
    assert out.startswith('<span class="jsx-pun">[</span>')
    assert '<span class="jsx-num">1</span>' in out
    assert '<span class="jsx-num">3</span>' in out
