"""Tests for the Role enum + privilege ordering."""

from __future__ import annotations

import pytest

from app.roles import Role


def test_role_string_values_are_stable():
    assert Role.owner.value == "owner"
    assert Role.admin.value == "admin"
    assert Role.user.value == "user"
    assert Role.readonly.value == "readonly"


def test_role_rank_is_monotone():
    ranks = [Role.readonly.rank, Role.user.rank, Role.support.rank,
             Role.operator.rank, Role.admin.rank, Role.owner.rank]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


@pytest.mark.parametrize(
    ("higher", "lower"),
    [
        (Role.owner, Role.admin),
        (Role.owner, Role.readonly),
        (Role.admin, Role.operator),
        (Role.operator, Role.support),
        (Role.support, Role.user),
        (Role.user, Role.readonly),
    ],
)
def test_higher_role_implies_lower(higher: Role, lower: Role):
    assert higher.implies(lower)
    assert not lower.implies(higher)


def test_role_implies_self():
    for r in Role:
        assert r.implies(r)
