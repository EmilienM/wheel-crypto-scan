"""Capping a match list without letting one kind of match crowd out the others.

Every per-binary limit exists for one reason: an object with half a million matching
symbols must not produce an unbounded JSON line. None of them exists to choose which
evidence survives, and until this module they did exactly that, because each one sorted
and cut and the sort key has nothing to do with what a match is worth.

What that cost, against the shipped ruleset: `openssl_banner` is tenth of thirteen
string group names, so seventy `mbedtls_` runs take the OpenSSL banner with them and the
object then reports `openssl_linkage: none` while carrying it. `libsodium` sorts before
`openssl`, so seventy defined `crypto_box_*` symbols do the same to a defined
`EVP_DigestInit_ex`. Worst of the three, a Rust object's crates sorted by name and cut at
128 dropped `ring` behind an `anyhow` and read `NO_CRYPTO_DETECTED` with nothing recorded
at all.

The fix is to notice how little the rules key on, which is what each type's `cap_key`
states: a string's group, a symbol's group and binding, a crate's name. Two matches
sharing a `cap_key` are interchangeable to every consumer, so a cap that keeps one of
each before filling the remainder answers every question the record is read for.

**This is only sound over a total `sort_key`.** The callers hand over sets, whose
iteration order is not stable across runs, and `sorted` is stable -- so two items whose
`sort_key` ties would keep the order the set happened to yield, and the record would
depend on the hash seed. Every `sort_key` here covers every field `==` compares, and
`tests/test_caps.py` pins that for all three types rather than leaving it to be noticed.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
from typing import Protocol, TypeVar


class Capped(Protocol):
    """A match that knows what makes it interchangeable and how it sorts."""

    def cap_key(self) -> Hashable: ...

    def sort_key(self) -> object: ...


T = TypeVar("T", bound=Capped)


def cap(
    items: Iterable[T], limit: int, *, pin: Callable[[T], bool] | None = None
) -> tuple[tuple[T, ...], bool]:
    """Cut `items` to `limit`, keeping a representative of every `cap_key` first.

    Returns the kept items, sorted, and whether anything was dropped. Three passes fill
    the room in order of what a reader would miss most:

      1. one per `cap_key` among the pinned items, when `pin` is given;
      2. one per `cap_key` among the rest;
      3. everything left, in sort order.

    `pin` exists for the one list whose entries are not all claimed by something. A
    string or a symbol only reaches here because a group matched it, so every entry is
    evidence and pass 2 is the whole job. A crate list is also an inventory, most of it
    named by nothing, and an unclaimed crate must not take the room a claimed one needs.

    When the keys alone outnumber `limit` the lowest-sorting ones win, which is
    arbitrary -- but no more arbitrary than the truncation it replaces, and stable.
    `ruleset_loader.parse_ruleset` refuses a ruleset whose limits are small enough for that to
    happen to the shipped groups, so reaching it means someone chose to.
    """
    ordered = sorted(items, key=lambda item: item.sort_key())
    if len(ordered) <= limit:
        return tuple(ordered), False

    pinned = [item for item in ordered if pin(item)] if pin is not None else []
    rest = [item for item in ordered if pin is None or not pin(item)]

    kept: list[T] = []
    seen: set[Hashable] = set()
    leftovers: list[T] = []
    for bucket in (pinned, rest):
        for item in bucket:
            identity = item.cap_key()
            if identity in seen:
                leftovers.append(item)
            elif len(kept) < limit:
                seen.add(identity)
                kept.append(item)
            else:
                leftovers.append(item)
    for item in leftovers:
        if len(kept) >= limit:
            break
        kept.append(item)
    return tuple(sorted(kept, key=lambda item: item.sort_key())), True
