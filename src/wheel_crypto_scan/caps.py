"""Capping an item list without letting one kind of item crowd out the others.

Every per-binary limit exists for one reason: an object with half a million matching
symbols must not produce an unbounded JSON line. None of them exists to choose which
evidence survives, and until this module they did exactly that, because each one sorted
and cut and the sort key has nothing to do with what an item is worth.

What that cost, against the shipped ruleset: `openssl_banner` is tenth of thirteen
string group names, so seventy `mbedtls_` runs take the OpenSSL banner with them and the
object then reports `openssl_linkage: none` while carrying it. `libsodium` sorts before
`openssl`, so seventy defined `crypto_box_*` symbols do the same to a defined
`EVP_DigestInit_ex`. Worst of the three, a Rust object's crates sorted by name and cut at
128 dropped `ring` behind an `anyhow` and read `NO_CRYPTO_DETECTED` with nothing recorded
at all.

The fix is to notice how little a consumer keys on, which is what each type's `cap_key`
states: a string's group, a symbol's group and binding, a crate's name, an error's stage
and kind. Two items sharing a `cap_key` are interchangeable to every consumer, so a cap
that keeps one of each before filling the remainder answers every question the record is
read for.

**This is only sound over a total `sort_key`.** The callers hand over sets, whose
iteration order is not stable across runs, and `sorted` is stable -- so two items whose
`sort_key` ties would keep the order the set happened to yield, and the record would
depend on the hash seed. Every `sort_key` here covers every field `==` compares, and
`tests/test_caps.py` pins that for all six types rather than leaving it to be noticed.

Lives at the package's top level, not under `binfmt/`, though every per-binary caller of
`cap` is a `binfmt` reader: this module has no binary-format knowledge of its own, and
`record.py` needs it too, to cap `evidence.errors` through `ScanError.cap_key`. Staying
under `binfmt/` would have made the serialisation layer transitively import every
structural reader -- pyelftools included -- just to cap a list of errors.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
from typing import Protocol, TypeVar


class Capped(Protocol):
    """An item that knows what makes it interchangeable and how it sorts."""

    def cap_key(self) -> Hashable: ...

    def sort_key(self) -> object: ...


T = TypeVar("T", bound=Capped)


def cap(
    items: Iterable[T], limit: int, *, pin: Callable[[T], bool] | None = None
) -> tuple[tuple[T, ...], bool]:
    """Cut `items` to `limit`, keeping a representative of every `cap_key` first.

    Returns the kept items, sorted, and whether anything was dropped. Four passes over
    `ordered` fill the room in order of what a reader would miss most:

      1. one per `cap_key` among the pinned items, when `pin` is given;
      2. one per `cap_key` among the rest;
      3. whatever pinned items are still left, in sort order;
      4. whatever of the rest is still left, in sort order.

    `pin` exists for the one list whose entries are not all claimed by something. A
    string or a symbol only reaches here because a group matched it, so every entry is
    evidence and pass 2 is the whole job. A crate list is also an inventory, most of it
    named by nothing, and an unclaimed crate must not take the room a claimed one needs.

    When the keys alone outnumber `limit` the lowest-sorting ones win, which is
    arbitrary -- but no more arbitrary than the truncation it replaces, and stable.
    `ruleset_loader.parse_ruleset` refuses a ruleset whose limits are small enough for that to
    happen to the shipped groups, so reaching it means someone chose to.

    Every pass scans `ordered` itself rather than a `pinned`/`rest` split materialised
    up front: those two lists, plus a third for whatever did not make the cut, used to
    hold references to nearly every input item at once. The sort dominates this
    function's peak memory regardless -- `sorted` itself has to hold `ordered` plus one
    key tuple per item -- so this is not a peak-memory fix; it shrinks what the *tail*
    after the sort needs to keep alive. `kept_at`, the set of indices already kept, is
    bounded by `limit` rather than by how many items came in, since an index is only
    added when `kept` grows. `pinned_at` is not bounded the same way: it is `pin`'s
    answer for every index, one bool per item, computed once so `pin` runs once per
    item rather than twice -- a real reduction on the three item-reference lists it
    replaces, but not `O(limit)`.
    """
    ordered = sorted(items, key=lambda item: item.sort_key())
    if len(ordered) <= limit:
        return tuple(ordered), False

    pinned_at = [pin(item) for item in ordered] if pin is not None else None
    passes = (True, False) if pinned_at is not None else (False,)

    kept: list[T] = []
    kept_at: set[int] = set()
    seen: set[Hashable] = set()

    for wants_pinned in passes:
        for index, item in enumerate(ordered):
            if len(kept) >= limit:
                break
            if index in kept_at or (pinned_at is not None and pinned_at[index] != wants_pinned):
                continue
            identity = item.cap_key()
            if identity in seen:
                continue
            seen.add(identity)
            kept.append(item)
            kept_at.add(index)

    for wants_pinned in passes:
        for index, item in enumerate(ordered):
            if len(kept) >= limit:
                break
            if index in kept_at or (pinned_at is not None and pinned_at[index] != wants_pinned):
                continue
            kept.append(item)
            kept_at.add(index)

    return tuple(sorted(kept, key=lambda item: item.sort_key())), True
