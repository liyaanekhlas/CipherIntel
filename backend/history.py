"""
SentinelScope Search History Module.

Maintains in-memory rolling search history per user (maximum 2 recent items).
Strict constraint: All data is stored in in-memory Python structures.
"""

from typing import Any, Dict, List

# In-memory dictionary mapping username -> list of search objects (max 2 items)
SEARCH_HISTORY: Dict[str, List[Dict[str, Any]]] = {}


def record_search(username: str, search_item: Dict[str, Any]) -> None:
    """
    Prepends a search record to the user's history and retains strictly the 2 most recent items.
    """
    if username not in SEARCH_HISTORY:
        SEARCH_HISTORY[username] = []

    # Prepend to history
    SEARCH_HISTORY[username].insert(0, search_item)

    # Strictly keep the most recent 2 items
    SEARCH_HISTORY[username] = SEARCH_HISTORY[username][:2]


def get_history(username: str) -> List[Dict[str, Any]]:
    """
    Retrieves the list of up to 2 most recent searches for the given user.
    """
    return SEARCH_HISTORY.get(username, [])
