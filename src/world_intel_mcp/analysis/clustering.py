"""News article clustering using Jaccard similarity.

Groups news articles by content similarity to reduce noise
and identify story clusters.
"""

import logging
import re

logger = logging.getLogger("world-intel-mcp.analysis.clustering")

_STOPWORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "shall", "in", "on", "at", "to",
    "for", "of", "and", "or", "but", "not", "no", "nor", "with", "from",
    "by", "it", "its", "that", "this", "these", "those", "he", "she",
    "they", "we", "you", "i", "me", "my", "his", "her", "our", "your",
    "their", "what", "which", "who", "whom", "how", "when", "where",
    "why", "if", "then", "than", "so", "as", "up", "out", "about",
    "into", "over", "after", "before", "between", "under", "again",
    "also", "just", "more", "most", "other", "some", "such", "very",
    "new", "said", "says", "one", "two", "first",
})


def _tokenize(text: str) -> set[str]:
    """Extract meaningful word tokens from text."""
    words = re.findall(r'[a-z]{3,}', text.lower())
    return {w for w in words if w not in _STOPWORDS}


def jaccard_similarity(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity between two sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def cluster_articles(
    articles: list[dict],
    similarity_threshold: float = 0.3,
    title_field: str = "title",
) -> list[dict]:
    """Cluster articles by title similarity.

    Args:
        articles: List of article dicts.
        similarity_threshold: Minimum Jaccard similarity to merge.
        title_field: Key containing the article title.

    Returns:
        List of cluster dicts with representative article and member count.
    """
    if not articles:
        return []

    # Tokenize all titles
    tokenized = []
    for article in articles:
        title = article.get(title_field, "") or ""
        tokens = _tokenize(title)
        tokenized.append(tokens)

    # Greedy single-linkage clustering
    assigned = [False] * len(articles)
    clusters: list[dict] = []

    for i in range(len(articles)):
        if assigned[i]:
            continue

        cluster_members = [i]
        assigned[i] = True

        for j in range(i + 1, len(articles)):
            if assigned[j]:
                continue

            # Check similarity against cluster representative (first member)
            sim = jaccard_similarity(tokenized[i], tokenized[j])
            if sim >= similarity_threshold:
                cluster_members.append(j)
                assigned[j] = True

        # Build cluster output
        representative = articles[cluster_members[0]]
        clusters.append({
            "representative": representative,
            "member_count": len(cluster_members),
            "member_indices": cluster_members,
        })

    # Sort by member count descending
    clusters.sort(key=lambda c: c["member_count"], reverse=True)
    return clusters
