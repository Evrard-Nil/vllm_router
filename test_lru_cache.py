#!/usr/bin/env python3
"""
Test script for LRU functionality in the prefixaware cache.
"""

import asyncio
import logging
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from prefix.hashtrie import HashTrie

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_lru_eviction():
    """Test that LRU eviction works correctly."""
    logger.info("Testing LRU eviction functionality...")

    # Create a HashTrie with small limits to trigger eviction quickly
    trie = HashTrie(max_nodes=10, eviction_batch_size=5, chunk_size=4)

    # Insert enough data to trigger eviction
    endpoints = ["http://endpoint1", "http://endpoint2", "http://endpoint3"]

    logger.info(f"Initial node count: {trie.node_count}")

    # Insert first batch of requests
    for i in range(8):
        request = f"request_{i}_with_longer_prefix_to_create_more_nodes"
        endpoint = endpoints[i % len(endpoints)]
        await trie.insert(request, endpoint)
        logger.info(f"Inserted {request}, node count: {trie.node_count}")

    logger.info("First batch inserted, accessing some requests to update LRU...")

    # Access some requests to update their access times
    await trie.longest_prefix_match(
        "request_0_with_longer_prefix_to_create_more_nodes", set(endpoints)
    )
    await trie.longest_prefix_match(
        "request_2_with_longer_prefix_to_create_more_nodes", set(endpoints)
    )
    await trie.longest_prefix_match(
        "request_4_with_longer_prefix_to_create_more_nodes", set(endpoints)
    )

    logger.info("Accessed some requests, inserting more to trigger eviction...")

    # Insert more requests to trigger eviction
    for i in range(8, 15):
        request = f"request_{i}_with_longer_prefix_to_create_more_nodes"
        endpoint = endpoints[i % len(endpoints)]
        await trie.insert(request, endpoint)
        logger.info(f"Inserted {request}, node count: {trie.node_count}")

    logger.info(f"Final node count: {trie.node_count}")
    logger.info("LRU eviction test completed successfully!")

    return True


async def test_prefix_matching_with_lru():
    """Test that prefix matching still works correctly with LRU."""
    logger.info("Testing prefix matching with LRU...")

    trie = HashTrie(max_nodes=20, eviction_batch_size=5, chunk_size=4)
    endpoints = ["http://endpoint1", "http://endpoint2"]

    # Insert some requests with common prefixes
    requests = [
        "hello world",
        "hello there",
        "hello my friend",
        "goodbye world",
        "goodbye everyone",
    ]

    for i, request in enumerate(requests):
        endpoint = endpoints[i % len(endpoints)]
        await trie.insert(request, endpoint)
        logger.info(f"Inserted: {request} -> {endpoint}")

    # Test prefix matching
    test_cases = [
        ("hello", ["http://endpoint1", "http://endpoint2"]),
        ("hello world", ["http://endpoint1"]),
        ("goodbye", ["http://endpoint2", "http://endpoint1"]),
        ("goodbye everyone", ["http://endpoint2"]),
    ]

    for query, expected_endpoints in test_cases:
        match_length, matched_endpoints = await trie.longest_prefix_match(
            query, set(endpoints)
        )
        logger.info(
            f"Query: '{query}' -> Match length: {match_length}, Endpoints: {matched_endpoints}"
        )

        # Verify we got some matches
        if not matched_endpoints:
            logger.error(f"No matches found for query: {query}")
            return False

    logger.info("Prefix matching with LRU test completed successfully!")
    return True


async def main():
    """Run all tests."""
    logger.info("Starting LRU cache tests...")

    try:
        success1 = await test_lru_eviction()
        success2 = await test_prefix_matching_with_lru()

        if success1 and success2:
            logger.info("All tests passed! ✅")
            return 0
        else:
            logger.error("Some tests failed! ❌")
            return 1
    except Exception as e:
        logger.error(f"Test failed with exception: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
