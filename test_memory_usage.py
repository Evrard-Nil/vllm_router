#!/usr/bin/env python3
"""
Test script to verify memory management and LRU functionality.
"""

import asyncio
import logging
import sys
import os
import psutil
import gc

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from prefix.hashtrie import HashTrie

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_memory_usage():
    """Get current memory usage in MB."""
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024


async def test_memory_management():
    """Test that memory usage stays bounded with LRU eviction."""
    logger.info("Testing memory management with LRU eviction...")

    # Create a HashTrie with reasonable limits
    trie = HashTrie(max_nodes=1000, eviction_batch_size=100, chunk_size=64)

    initial_memory = get_memory_usage()
    logger.info(f"Initial memory usage: {initial_memory:.2f} MB")

    endpoints = ["http://endpoint1", "http://endpoint2", "http://endpoint3"]

    # Insert many requests to test memory bounds
    for i in range(500):
        request = f"request_{i}_with_some_content_to_create_nodes"
        endpoint = endpoints[i % len(endpoints)]
        await trie.insert(request, endpoint)

        if i % 50 == 0:
            current_memory = get_memory_usage()
            logger.info(
                f"Inserted {i} requests, nodes: {trie.node_count}, memory: {current_memory:.2f} MB"
            )

    final_memory = get_memory_usage()
    memory_increase = final_memory - initial_memory

    logger.info(f"Final memory usage: {final_memory:.2f} MB")
    logger.info(f"Memory increase: {memory_increase:.2f} MB")
    logger.info(f"Final node count: {trie.node_count}")

    # Verify that node count is bounded
    if trie.node_count <= trie.max_nodes + trie.eviction_batch_size:
        logger.info("✅ Node count is properly bounded!")
        return True
    else:
        logger.error(f"❌ Node count {trie.node_count} exceeds expected bounds")
        return False


async def test_lru_behavior():
    """Test LRU behavior with access patterns."""
    logger.info("Testing LRU behavior...")

    trie = HashTrie(max_nodes=50, eviction_batch_size=10, chunk_size=32)
    endpoints = ["http://endpoint1"]

    # Insert initial requests
    requests = []
    for i in range(20):
        request = f"initial_request_{i}"
        requests.append(request)
        await trie.insert(request, endpoints[0])

    logger.info(f"After initial insertions: {trie.node_count} nodes")

    # Access some requests to make them "recently used"
    for i in [0, 2, 4, 6, 8]:  # Access every other request
        await trie.longest_prefix_match(requests[i], set(endpoints))

    logger.info("Accessed some requests, inserting more to trigger eviction...")

    # Insert more requests to trigger eviction
    for i in range(20, 40):
        request = f"new_request_{i}"
        await trie.insert(request, endpoints[0])

    logger.info(f"After new insertions: {trie.node_count} nodes")

    # Test that recently accessed requests are still available
    still_available = 0
    for i in [0, 2, 4, 6, 8]:  # The ones we accessed
        match_length, matched_endpoints = await trie.longest_prefix_match(
            requests[i], set(endpoints)
        )
        if matched_endpoints:
            still_available += 1

    logger.info(f"Recently accessed requests still available: {still_available}/5")

    # Test that non-accessed requests are more likely to be evicted
    still_available_old = 0
    for i in [1, 3, 5, 7, 9]:  # The ones we didn't access
        match_length, matched_endpoints = await trie.longest_prefix_match(
            requests[i], set(endpoints)
        )
        if matched_endpoints:
            still_available_old += 1

    logger.info(f"Non-accessed old requests still available: {still_available_old}/5")

    # LRU should prefer keeping recently accessed items
    if still_available >= still_available_old:
        logger.info("✅ LRU behavior is working correctly!")
        return True
    else:
        logger.error("❌ LRU behavior is not working as expected")
        return False


async def main():
    """Run all memory management tests."""
    logger.info("Starting memory management tests...")

    try:
        success1 = await test_memory_management()
        success2 = await test_lru_behavior()

        if success1 and success2:
            logger.info("All memory management tests passed! ✅")
            return 0
        else:
            logger.error("Some memory management tests failed! ❌")
            return 1
    except Exception as e:
        logger.error(f"Test failed with exception: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
