#!/usr/bin/env python3
"""
Debug script to understand eviction behavior.
"""

import asyncio
import logging
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from prefix.hashtrie import HashTrie

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def debug_eviction():
    """Debug eviction behavior with very small limits."""
    logger.info("Debugging eviction behavior...")

    # Create a HashTrie with very small limits
    trie = HashTrie(max_nodes=5, eviction_batch_size=2, chunk_size=4)

    logger.info(f"Initial node count: {trie.node_count}")
    logger.info(f"Max nodes: {trie.max_nodes}")
    logger.info(f"Eviction batch size: {trie.eviction_batch_size}")

    endpoints = ["http://endpoint1"]

    # Insert requests one by one and observe
    for i in range(10):
        request = f"req{i}"  # Very short requests
        await trie.insert(request, endpoints[0])
        logger.info(f"After inserting '{request}': {trie.node_count} nodes")

        if trie.node_count > trie.max_nodes:
            logger.info(
                f"  -> Node count exceeds max_nodes, eviction should have occurred"
            )
        else:
            logger.info(f"  -> Node count within limits")

    logger.info(f"Final node count: {trie.node_count}")


async def main():
    """Run debug test."""
    await debug_eviction()


if __name__ == "__main__":
    asyncio.run(main())
