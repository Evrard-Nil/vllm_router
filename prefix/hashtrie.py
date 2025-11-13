# Copyright 2024-2025 The vLLM Production Stack Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Generator, Optional, Set, Tuple

import xxhash

logger = logging.getLogger(__name__)


class TrieNode:
    def __init__(self):
        self.children = {}
        self.endpoints = set()
        self.last_accessed = time.time()

        # assign a lock for each trie node.
        # this assures that each node will only be accessed by one co-routine
        # at a time.
        self.lock = asyncio.Lock()


class HashTrie:
    def __init__(
        self,
        chunk_size: int = 128,
        max_nodes: int = 10000,
        eviction_batch_size: int = 100,
    ):
        """
        Initialize the HashTrie.
        Args:
            chunk_size (int): the string chunk size (in terms of # characters)
            max_nodes (int): maximum number of nodes before eviction starts
            eviction_batch_size (int): number of nodes to evict at once when limit is reached
        """
        self.root = TrieNode()
        self.chunk_size = chunk_size
        self.max_nodes = max_nodes
        self.eviction_batch_size = eviction_batch_size
        self.node_count = 1  # Start with 1 for the root node
        self.eviction_lock = asyncio.Lock()

    def _chunk_and_hash(self, request: str) -> Generator[int, None, None]:
        """
        Chunk and hash the request.
        Args:
            request (str): The request to chunk and hash.
        Returns:
            Generator[int, None, None]: A generator that yields a hash for each
            chunk.
        """

        for i in range(0, len(request), self.chunk_size):
            yield xxhash.xxh64(request[i : i + self.chunk_size]).intdigest()

    async def _collect_nodes_for_eviction(
        self, node: TrieNode, nodes_list: list
    ) -> None:
        """
        Recursively collect all nodes for eviction analysis.
        Args:
            node (TrieNode): Current node to process
            nodes_list (list): List to collect nodes into
        """
        async with node.lock:
            nodes_list.append(node)
            for child in node.children.values():
                await self._collect_nodes_for_eviction(child, nodes_list)

    async def _evict_lru_nodes(self) -> None:
        """
        Evict least recently used nodes to prevent OOM.
        """
        async with self.eviction_lock:
            if self.node_count <= self.max_nodes:
                return

            logger.info(
                f"Starting LRU eviction: current nodes={self.node_count}, max_nodes={self.max_nodes}"
            )

            # Collect all nodes
            all_nodes = []
            await self._collect_nodes_for_eviction(self.root, all_nodes)

            # Sort by last_accessed time (oldest first)
            all_nodes.sort(key=lambda n: n.last_accessed)

            # Calculate how many nodes to evict
            nodes_to_evict = min(
                self.eviction_batch_size, self.node_count - self.max_nodes
            )

            # Evict the oldest nodes (excluding root)
            evicted_count = 0
            for i, node in enumerate(all_nodes):
                if node is self.root:  # Never evict the root
                    continue
                if evicted_count >= nodes_to_evict:
                    break

                # Find parent and remove this child
                parent = self._find_parent_node(self.root, node)
                if parent:
                    async with parent.lock:
                        # Find the key to remove
                        for key, child in parent.children.items():
                            if child is node:
                                del parent.children[key]
                                self.node_count -= 1
                                evicted_count += 1
                                break

            logger.info(
                f"LRU eviction completed: evicted {evicted_count} nodes, new count={self.node_count}"
            )

    def _find_parent_node(
        self, current: TrieNode, target: TrieNode
    ) -> Optional["TrieNode"]:
        """
        Find the parent of a target node.
        Args:
            current (TrieNode): Current node in search
            target (TrieNode): Node whose parent we're looking for
        Returns:
            Optional[TrieNode]: Parent node or None if not found
        """
        for child in current.children.values():
            if child is target:
                return current
            parent = self._find_parent_node(child, target)
            if parent:
                return parent
        return None

    async def insert(self, request: str, endpoint: str) -> None:
        """
        Insert the request and endpoint into the trie.
        Args:
            request (str): The request to insert.
            endpoint (str): The endpoint to insert.
        """
        node = self.root
        async with node.lock:
            node.endpoints.add(endpoint)
            node.last_accessed = time.time()

        nodes_created = 0
        for chunk_hash in self._chunk_and_hash(request):
            async with node.lock:
                if chunk_hash not in node.children:
                    node.children[chunk_hash] = TrieNode()
                    nodes_created += 1
                node = node.children[chunk_hash]
            async with node.lock:
                node.endpoints.add(endpoint)
                node.last_accessed = time.time()

        # Update node count and trigger eviction if needed
        self.node_count += nodes_created
        if self.node_count > self.max_nodes:
            await self._evict_lru_nodes()

    async def longest_prefix_match(
        self, request: str, available_endpoints: Set[str] = set()
    ) -> Tuple[int, Set[str]]:
        """
        Find the longest matching prefix using hashed chunks.
        Args:
            request (str): The request to find the longest matching prefix.
            available_endpoints (Set[str]): The endpoints that are available.
        """
        node = self.root
        match_length = 0
        selected_endpoints = available_endpoints

        # Update root access time
        async with node.lock:
            node.last_accessed = time.time()

        for chunk_hash in self._chunk_and_hash(request):
            async with node.lock:
                node = node.children.get(chunk_hash)
            if not node:
                break
            async with node.lock:
                # Update access time for LRU tracking
                node.last_accessed = time.time()
                endpoints = node.endpoints.copy()
            intersection = endpoints.intersection(selected_endpoints)
            # reached longest prefix match in currently-available endpoints.
            if not intersection:
                break
            match_length += self.chunk_size
            selected_endpoints = intersection

        return match_length, selected_endpoints
