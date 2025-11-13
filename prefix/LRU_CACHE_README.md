# LRU Cache Implementation for PrefixAware Router

## Overview

The prefixaware cache now includes LRU (Least Recently Used) eviction logic to prevent Out of Memory (OOM) issues. This implementation ensures that the cache size remains bounded while maintaining good performance for frequently accessed prefixes.

## Features

### LRU Eviction
- **Automatic eviction**: When the cache exceeds `max_nodes`, the least recently used nodes are automatically evicted
- **Batch eviction**: Nodes are evicted in batches (`eviction_batch_size`) to improve performance
- **Access time tracking**: Each node tracks its last access time for LRU decisions
- **Root protection**: The root node is never evicted to maintain cache integrity

### Configuration Options
- `max_nodes`: Maximum number of nodes before eviction starts (default: 10,000)
- `eviction_batch_size`: Number of nodes to evict at once (default: 100)
- `chunk_size`: Size of text chunks for hashing (default: 128 characters)

## Implementation Details

### TrieNode Changes
```python
class TrieNode:
    def __init__(self):
        self.children = {}
        self.endpoints = set()
        self.last_accessed = time.time()  # New: Track access time
        self.lock = asyncio.Lock()
```

### HashTrie Changes
```python
class HashTrie:
    def __init__(self, max_nodes=10000, eviction_batch_size=100, chunk_size=128):
        self.max_nodes = max_nodes
        self.eviction_batch_size = eviction_batch_size
        self.node_count = 1  # Track total nodes
        self.eviction_lock = asyncio.Lock()  # Protect eviction process
```

### Key Methods

#### `_evict_lru_nodes()`
- Collects all nodes in the trie
- Sorts by `last_accessed` time (oldest first)
- Evicts the oldest nodes in batches
- Updates node count accordingly

#### Access Time Updates
- `insert()`: Updates access time for all traversed nodes
- `longest_prefix_match()`: Updates access time for matched nodes

## Usage

### Basic Usage
```python
from prefix.hashtrie import HashTrie

# Create with default settings
trie = HashTrie()

# Create with custom limits
trie = HashTrie(max_nodes=1000, eviction_batch_size=50, chunk_size=64)
```

### Router Configuration
```python
from routers.routing_logic import PrefixAwareRouter

router = PrefixAwareRouter(
    max_nodes=5000,           # Maximum cache size
    eviction_batch_size=100,  # Batch eviction size
    chunk_size=64            # Chunk size for hashing
)
```

## Performance Characteristics

### Memory Usage
- **Bounded**: Memory usage is limited by `max_nodes`
- **Predictable**: Memory growth stops when eviction starts
- **Efficient**: Batch eviction minimizes performance impact

### Access Patterns
- **Cache-friendly**: Frequently accessed prefixes are retained
- **Adaptive**: Cache automatically adapts to access patterns
- **Graceful degradation**: Performance degrades gracefully under memory pressure

## Testing

### Run Tests
```bash
# Basic LRU functionality test
uv run test_lru_cache.py

# Memory management test
uv run test_memory_usage.py

# Debug eviction behavior
uv run debug_eviction.py
```

### Test Coverage
- ✅ LRU eviction triggers correctly
- ✅ Node count stays bounded
- ✅ Recently accessed items are preferred
- ✅ Prefix matching works with LRU
- ✅ Memory usage remains controlled

## Monitoring

### Logging
The implementation provides detailed logging for eviction events:
```
INFO:prefix.hashtrie:Starting LRU eviction: current nodes=10050, max_nodes=10000
INFO:prefix.hashtrie:LRU eviction completed: evicted 50 nodes, new count=10000
```

### Metrics
- `node_count`: Current number of nodes in cache
- `eviction_count`: Number of nodes evicted in each batch
- Memory usage can be monitored via system tools

## Best Practices

### Configuration Guidelines
1. **max_nodes**: Set based on available memory and expected load
2. **eviction_batch_size**: Set to 1-10% of max_nodes for balanced performance
3. **chunk_size**: Smaller chunks create more nodes but better granularity

### Performance Tips
1. Monitor eviction logs to tune configuration
2. Use larger chunk sizes for high-throughput scenarios
3. Adjust batch size based on eviction frequency

### Memory Estimation
Approximate memory usage per node:
- Node object: ~200 bytes
- Children dict: Varies by fan-out
- Endpoints set: ~50 bytes per endpoint
- Lock object: ~100 bytes

Total: ~350-500 bytes per node (varies by usage pattern)

## Migration

### From Non-LRU Version
The LRU implementation is backward compatible. Existing code will work without changes, but you can now configure LRU parameters:

```python
# Old code (still works)
router = PrefixAwareRouter()

# New code with LRU configuration
router = PrefixAwareRouter(max_nodes=5000, eviction_batch_size=100)
```

## Troubleshooting

### Common Issues

1. **Eviction not triggering**
   - Check if `max_nodes` is set too high
   - Monitor `node_count` in logs
   - Verify chunk size isn't creating too few nodes

2. **Too frequent eviction**
   - Increase `max_nodes` if memory allows
   - Increase `eviction_batch_size` to reduce frequency
   - Consider larger `chunk_size` to reduce node creation

3. **Poor cache hit rate**
   - Check if `eviction_batch_size` is too large
   - Monitor access patterns
   - Consider increasing `max_nodes`

### Debug Commands
```python
# Check current state
print(f"Nodes: {trie.node_count}/{trie.max_nodes}")

# Force eviction (for testing)
await trie._evict_lru_nodes()
```

## Future Enhancements

Potential improvements for future versions:
1. **Adaptive sizing**: Automatically adjust limits based on memory pressure
2. **Priority eviction**: Consider endpoint importance in eviction decisions
3. **Statistics**: Track hit rates and eviction patterns
4. **Persistent cache**: Option to persist cache across restarts
5. **Multi-level cache**: L1/L2 cache hierarchy for better performance
