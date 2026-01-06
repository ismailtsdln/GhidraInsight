"""
Performance Optimization Module for GhidraInsight

This module provides memory-efficient processing, performance optimization,
caching strategies, and sub-second analysis capabilities for small binaries.

Author: GhidraInsight Team
License: Apache 2.0
"""

import gc
import hashlib
import logging
import mmap
import os
import pickle
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)


class OptimizationLevel(Enum):
    """Optimization levels"""

    NONE = "none"
    BASIC = "basic"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


class CacheStrategy(Enum):
    """Cache eviction strategies"""

    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live


@dataclass
class MemoryProfile:
    """Memory usage profile"""

    rss: int  # Resident Set Size
    vms: int  # Virtual Memory Size
    shared: int  # Shared memory
    peak_rss: int
    timestamp: float = field(default_factory=time.time)


@dataclass
class PerformanceMetrics:
    """Performance metrics"""

    execution_time: float = 0.0
    memory_peak: int = 0
    memory_average: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    io_operations: int = 0
    cpu_time: float = 0.0
    throughput: float = 0.0  # bytes per second


@dataclass
class OptimizationConfig:
    """Configuration for optimization"""

    optimization_level: OptimizationLevel = OptimizationLevel.AGGRESSIVE
    enable_cache: bool = True
    cache_strategy: CacheStrategy = CacheStrategy.LRU
    cache_size: int = 1000
    cache_ttl: int = 3600  # seconds
    enable_parallel: bool = True
    max_workers: int = 8
    chunk_size: int = 1024 * 1024  # 1MB
    memory_limit: int = 1024 * 1024 * 1024  # 1GB
    enable_gc_optimization: bool = True
    enable_memory_mapping: bool = True
    enable_profiling: bool = False


class MemoryEfficientBuffer:
    """Memory-efficient circular buffer"""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.buffer = []
        self.write_pos = 0
        self.read_pos = 0
        self.count = 0

    def write(self, data: Any):
        """Write data to buffer"""
        if self.count < self.max_size:
            self.buffer.append(data)
            self.count += 1
        else:
            self.buffer[self.write_pos] = data
            self.write_pos = (self.write_pos + 1) % self.max_size

    def read(self) -> Optional[Any]:
        """Read data from buffer"""
        if self.count == 0:
            return None

        data = self.buffer[self.read_pos]
        self.read_pos = (self.read_pos + 1) % self.max_size
        self.count -= 1
        return data

    def clear(self):
        """Clear buffer and free memory"""
        self.buffer.clear()
        self.write_pos = 0
        self.read_pos = 0
        self.count = 0
        gc.collect()


class AdaptiveCache:
    """Adaptive cache with multiple eviction strategies"""

    def __init__(
        self,
        max_size: int = 1000,
        strategy: CacheStrategy = CacheStrategy.LRU,
        ttl: int = 3600,
    ):
        self.max_size = max_size
        self.strategy = strategy
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.access_count: Dict[str, int] = {}
        self.access_time: Dict[str, float] = {}
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        if key not in self.cache:
            self.misses += 1
            return None

        # Check TTL
        if self.strategy == CacheStrategy.TTL:
            if time.time() - self.access_time[key] > self.ttl:
                self.evict(key)
                self.misses += 1
                return None

        self.hits += 1
        self.access_count[key] = self.access_count.get(key, 0) + 1
        self.access_time[key] = time.time()

        # Move to end for LRU
        if self.strategy == CacheStrategy.LRU:
            self.cache.move_to_end(key)

        return self.cache[key]

    def put(self, key: str, value: Any):
        """Put item in cache"""
        if key in self.cache:
            # Update existing
            self.cache[key] = value
            self.access_time[key] = time.time()
            if self.strategy == CacheStrategy.LRU:
                self.cache.move_to_end(key)
            return

        # Check if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_one()

        self.cache[key] = value
        self.access_count[key] = 0
        self.access_time[key] = time.time()

    def _evict_one(self):
        """Evict one item based on strategy"""
        if self.strategy == CacheStrategy.LRU:
            # Remove oldest (first item)
            key = next(iter(self.cache))
            self.evict(key)

        elif self.strategy == CacheStrategy.LFU:
            # Remove least frequently used
            min_key = min(self.access_count.items(), key=lambda x: x[1])[0]
            self.evict(min_key)

        elif self.strategy == CacheStrategy.FIFO:
            # Remove first item
            key = next(iter(self.cache))
            self.evict(key)

        elif self.strategy == CacheStrategy.TTL:
            # Remove oldest access time
            min_key = min(self.access_time.items(), key=lambda x: x[1])[0]
            self.evict(min_key)

    def evict(self, key: str):
        """Evict specific key"""
        if key in self.cache:
            del self.cache[key]
            if key in self.access_count:
                del self.access_count[key]
            if key in self.access_time:
                del self.access_time[key]

    def clear(self):
        """Clear entire cache"""
        self.cache.clear()
        self.access_count.clear()
        self.access_time.clear()
        gc.collect()

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "strategy": self.strategy.value,
        }


class MemoryManager:
    """Memory management and monitoring"""

    def __init__(self, memory_limit: int = 1024 * 1024 * 1024):
        self.memory_limit = memory_limit
        self.process = psutil.Process(os.getpid())
        self.profiles: List[MemoryProfile] = []
        self.peak_memory = 0

    def get_current_memory(self) -> int:
        """Get current memory usage in bytes"""
        mem_info = self.process.memory_info()
        return mem_info.rss

    def get_available_memory(self) -> int:
        """Get available system memory"""
        return psutil.virtual_memory().available

    def is_memory_available(self, required_bytes: int) -> bool:
        """Check if required memory is available"""
        current = self.get_current_memory()
        return (current + required_bytes) < self.memory_limit

    def profile(self) -> MemoryProfile:
        """Create memory profile"""
        mem_info = self.process.memory_info()
        current_rss = mem_info.rss

        if current_rss > self.peak_memory:
            self.peak_memory = current_rss

        profile = MemoryProfile(
            rss=current_rss,
            vms=mem_info.vms,
            shared=getattr(mem_info, "shared", 0),
            peak_rss=self.peak_memory,
        )

        self.profiles.append(profile)
        return profile

    def optimize(self):
        """Optimize memory usage"""
        # Force garbage collection
        gc.collect()

        # Clear cache if memory is high
        current = self.get_current_memory()
        if current > self.memory_limit * 0.9:
            logger.warning(f"Memory usage high: {current / (1024**2):.2f} MB")
            gc.collect(2)  # Full collection

    def get_statistics(self) -> Dict[str, Any]:
        """Get memory statistics"""
        if not self.profiles:
            return {}

        avg_rss = sum(p.rss for p in self.profiles) / len(self.profiles)

        return {
            "current_mb": self.get_current_memory() / (1024**2),
            "peak_mb": self.peak_memory / (1024**2),
            "average_mb": avg_rss / (1024**2),
            "limit_mb": self.memory_limit / (1024**2),
            "available_mb": self.get_available_memory() / (1024**2),
            "utilization": self.get_current_memory() / self.memory_limit,
        }


class FastBinaryReader:
    """Fast, memory-efficient binary reader using memory mapping"""

    def __init__(self, file_path: str, enable_mmap: bool = True):
        self.file_path = file_path
        self.enable_mmap = enable_mmap
        self.file = None
        self.mmap_obj = None
        self.size = os.path.getsize(file_path)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        """Open file for reading"""
        self.file = open(self.file_path, "rb")

        if self.enable_mmap and self.size > 0:
            try:
                self.mmap_obj = mmap.mmap(
                    self.file.fileno(), 0, access=mmap.ACCESS_READ
                )
            except Exception as e:
                logger.warning(f"Memory mapping failed: {e}")
                self.mmap_obj = None

    def close(self):
        """Close file"""
        if self.mmap_obj:
            self.mmap_obj.close()
        if self.file:
            self.file.close()

    def read(self, offset: int = 0, length: Optional[int] = None) -> bytes:
        """Read bytes from file"""
        if length is None:
            length = self.size - offset

        if self.mmap_obj:
            return self.mmap_obj[offset : offset + length]
        else:
            self.file.seek(offset)
            return self.file.read(length)

    def read_chunk(self, chunk_size: int = 1024 * 1024):
        """Generator for reading file in chunks"""
        offset = 0
        while offset < self.size:
            chunk = self.read(offset, min(chunk_size, self.size - offset))
            yield chunk
            offset += len(chunk)

    def find_pattern(self, pattern: bytes, max_matches: int = -1) -> List[int]:
        """Fast pattern matching"""
        matches = []
        offset = 0

        if self.mmap_obj:
            # Use mmap.find for efficiency
            while True:
                pos = self.mmap_obj.find(pattern, offset)
                if pos == -1:
                    break
                matches.append(pos)
                if max_matches > 0 and len(matches) >= max_matches:
                    break
                offset = pos + 1
        else:
            # Fallback to chunked reading
            chunk_size = 1024 * 1024
            for chunk_offset, chunk in enumerate(self.read_chunk(chunk_size)):
                pos = 0
                while True:
                    idx = chunk.find(pattern, pos)
                    if idx == -1:
                        break
                    matches.append(chunk_offset * chunk_size + idx)
                    if max_matches > 0 and len(matches) >= max_matches:
                        return matches
                    pos = idx + 1

        return matches


def measure_performance(func: Callable) -> Callable:
    """Decorator to measure function performance"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process(os.getpid()).memory_info().rss

        try:
            result = func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            end_memory = psutil.Process(os.getpid()).memory_info().rss

            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory

            logger.debug(
                f"{func.__name__}: {execution_time:.3f}s, "
                f"Memory: {memory_delta / (1024**2):.2f} MB"
            )

    return wrapper


def cached_analysis(cache: AdaptiveCache):
    """Decorator for caching analysis results"""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key_parts = [func.__name__]
            for arg in args:
                if isinstance(arg, (str, int, float, bool)):
                    key_parts.append(str(arg))
                elif isinstance(arg, bytes):
                    key_parts.append(hashlib.md5(arg).hexdigest()[:8])

            cache_key = "|".join(key_parts)

            # Check cache
            result = cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit: {func.__name__}")
                return result

            # Execute function
            result = func(*args, **kwargs)

            # Store in cache
            cache.put(cache_key, result)

            return result

        return wrapper

    return decorator


class PerformanceOptimizer:
    """
    Main performance optimizer for GhidraInsight.
    Provides sub-second analysis for small binaries and memory-efficient processing.
    """

    def __init__(self, config: Optional[OptimizationConfig] = None):
        self.config = config or OptimizationConfig()
        self.memory_manager = MemoryManager(self.config.memory_limit)
        self.cache = AdaptiveCache(
            self.config.cache_size, self.config.cache_strategy, self.config.cache_ttl
        )
        self.metrics = PerformanceMetrics()

        # Configure garbage collection
        if self.config.enable_gc_optimization:
            self._optimize_gc()

    def _optimize_gc(self):
        """Optimize garbage collection settings"""
        # Increase GC thresholds for better performance
        gc.set_threshold(700, 10, 10)
        logger.info("Garbage collection optimized")

    def analyze_small_binary(self, file_path: str) -> Dict[str, Any]:
        """
        Sub-second analysis for small binaries (<1MB).
        Optimized for speed.
        """
        start_time = time.time()

        file_size = os.path.getsize(file_path)
        if file_size > 1024 * 1024:
            logger.warning(f"File size {file_size} exceeds 1MB, may not be sub-second")

        # Calculate file hash for caching
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Check cache
        cache_key = f"small_binary_{file_hash}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            self.metrics.cache_hits += 1
            logger.info(f"Cache hit for {file_path}")
            return cached_result

        self.metrics.cache_misses += 1

        # Fast analysis
        with FastBinaryReader(file_path, self.config.enable_memory_mapping) as reader:
            result = {
                "file_path": file_path,
                "file_size": file_size,
                "file_hash": file_hash,
                "entropy": self._calculate_entropy_fast(reader),
                "magic_bytes": reader.read(0, 4).hex(),
                "strings": self._extract_strings_fast(reader),
                "patterns": self._detect_patterns_fast(reader),
            }

        # Cache result
        self.cache.put(cache_key, result)

        execution_time = time.time() - start_time
        self.metrics.execution_time += execution_time

        logger.info(
            f"Small binary analysis completed in {execution_time:.3f}s "
            f"({'sub-second' if execution_time < 1.0 else 'exceeded 1s'})"
        )

        return result

    def _calculate_entropy_fast(self, reader: FastBinaryReader) -> float:
        """Fast entropy calculation"""
        import math

        byte_counts = [0] * 256
        data = reader.read(0, min(100000, reader.size))  # Sample first 100KB

        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return entropy

    def _extract_strings_fast(
        self, reader: FastBinaryReader, min_length: int = 4
    ) -> List[str]:
        """Fast string extraction"""
        strings = []
        current = []

        # Sample first 100KB
        data = reader.read(0, min(100000, reader.size))

        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                    if len(strings) >= 50:  # Limit strings
                        return strings
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings

    def _detect_patterns_fast(self, reader: FastBinaryReader) -> List[Dict[str, Any]]:
        """Fast pattern detection"""
        patterns = []

        # Common patterns
        common_patterns = {
            b"MZ": "PE executable",
            b"\x7fELF": "ELF executable",
            b"\xfe\xed\xfa": "Mach-O",
            b"PK\x03\x04": "ZIP archive",
            b"\x1f\x8b": "GZIP",
            b"Rar!": "RAR archive",
        }

        for pattern, description in common_patterns.items():
            matches = reader.find_pattern(pattern, max_matches=1)
            if matches:
                patterns.append(
                    {
                        "pattern": pattern.hex(),
                        "description": description,
                        "offset": matches[0],
                    }
                )

        return patterns

    def optimize_memory(self):
        """Optimize memory usage"""
        self.memory_manager.optimize()
        self.cache.clear()
        logger.info("Memory optimization completed")

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report"""
        return {
            "metrics": {
                "execution_time": self.metrics.execution_time,
                "cache_hits": self.metrics.cache_hits,
                "cache_misses": self.metrics.cache_misses,
                "cache_hit_rate": (
                    self.metrics.cache_hits
                    / (self.metrics.cache_hits + self.metrics.cache_misses)
                    if (self.metrics.cache_hits + self.metrics.cache_misses) > 0
                    else 0
                ),
            },
            "cache_stats": self.cache.get_stats(),
            "memory_stats": self.memory_manager.get_statistics(),
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create optimizer
    config = OptimizationConfig(
        optimization_level=OptimizationLevel.AGGRESSIVE,
        enable_cache=True,
        enable_memory_mapping=True,
    )
    optimizer = PerformanceOptimizer(config)

    # Analyze small binary
    result = optimizer.analyze_small_binary("/path/to/small/binary")
    print(f"File hash: {result['file_hash']}")
    print(f"Entropy: {result['entropy']:.2f}")
    print(f"Strings found: {len(result['strings'])}")

    # Get performance report
    report = optimizer.get_performance_report()
    print(f"\nPerformance Report:")
    print(f"  Cache hit rate: {report['metrics']['cache_hit_rate']:.2%}")
    print(f"  Memory usage: {report['memory_stats']['current_mb']:.2f} MB")
