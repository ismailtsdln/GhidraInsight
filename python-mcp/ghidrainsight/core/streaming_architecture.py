"""
Streaming Architecture Module for GhidraInsight

This module provides a high-performance streaming architecture for processing
large binaries and real-time analysis with memory-efficient data pipelines,
reactive streams, and event-driven processing.

Author: GhidraInsight Team
License: Apache 2.0
"""

import asyncio
import logging
import queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Set

logger = logging.getLogger(__name__)


class StreamType(Enum):
    """Types of data streams"""

    BINARY_CHUNK = "binary_chunk"
    ANALYSIS_RESULT = "analysis_result"
    EVENT = "event"
    METRIC = "metric"
    LOG = "log"


class BackpressureStrategy(Enum):
    """Backpressure handling strategies"""

    DROP = "drop"  # Drop oldest items
    BUFFER = "buffer"  # Buffer items (with limit)
    BLOCK = "block"  # Block producer
    ERROR = "error"  # Raise error


@dataclass
class StreamMessage:
    """Message in a stream"""

    message_id: str
    stream_type: StreamType
    data: Any
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    sequence: int = 0


@dataclass
class StreamMetrics:
    """Metrics for a stream"""

    messages_sent: int = 0
    messages_received: int = 0
    messages_dropped: int = 0
    bytes_processed: int = 0
    processing_time: float = 0.0
    errors: int = 0
    start_time: float = field(default_factory=time.time)


@dataclass
class StreamConfig:
    """Configuration for streaming"""

    buffer_size: int = 10000
    chunk_size: int = 1024 * 1024  # 1MB chunks
    max_memory: int = 1024 * 1024 * 1024  # 1GB
    backpressure_strategy: BackpressureStrategy = BackpressureStrategy.BUFFER
    enable_compression: bool = False
    compression_level: int = 6
    enable_checksum: bool = True
    num_workers: int = 4
    timeout: int = 300


class StreamProcessor(ABC):
    """Abstract base class for stream processors"""

    @abstractmethod
    async def process(self, message: StreamMessage) -> Optional[StreamMessage]:
        """Process a stream message"""
        pass

    @abstractmethod
    async def on_error(self, error: Exception, message: StreamMessage):
        """Handle processing error"""
        pass


class BinaryChunker:
    """Chunks binary data for streaming"""

    def __init__(self, chunk_size: int = 1024 * 1024):
        self.chunk_size = chunk_size
        self.sequence = 0

    def chunk_file(self, file_path: str) -> Iterator[bytes]:
        """Chunk a file into smaller pieces"""
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk

    async def chunk_file_async(self, file_path: str) -> AsyncIterator[bytes]:
        """Async version of chunk_file"""
        loop = asyncio.get_event_loop()
        with open(file_path, "rb") as f:
            while True:
                chunk = await loop.run_in_executor(None, f.read, self.chunk_size)
                if not chunk:
                    break
                yield chunk

    def create_chunk_message(self, chunk: bytes, file_path: str) -> StreamMessage:
        """Create a stream message from a chunk"""
        self.sequence += 1
        return StreamMessage(
            message_id=f"chunk_{self.sequence}",
            stream_type=StreamType.BINARY_CHUNK,
            data=chunk,
            sequence=self.sequence,
            metadata={
                "file_path": file_path,
                "size": len(chunk),
                "chunk_index": self.sequence,
            },
        )


class StreamBuffer:
    """Thread-safe buffer for stream messages"""

    def __init__(
        self,
        max_size: int = 10000,
        backpressure: BackpressureStrategy = BackpressureStrategy.BUFFER,
    ):
        self.max_size = max_size
        self.backpressure = backpressure
        self.buffer: queue.Queue = queue.Queue(maxsize=max_size)
        self.metrics = StreamMetrics()
        self._lock = threading.Lock()

    def put(self, message: StreamMessage, block: bool = True, timeout: float = None):
        """Add message to buffer"""
        try:
            if self.backpressure == BackpressureStrategy.DROP:
                if self.buffer.full():
                    with self._lock:
                        self.metrics.messages_dropped += 1
                    logger.warning("Buffer full, dropping message")
                    return
                self.buffer.put_nowait(message)
            elif self.backpressure == BackpressureStrategy.BUFFER:
                self.buffer.put(message, block=block, timeout=timeout)
            elif self.backpressure == BackpressureStrategy.BLOCK:
                self.buffer.put(message, block=True)
            elif self.backpressure == BackpressureStrategy.ERROR:
                if self.buffer.full():
                    raise BufferError("Stream buffer is full")
                self.buffer.put_nowait(message)

            with self._lock:
                self.metrics.messages_sent += 1

        except queue.Full:
            with self._lock:
                self.metrics.messages_dropped += 1
            logger.warning("Buffer full, message dropped")

    def get(self, block: bool = True, timeout: float = None) -> StreamMessage:
        """Get message from buffer"""
        message = self.buffer.get(block=block, timeout=timeout)
        with self._lock:
            self.metrics.messages_received += 1
        return message

    def size(self) -> int:
        """Get current buffer size"""
        return self.buffer.qsize()

    def is_empty(self) -> bool:
        """Check if buffer is empty"""
        return self.buffer.empty()

    def is_full(self) -> bool:
        """Check if buffer is full"""
        return self.buffer.full()


class StreamPipeline:
    """Pipeline for processing streams"""

    def __init__(self, config: Optional[StreamConfig] = None):
        self.config = config or StreamConfig()
        self.processors: List[StreamProcessor] = []
        self.input_buffer = StreamBuffer(
            self.config.buffer_size, self.config.backpressure_strategy
        )
        self.output_buffer = StreamBuffer(
            self.config.buffer_size, self.config.backpressure_strategy
        )
        self.metrics = StreamMetrics()
        self._running = False
        self._workers: List[threading.Thread] = []

    def add_processor(self, processor: StreamProcessor):
        """Add a processor to the pipeline"""
        self.processors.append(processor)
        logger.info(f"Added processor: {processor.__class__.__name__}")

    async def process_message(self, message: StreamMessage) -> Optional[StreamMessage]:
        """Process a message through all processors"""
        current_message = message
        start_time = time.time()

        try:
            for processor in self.processors:
                result = await processor.process(current_message)
                if result is None:
                    # Processor filtered out the message
                    return None
                current_message = result

            self.metrics.processing_time += time.time() - start_time
            return current_message

        except Exception as e:
            self.metrics.errors += 1
            logger.error(f"Error processing message: {e}")
            for processor in self.processors:
                await processor.on_error(e, message)
            return None

    def start(self):
        """Start the pipeline"""
        if self._running:
            logger.warning("Pipeline already running")
            return

        self._running = True
        logger.info(f"Starting pipeline with {self.config.num_workers} workers")

        # Start worker threads
        for i in range(self.config.num_workers):
            worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            worker.start()
            self._workers.append(worker)

    def stop(self):
        """Stop the pipeline"""
        logger.info("Stopping pipeline")
        self._running = False

        # Wait for workers to finish
        for worker in self._workers:
            worker.join(timeout=5.0)

        self._workers.clear()

    def _worker_loop(self, worker_id: int):
        """Worker loop for processing messages"""
        logger.info(f"Worker {worker_id} started")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        while self._running:
            try:
                # Get message from input buffer
                message = self.input_buffer.get(block=True, timeout=1.0)

                # Process message
                result = loop.run_until_complete(self.process_message(message))

                # Put result in output buffer
                if result:
                    self.output_buffer.put(result)

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

        loop.close()
        logger.info(f"Worker {worker_id} stopped")

    def submit(self, message: StreamMessage):
        """Submit a message to the pipeline"""
        self.input_buffer.put(message)

    def get_result(self, timeout: float = None) -> Optional[StreamMessage]:
        """Get a result from the pipeline"""
        try:
            return self.output_buffer.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics"""
        return {
            "input_buffer": {
                "size": self.input_buffer.size(),
                "sent": self.input_buffer.metrics.messages_sent,
                "dropped": self.input_buffer.metrics.messages_dropped,
            },
            "output_buffer": {
                "size": self.output_buffer.size(),
                "received": self.output_buffer.metrics.messages_received,
            },
            "processing": {
                "time": self.metrics.processing_time,
                "errors": self.metrics.errors,
            },
        }


class BinaryAnalysisProcessor(StreamProcessor):
    """Processor for binary analysis"""

    async def process(self, message: StreamMessage) -> Optional[StreamMessage]:
        """Process binary chunk"""
        if message.stream_type != StreamType.BINARY_CHUNK:
            return message

        # Simulate analysis
        chunk_data = message.data
        analysis_result = {
            "chunk_id": message.message_id,
            "size": len(chunk_data),
            "entropy": self._calculate_entropy(chunk_data),
            "strings": self._extract_strings(chunk_data),
        }

        return StreamMessage(
            message_id=f"analysis_{message.message_id}",
            stream_type=StreamType.ANALYSIS_RESULT,
            data=analysis_result,
            metadata=message.metadata,
        )

    async def on_error(self, error: Exception, message: StreamMessage):
        """Handle error"""
        logger.error(f"Analysis error for {message.message_id}: {error}")

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        import math

        byte_counts = [0] * 256
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

    def _extract_strings(self, data: bytes) -> List[str]:
        """Extract printable strings"""
        strings = []
        current = []

        for byte in data:
            if 32 <= byte < 127:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []

        if len(current) >= 4:
            strings.append("".join(current))

        return strings[:10]  # Return first 10 strings


class EventStream:
    """Real-time event streaming"""

    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.event_history: List[StreamMessage] = []
        self.max_history = 1000
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to events"""
        with self._lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(callback)
        logger.info(f"Subscribed to event type: {event_type}")

    def unsubscribe(self, event_type: str, callback: Callable):
        """Unsubscribe from events"""
        with self._lock:
            if event_type in self.subscribers:
                self.subscribers[event_type].remove(callback)

    def publish(self, event_type: str, data: Any):
        """Publish an event"""
        message = StreamMessage(
            message_id=f"event_{int(time.time() * 1000)}",
            stream_type=StreamType.EVENT,
            data=data,
            metadata={"event_type": event_type},
        )

        with self._lock:
            # Add to history
            self.event_history.append(message)
            if len(self.event_history) > self.max_history:
                self.event_history.pop(0)

            # Notify subscribers
            if event_type in self.subscribers:
                for callback in self.subscribers[event_type]:
                    try:
                        callback(message)
                    except Exception as e:
                        logger.error(f"Error in event callback: {e}")

    def get_history(self, event_type: Optional[str] = None) -> List[StreamMessage]:
        """Get event history"""
        with self._lock:
            if event_type:
                return [
                    m
                    for m in self.event_history
                    if m.metadata.get("event_type") == event_type
                ]
            return self.event_history.copy()


class StreamingAnalyzer:
    """
    Main streaming analyzer for memory-efficient binary analysis.
    """

    def __init__(self, config: Optional[StreamConfig] = None):
        self.config = config or StreamConfig()
        self.pipeline = StreamPipeline(self.config)
        self.chunker = BinaryChunker(self.config.chunk_size)
        self.event_stream = EventStream()
        self.results: List[Dict[str, Any]] = []

        # Add default processors
        self.pipeline.add_processor(BinaryAnalysisProcessor())

    async def analyze_file_stream(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file using streaming"""
        logger.info(f"Starting streaming analysis: {file_path}")
        start_time = time.time()

        # Start pipeline
        self.pipeline.start()

        # Publish start event
        self.event_stream.publish("analysis_start", {"file_path": file_path})

        # Stream file chunks
        chunk_count = 0
        async for chunk in self.chunker.chunk_file_async(file_path):
            chunk_count += 1
            message = self.chunker.create_chunk_message(chunk, file_path)
            self.pipeline.submit(message)

            # Publish progress event
            if chunk_count % 10 == 0:
                self.event_stream.publish(
                    "analysis_progress", {"chunks_processed": chunk_count}
                )

        logger.info(f"Submitted {chunk_count} chunks for processing")

        # Collect results
        results = []
        collected = 0
        while collected < chunk_count:
            result = self.pipeline.get_result(timeout=5.0)
            if result:
                results.append(result.data)
                collected += 1

        # Stop pipeline
        self.pipeline.stop()

        analysis_time = time.time() - start_time

        # Aggregate results
        final_result = {
            "file_path": file_path,
            "total_chunks": chunk_count,
            "analysis_time": analysis_time,
            "metrics": self.pipeline.get_metrics(),
            "chunks": results,
        }

        # Publish complete event
        self.event_stream.publish("analysis_complete", final_result)

        logger.info(f"Streaming analysis completed in {analysis_time:.2f}s")

        return final_result

    def analyze_file_sync(self, file_path: str) -> Dict[str, Any]:
        """Synchronous wrapper for analyze_file_stream"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.analyze_file_stream(file_path))
        finally:
            loop.close()


class DataPipeline:
    """Generic data processing pipeline"""

    def __init__(self):
        self.stages: List[Callable] = []
        self.metrics = StreamMetrics()

    def add_stage(self, stage: Callable):
        """Add a processing stage"""
        self.stages.append(stage)

    async def execute(self, data: Any) -> Any:
        """Execute pipeline on data"""
        current_data = data
        start_time = time.time()

        for stage in self.stages:
            try:
                if asyncio.iscoroutinefunction(stage):
                    current_data = await stage(current_data)
                else:
                    current_data = stage(current_data)
            except Exception as e:
                self.metrics.errors += 1
                logger.error(f"Pipeline stage error: {e}")
                raise

        self.metrics.processing_time += time.time() - start_time
        return current_data


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create streaming analyzer
    config = StreamConfig(
        chunk_size=1024 * 1024,  # 1MB chunks
        buffer_size=100,
        num_workers=4,
    )
    analyzer = StreamingAnalyzer(config)

    # Subscribe to events
    def on_progress(message: StreamMessage):
        data = message.data
        print(f"Progress: {data.get('chunks_processed')} chunks processed")

    analyzer.event_stream.subscribe("analysis_progress", on_progress)

    # Analyze file
    result = analyzer.analyze_file_sync("/path/to/large/binary")

    print(f"Analysis complete:")
    print(f"  Total chunks: {result['total_chunks']}")
    print(f"  Analysis time: {result['analysis_time']:.2f}s")
    print(f"  Metrics: {result['metrics']}")
