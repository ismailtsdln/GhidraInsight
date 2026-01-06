"""
GPU Acceleration Module for GhidraInsight

This module provides GPU-accelerated analysis capabilities for computationally
intensive tasks such as pattern matching, cryptographic analysis, and large-scale
data processing.

Author: GhidraInsight Team
License: Apache 2.0
"""

import hashlib
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class GPUBackend(Enum):
    """Supported GPU backends"""

    CUDA = "cuda"
    OPENCL = "opencl"
    METAL = "metal"
    CPU = "cpu"  # Fallback


class GPUVendor(Enum):
    """GPU vendors"""

    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"
    APPLE = "apple"
    UNKNOWN = "unknown"


@dataclass
class GPUDevice:
    """Information about a GPU device"""

    device_id: int
    name: str
    vendor: GPUVendor
    backend: GPUBackend
    compute_capability: Optional[str] = None
    memory_total: int = 0  # bytes
    memory_available: int = 0  # bytes
    cores: int = 0
    clock_rate: int = 0  # MHz
    supports_fp64: bool = False
    supports_fp16: bool = False


@dataclass
class GPUConfig:
    """Configuration for GPU acceleration"""

    preferred_backend: GPUBackend = GPUBackend.CUDA
    device_id: int = 0
    enable_fallback: bool = True
    max_memory_usage: float = 0.8  # Use up to 80% of GPU memory
    batch_size: int = 1024
    num_streams: int = 4
    enable_profiling: bool = False


@dataclass
class GPUTask:
    """Represents a GPU-accelerated task"""

    task_id: str
    task_type: str
    input_data: Any
    output_data: Any = None
    execution_time: float = 0.0
    memory_used: int = 0
    status: str = "pending"  # "pending", "running", "completed", "failed"
    error: Optional[str] = None


class GPUAccelerator:
    """
    Main GPU acceleration engine for GhidraInsight.
    """

    def __init__(self, config: Optional[GPUConfig] = None):
        self.config = config or GPUConfig()
        self.devices: List[GPUDevice] = []
        self.current_device: Optional[GPUDevice] = None
        self.backend = None
        self.context = None
        self.tasks: Dict[str, GPUTask] = {}
        self._initialized = False

        # Initialize GPU
        self._initialize()

    def _initialize(self):
        """Initialize GPU acceleration"""
        logger.info("Initializing GPU acceleration...")

        # Detect available GPUs
        self.devices = self._detect_gpus()

        if not self.devices:
            logger.warning("No GPU devices found, falling back to CPU")
            if self.config.enable_fallback:
                self._initialize_cpu_fallback()
            return

        # Select device
        if self.config.device_id < len(self.devices):
            self.current_device = self.devices[self.config.device_id]
        else:
            self.current_device = self.devices[0]

        logger.info(
            f"Selected GPU: {self.current_device.name} "
            f"({self.current_device.vendor.value})"
        )

        # Initialize backend
        try:
            if self.current_device.backend == GPUBackend.CUDA:
                self._initialize_cuda()
            elif self.current_device.backend == GPUBackend.OPENCL:
                self._initialize_opencl()
            elif self.current_device.backend == GPUBackend.METAL:
                self._initialize_metal()

            self._initialized = True
            logger.info("GPU acceleration initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize GPU: {e}")
            if self.config.enable_fallback:
                self._initialize_cpu_fallback()

    def _detect_gpus(self) -> List[GPUDevice]:
        """Detect available GPU devices"""
        devices = []

        # Try CUDA (NVIDIA)
        cuda_devices = self._detect_cuda_devices()
        devices.extend(cuda_devices)

        # Try OpenCL (AMD, Intel, NVIDIA)
        opencl_devices = self._detect_opencl_devices()
        devices.extend(opencl_devices)

        # Try Metal (Apple)
        if platform.system() == "Darwin":
            metal_devices = self._detect_metal_devices()
            devices.extend(metal_devices)

        return devices

    def _detect_cuda_devices(self) -> List[GPUDevice]:
        """Detect NVIDIA CUDA devices"""
        devices = []

        try:
            import pycuda.autoinit
            import pycuda.driver as cuda

            cuda.init()
            device_count = cuda.Device.count()

            for i in range(device_count):
                dev = cuda.Device(i)
                compute_capability = dev.compute_capability()

                device = GPUDevice(
                    device_id=i,
                    name=dev.name(),
                    vendor=GPUVendor.NVIDIA,
                    backend=GPUBackend.CUDA,
                    compute_capability=f"{compute_capability[0]}.{compute_capability[1]}",
                    memory_total=dev.total_memory(),
                    cores=dev.get_attribute(cuda.device_attribute.MULTIPROCESSOR_COUNT),
                    clock_rate=dev.get_attribute(cuda.device_attribute.CLOCK_RATE),
                    supports_fp64=True,
                    supports_fp16=compute_capability[0] >= 7,
                )

                devices.append(device)
                logger.info(f"Found CUDA device: {device.name}")

        except ImportError:
            logger.debug("PyCUDA not available")
        except Exception as e:
            logger.debug(f"Error detecting CUDA devices: {e}")

        return devices

    def _detect_opencl_devices(self) -> List[GPUDevice]:
        """Detect OpenCL devices"""
        devices = []

        try:
            import pyopencl as cl

            platforms = cl.get_platforms()
            for platform in platforms:
                for dev in platform.get_devices():
                    vendor = self._identify_vendor(dev.vendor)

                    device = GPUDevice(
                        device_id=len(devices),
                        name=dev.name,
                        vendor=vendor,
                        backend=GPUBackend.OPENCL,
                        memory_total=dev.global_mem_size,
                        cores=dev.max_compute_units,
                        clock_rate=dev.max_clock_frequency,
                        supports_fp64=bool(dev.double_fp_config),
                        supports_fp16=bool(dev.half_fp_config),
                    )

                    devices.append(device)
                    logger.info(f"Found OpenCL device: {device.name}")

        except ImportError:
            logger.debug("PyOpenCL not available")
        except Exception as e:
            logger.debug(f"Error detecting OpenCL devices: {e}")

        return devices

    def _detect_metal_devices(self) -> List[GPUDevice]:
        """Detect Apple Metal devices"""
        devices = []

        # Metal detection would require platform-specific code
        # Placeholder for now
        logger.debug("Metal device detection not fully implemented")

        return devices

    def _identify_vendor(self, vendor_name: str) -> GPUVendor:
        """Identify GPU vendor from name"""
        vendor_lower = vendor_name.lower()

        if "nvidia" in vendor_lower:
            return GPUVendor.NVIDIA
        elif "amd" in vendor_lower or "advanced micro devices" in vendor_lower:
            return GPUVendor.AMD
        elif "intel" in vendor_lower:
            return GPUVendor.INTEL
        elif "apple" in vendor_lower:
            return GPUVendor.APPLE
        else:
            return GPUVendor.UNKNOWN

    def _initialize_cuda(self):
        """Initialize CUDA backend"""
        try:
            import pycuda.compiler as compiler
            import pycuda.driver as cuda

            self.backend = cuda
            logger.info("CUDA backend initialized")

        except ImportError:
            raise RuntimeError("PyCUDA not installed. Install with: pip install pycuda")

    def _initialize_opencl(self):
        """Initialize OpenCL backend"""
        try:
            import pyopencl as cl

            platforms = cl.get_platforms()
            if not platforms:
                raise RuntimeError("No OpenCL platforms found")

            self.context = cl.Context(
                devices=[platforms[0].get_devices()[self.config.device_id]]
            )
            self.backend = cl
            logger.info("OpenCL backend initialized")

        except ImportError:
            raise RuntimeError(
                "PyOpenCL not installed. Install with: pip install pyopencl"
            )

    def _initialize_metal(self):
        """Initialize Metal backend"""
        # Metal initialization would require platform-specific code
        logger.warning("Metal backend not fully implemented")
        raise RuntimeError("Metal backend not available")

    def _initialize_cpu_fallback(self):
        """Initialize CPU fallback"""
        logger.info("Using CPU fallback for computations")
        self.current_device = GPUDevice(
            device_id=0,
            name="CPU",
            vendor=GPUVendor.UNKNOWN,
            backend=GPUBackend.CPU,
        )
        self._initialized = True

    def is_available(self) -> bool:
        """Check if GPU acceleration is available"""
        return self._initialized and self.current_device is not None

    def get_device_info(self) -> Optional[GPUDevice]:
        """Get current device information"""
        return self.current_device

    def pattern_match_accelerated(
        self, data: bytes, patterns: List[bytes], max_results: int = 1000
    ) -> List[Tuple[int, int]]:
        """
        GPU-accelerated pattern matching.

        Args:
            data: Binary data to search
            patterns: List of byte patterns to find
            max_results: Maximum number of results to return

        Returns:
            List of (pattern_index, offset) tuples
        """
        if not self.is_available():
            return self._pattern_match_cpu(data, patterns, max_results)

        task_id = f"pattern_match_{int(time.time() * 1000)}"
        task = GPUTask(
            task_id=task_id, task_type="pattern_match", input_data=(data, patterns)
        )
        self.tasks[task_id] = task

        start_time = time.time()

        try:
            if self.current_device.backend == GPUBackend.CUDA:
                results = self._pattern_match_cuda(data, patterns, max_results)
            elif self.current_device.backend == GPUBackend.OPENCL:
                results = self._pattern_match_opencl(data, patterns, max_results)
            else:
                results = self._pattern_match_cpu(data, patterns, max_results)

            task.output_data = results
            task.status = "completed"
            task.execution_time = time.time() - start_time

            logger.info(
                f"Pattern matching completed in {task.execution_time:.3f}s, "
                f"found {len(results)} matches"
            )

            return results

        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            logger.error(f"Pattern matching failed: {e}")
            return []

    def _pattern_match_cuda(
        self, data: bytes, patterns: List[bytes], max_results: int
    ) -> List[Tuple[int, int]]:
        """CUDA implementation of pattern matching"""
        import pycuda.compiler as compiler
        import pycuda.driver as cuda
        from pycuda import gpuarray

        # CUDA kernel for pattern matching
        kernel_code = """
        __global__ void pattern_match(
            const unsigned char* data,
            int data_len,
            const unsigned char* pattern,
            int pattern_len,
            int* results,
            int max_results,
            int* result_count
        ) {
            int idx = blockIdx.x * blockDim.x + threadIdx.x;

            if (idx >= data_len - pattern_len + 1) return;

            // Check if pattern matches at this position
            bool match = true;
            for (int i = 0; i < pattern_len; i++) {
                if (data[idx + i] != pattern[i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                int pos = atomicAdd(result_count, 1);
                if (pos < max_results) {
                    results[pos] = idx;
                }
            }
        }
        """

        # Compile kernel
        mod = compiler.SourceModule(kernel_code)
        pattern_match_kernel = mod.get_function("pattern_match")

        # Allocate memory
        data_gpu = cuda.to_device(np.frombuffer(data, dtype=np.uint8))

        all_results = []

        # Process each pattern
        for pattern_idx, pattern in enumerate(patterns):
            pattern_gpu = cuda.to_device(np.frombuffer(pattern, dtype=np.uint8))
            results_gpu = gpuarray.zeros(max_results, dtype=np.int32)
            result_count_gpu = gpuarray.zeros(1, dtype=np.int32)

            # Launch kernel
            block_size = 256
            grid_size = (len(data) + block_size - 1) // block_size

            pattern_match_kernel(
                data_gpu,
                np.int32(len(data)),
                pattern_gpu,
                np.int32(len(pattern)),
                results_gpu,
                np.int32(max_results),
                result_count_gpu,
                block=(block_size, 1, 1),
                grid=(grid_size, 1),
            )

            # Get results
            result_count = int(result_count_gpu.get()[0])
            if result_count > 0:
                results = results_gpu.get()[:result_count]
                for offset in results:
                    all_results.append((pattern_idx, int(offset)))

        return all_results[:max_results]

    def _pattern_match_opencl(
        self, data: bytes, patterns: List[bytes], max_results: int
    ) -> List[Tuple[int, int]]:
        """OpenCL implementation of pattern matching"""
        import pyopencl as cl

        # OpenCL kernel
        kernel_code = """
        __kernel void pattern_match(
            __global const uchar* data,
            int data_len,
            __global const uchar* pattern,
            int pattern_len,
            __global int* results,
            int max_results,
            __global int* result_count
        ) {
            int idx = get_global_id(0);

            if (idx >= data_len - pattern_len + 1) return;

            // Check if pattern matches
            bool match = true;
            for (int i = 0; i < pattern_len; i++) {
                if (data[idx + i] != pattern[i]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                int pos = atomic_add(result_count, 1);
                if (pos < max_results) {
                    results[pos] = idx;
                }
            }
        }
        """

        queue = cl.CommandQueue(self.context)
        program = cl.Program(self.context, kernel_code).build()

        data_buf = cl.Buffer(
            self.context,
            cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
            hostbuf=data,
        )

        all_results = []

        for pattern_idx, pattern in enumerate(patterns):
            pattern_buf = cl.Buffer(
                self.context,
                cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR,
                hostbuf=pattern,
            )
            results = np.zeros(max_results, dtype=np.int32)
            results_buf = cl.Buffer(
                self.context, cl.mem_flags.WRITE_ONLY, results.nbytes
            )
            result_count = np.zeros(1, dtype=np.int32)
            result_count_buf = cl.Buffer(
                self.context, cl.mem_flags.READ_WRITE, result_count.nbytes
            )

            # Execute kernel
            program.pattern_match(
                queue,
                (len(data),),
                None,
                data_buf,
                np.int32(len(data)),
                pattern_buf,
                np.int32(len(pattern)),
                results_buf,
                np.int32(max_results),
                result_count_buf,
            )

            # Read results
            cl.enqueue_copy(queue, results, results_buf)
            cl.enqueue_copy(queue, result_count, result_count_buf)

            count = int(result_count[0])
            for i in range(min(count, max_results)):
                all_results.append((pattern_idx, int(results[i])))

        return all_results[:max_results]

    def _pattern_match_cpu(
        self, data: bytes, patterns: List[bytes], max_results: int
    ) -> List[Tuple[int, int]]:
        """CPU fallback for pattern matching"""
        results = []

        for pattern_idx, pattern in enumerate(patterns):
            offset = 0
            while offset < len(data):
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                results.append((pattern_idx, pos))
                if len(results) >= max_results:
                    return results
                offset = pos + 1

        return results

    def hash_accelerated(
        self, data_chunks: List[bytes], algorithm: str = "sha256"
    ) -> List[str]:
        """
        GPU-accelerated hash computation for multiple data chunks.

        Args:
            data_chunks: List of data chunks to hash
            algorithm: Hash algorithm (sha256, md5, sha1)

        Returns:
            List of hex-encoded hashes
        """
        if not self.is_available() or self.current_device.backend == GPUBackend.CPU:
            # CPU fallback
            return [hashlib.new(algorithm, chunk).hexdigest() for chunk in data_chunks]

        # GPU hashing would require specialized libraries
        # For now, use optimized CPU implementation
        logger.debug("GPU hashing not fully implemented, using CPU")
        return [hashlib.new(algorithm, chunk).hexdigest() for chunk in data_chunks]

    def entropy_accelerated(self, data_chunks: List[bytes]) -> List[float]:
        """
        GPU-accelerated entropy calculation.

        Args:
            data_chunks: List of data chunks

        Returns:
            List of entropy values
        """
        if not self.is_available():
            return [self._calculate_entropy_cpu(chunk) for chunk in data_chunks]

        # Use NumPy for vectorized operations
        entropies = []
        for chunk in data_chunks:
            entropies.append(self._calculate_entropy_cpu(chunk))

        return entropies

    def _calculate_entropy_cpu(self, data: bytes) -> float:
        """Calculate Shannon entropy (CPU)"""
        if not data:
            return 0.0

        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]

        return float(-np.sum(probabilities * np.log2(probabilities)))

    def memory_info(self) -> Dict[str, int]:
        """Get GPU memory information"""
        if not self.current_device:
            return {"total": 0, "available": 0, "used": 0}

        info = {
            "total": self.current_device.memory_total,
            "available": self.current_device.memory_available,
            "used": self.current_device.memory_total
            - self.current_device.memory_available,
        }

        return info

    def benchmark(self) -> Dict[str, float]:
        """Run GPU benchmark"""
        logger.info("Running GPU benchmark...")

        results = {}

        # Pattern matching benchmark
        test_data = b"A" * 1000000
        test_patterns = [b"ABCD", b"1234", b"TEST"]

        start = time.time()
        matches = self.pattern_match_accelerated(test_data, test_patterns)
        results["pattern_matching_ms"] = (time.time() - start) * 1000

        # Entropy benchmark
        test_chunks = [os.urandom(10000) for _ in range(100)]
        start = time.time()
        entropies = self.entropy_accelerated(test_chunks)
        results["entropy_ms"] = (time.time() - start) * 1000

        logger.info(f"Benchmark results: {results}")
        return results

    def cleanup(self):
        """Clean up GPU resources"""
        logger.info("Cleaning up GPU resources...")

        if self.context:
            try:
                # Release OpenCL context
                self.context = None
            except:
                pass

        self._initialized = False


# Singleton instance
_gpu_accelerator_instance: Optional[GPUAccelerator] = None


def get_gpu_accelerator(config: Optional[GPUConfig] = None) -> GPUAccelerator:
    """Get or create GPU accelerator singleton"""
    global _gpu_accelerator_instance

    if _gpu_accelerator_instance is None:
        _gpu_accelerator_instance = GPUAccelerator(config)

    return _gpu_accelerator_instance


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create GPU accelerator
    config = GPUConfig(preferred_backend=GPUBackend.CUDA, enable_fallback=True)
    gpu = GPUAccelerator(config)

    # Check availability
    if gpu.is_available():
        device = gpu.get_device_info()
        print(f"GPU: {device.name}")
        print(f"Memory: {device.memory_total / (1024**3):.2f} GB")

        # Run benchmark
        results = gpu.benchmark()
        print(f"Benchmark: {results}")
    else:
        print("GPU not available")

    # Cleanup
    gpu.cleanup()
