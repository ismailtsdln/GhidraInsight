"""
Dynamic Analysis Integration Module for GhidraInsight

This module provides dynamic analysis capabilities to complement static analysis,
including test generation, taint tracking, fuzzing, and behavior monitoring.

Author: GhidraInsight Team
License: Apache 2.0
"""

import hashlib
import json
import logging
import os
import queue
import random
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AnalysisMode(Enum):
    """Dynamic analysis modes"""

    CONCRETE = "concrete"  # Concrete execution with real inputs
    SYMBOLIC = "symbolic"  # Symbolic execution
    CONCOLIC = "concolic"  # Combined concrete + symbolic
    FUZZING = "fuzzing"  # Automated fuzzing
    TAINT = "taint"  # Taint analysis


class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be detected"""

    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_DEREFERENCE = "null_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    UNINITIALIZED_MEMORY = "uninitialized_memory"


@dataclass
class TestCase:
    """Represents a test case for dynamic analysis"""

    test_id: str
    input_data: bytes
    input_type: str  # "file", "stdin", "network", "args"
    input_source: Optional[str] = None
    expected_output: Optional[bytes] = None
    coverage_target: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Results from executing a test case"""

    test_id: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    execution_time: float
    memory_usage: int  # Peak memory in bytes
    crashed: bool = False
    crash_signal: Optional[int] = None
    coverage: Dict[str, Any] = field(default_factory=dict)
    taint_flow: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    sanitizer_output: Optional[str] = None


@dataclass
class TaintSource:
    """Represents a source of tainted data"""

    source_id: str
    source_type: str  # "user_input", "file", "network", "env"
    location: str
    data_type: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintSink:
    """Represents a dangerous operation (sink) that tainted data reaches"""

    sink_id: str
    sink_type: str  # "system_call", "memory_operation", "file_operation"
    location: str
    function: str
    taint_sources: List[str] = field(default_factory=list)
    risk_level: str = "medium"  # "low", "medium", "high", "critical"


@dataclass
class DynamicAnalysisConfig:
    """Configuration for dynamic analysis"""

    mode: AnalysisMode = AnalysisMode.CONCRETE
    timeout: int = 30  # Seconds per test
    memory_limit: int = 1024 * 1024 * 1024  # 1GB default
    enable_sanitizers: bool = True  # AddressSanitizer, UBSan, etc.
    enable_coverage: bool = True
    enable_taint_tracking: bool = True
    max_test_cases: int = 1000
    parallel_executions: int = 4
    save_crashes: bool = True
    crash_dir: Optional[str] = None
    corpus_dir: Optional[str] = None


class DynamicAnalyzer:
    """
    Main dynamic analysis engine that coordinates various dynamic analysis techniques.
    """

    def __init__(self, config: Optional[DynamicAnalysisConfig] = None):
        self.config = config or DynamicAnalysisConfig()
        self.test_cases: Dict[str, TestCase] = {}
        self.results: Dict[str, ExecutionResult] = {}
        self.taint_sources: Dict[str, TaintSource] = {}
        self.taint_sinks: Dict[str, TaintSink] = {}
        self.coverage_map: Dict[str, Set[int]] = {}  # function -> line numbers
        self._execution_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        if self.config.crash_dir:
            os.makedirs(self.config.crash_dir, exist_ok=True)

    def add_test_case(self, test_case: TestCase) -> str:
        """Add a test case to the analysis queue"""
        with self._lock:
            self.test_cases[test_case.test_id] = test_case
            self._execution_queue.put(test_case.test_id)
            logger.info(f"Added test case: {test_case.test_id}")
            return test_case.test_id

    def generate_test_cases(
        self,
        binary_path: str,
        num_cases: int = 100,
        strategy: str = "random",
        seed_inputs: Optional[List[bytes]] = None,
    ) -> List[TestCase]:
        """
        Generate test cases for dynamic analysis.

        Args:
            binary_path: Path to the binary
            num_cases: Number of test cases to generate
            strategy: Generation strategy ("random", "mutation", "grammar", "symbolic")
            seed_inputs: Optional seed inputs for mutation-based generation

        Returns:
            List of generated test cases
        """
        test_cases = []

        if strategy == "random":
            test_cases = self._generate_random_tests(binary_path, num_cases)
        elif strategy == "mutation":
            test_cases = self._generate_mutation_tests(
                binary_path, num_cases, seed_inputs or []
            )
        elif strategy == "grammar":
            test_cases = self._generate_grammar_tests(binary_path, num_cases)
        elif strategy == "symbolic":
            test_cases = self._generate_symbolic_tests(binary_path, num_cases)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

        for tc in test_cases:
            self.add_test_case(tc)

        logger.info(f"Generated {len(test_cases)} test cases using {strategy} strategy")
        return test_cases

    def _generate_random_tests(
        self, binary_path: str, num_cases: int
    ) -> List[TestCase]:
        """Generate random test inputs"""
        test_cases = []
        for i in range(num_cases):
            size = random.randint(1, 4096)
            data = bytes(random.getrandbits(8) for _ in range(size))
            test_id = f"random_{i}_{hashlib.md5(data).hexdigest()[:8]}"

            test_cases.append(
                TestCase(
                    test_id=test_id,
                    input_data=data,
                    input_type="stdin",
                    metadata={"strategy": "random", "size": size},
                )
            )

        return test_cases

    def _generate_mutation_tests(
        self, binary_path: str, num_cases: int, seed_inputs: List[bytes]
    ) -> List[TestCase]:
        """Generate test cases by mutating seed inputs"""
        if not seed_inputs:
            # Create basic seed inputs
            seed_inputs = [
                b"A" * 10,
                b"test",
                b"\x00" * 10,
                b"\xff" * 10,
                b"A" * 100,
            ]

        test_cases = []
        for i in range(num_cases):
            # Select random seed
            seed = random.choice(seed_inputs)
            mutated = self._mutate_input(seed)
            test_id = f"mutation_{i}_{hashlib.md5(mutated).hexdigest()[:8]}"

            test_cases.append(
                TestCase(
                    test_id=test_id,
                    input_data=mutated,
                    input_type="stdin",
                    metadata={"strategy": "mutation", "seed_size": len(seed)},
                )
            )

        return test_cases

    def _mutate_input(self, data: bytes) -> bytes:
        """Apply random mutations to input data"""
        data = bytearray(data)
        mutation_type = random.choice(
            ["bit_flip", "byte_flip", "insert", "delete", "replace", "splice"]
        )

        if mutation_type == "bit_flip" and len(data) > 0:
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= 1 << bit

        elif mutation_type == "byte_flip" and len(data) > 0:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)

        elif mutation_type == "insert":
            pos = random.randint(0, len(data))
            data.insert(pos, random.randint(0, 255))

        elif mutation_type == "delete" and len(data) > 1:
            pos = random.randint(0, len(data) - 1)
            del data[pos]

        elif mutation_type == "replace" and len(data) > 0:
            pos = random.randint(0, len(data) - 1)
            length = random.randint(1, min(10, len(data) - pos))
            replacement = bytes(random.getrandbits(8) for _ in range(length))
            data[pos : pos + length] = replacement

        elif mutation_type == "splice" and len(data) > 1:
            pos1 = random.randint(0, len(data) - 1)
            pos2 = random.randint(pos1, len(data))
            data = data[:pos1] + data[pos2:]

        return bytes(data)

    def _generate_grammar_tests(
        self, binary_path: str, num_cases: int
    ) -> List[TestCase]:
        """Generate test cases based on input grammar (placeholder)"""
        # TODO: Implement grammar-based generation
        logger.warning("Grammar-based generation not yet implemented")
        return self._generate_random_tests(binary_path, num_cases)

    def _generate_symbolic_tests(
        self, binary_path: str, num_cases: int
    ) -> List[TestCase]:
        """Generate test cases using symbolic execution (placeholder)"""
        # TODO: Integrate with angr or other symbolic execution engine
        logger.warning("Symbolic execution not yet implemented")
        return self._generate_random_tests(binary_path, num_cases)

    def execute_test(
        self,
        binary_path: str,
        test_case: TestCase,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecutionResult:
        """
        Execute a single test case and collect results.

        Args:
            binary_path: Path to the binary to execute
            test_case: Test case to execute
            env: Optional environment variables

        Returns:
            ExecutionResult with collected data
        """
        start_time = time.time()

        # Create input file if needed
        input_file = None
        if test_case.input_type == "file":
            input_file = tempfile.NamedTemporaryFile(delete=False)
            input_file.write(test_case.input_data)
            input_file.close()
            cmd = [binary_path, input_file.name]
            stdin_data = None
        else:
            cmd = [binary_path]
            stdin_data = test_case.input_data

        # Set up environment for sanitizers
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        if self.config.enable_sanitizers:
            exec_env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
            exec_env["UBSAN_OPTIONS"] = "print_stacktrace=1"

        # Execute the test
        result = ExecutionResult(
            test_id=test_case.test_id,
            exit_code=0,
            stdout=b"",
            stderr=b"",
            execution_time=0.0,
            memory_usage=0,
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=exec_env,
            )

            try:
                stdout, stderr = proc.communicate(
                    input=stdin_data, timeout=self.config.timeout
                )
                result.stdout = stdout
                result.stderr = stderr
                result.exit_code = proc.returncode

                # Check for crash
                if proc.returncode < 0:
                    result.crashed = True
                    result.crash_signal = -proc.returncode
                    self._handle_crash(test_case, result)

                # Parse sanitizer output
                if self.config.enable_sanitizers:
                    result.sanitizer_output = stderr.decode("utf-8", errors="ignore")
                    vulnerabilities = self._parse_sanitizer_output(
                        result.sanitizer_output
                    )
                    result.vulnerabilities.extend(vulnerabilities)

            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                result.stdout = stdout
                result.stderr = stderr
                result.exit_code = -1
                logger.warning(f"Test {test_case.test_id} timed out")

        except Exception as e:
            logger.error(f"Error executing test {test_case.test_id}: {e}")
            result.exit_code = -1

        finally:
            if input_file:
                os.unlink(input_file.name)

        result.execution_time = time.time() - start_time

        # Store result
        with self._lock:
            self.results[test_case.test_id] = result

        return result

    def _handle_crash(self, test_case: TestCase, result: ExecutionResult):
        """Handle a crash by saving the crashing input"""
        if self.config.save_crashes and self.config.crash_dir:
            crash_file = os.path.join(
                self.config.crash_dir,
                f"crash_{test_case.test_id}_{result.crash_signal}.bin",
            )
            with open(crash_file, "wb") as f:
                f.write(test_case.input_data)
            logger.info(f"Saved crash to {crash_file}")

    def _parse_sanitizer_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse sanitizer output to detect vulnerabilities"""
        vulnerabilities = []

        if "heap-buffer-overflow" in output:
            vulnerabilities.append(
                {
                    "type": VulnerabilityType.BUFFER_OVERFLOW.value,
                    "severity": "high",
                    "description": "Heap buffer overflow detected",
                    "details": output,
                }
            )

        if "heap-use-after-free" in output:
            vulnerabilities.append(
                {
                    "type": VulnerabilityType.USE_AFTER_FREE.value,
                    "severity": "critical",
                    "description": "Use-after-free detected",
                    "details": output,
                }
            )

        if "null-pointer-dereference" in output or "SEGV" in output:
            vulnerabilities.append(
                {
                    "type": VulnerabilityType.NULL_DEREFERENCE.value,
                    "severity": "medium",
                    "description": "Null pointer dereference",
                    "details": output,
                }
            )

        if "memory leak" in output.lower():
            vulnerabilities.append(
                {
                    "type": VulnerabilityType.MEMORY_LEAK.value,
                    "severity": "low",
                    "description": "Memory leak detected",
                    "details": output,
                }
            )

        return vulnerabilities

    def run_analysis(
        self, binary_path: str, test_cases: Optional[List[TestCase]] = None
    ) -> Dict[str, Any]:
        """
        Run dynamic analysis on a binary with test cases.

        Args:
            binary_path: Path to the binary
            test_cases: Optional list of test cases (will generate if not provided)

        Returns:
            Analysis results summary
        """
        if test_cases:
            for tc in test_cases:
                self.add_test_case(tc)
        elif not self.test_cases:
            # Generate test cases if none provided
            self.generate_test_cases(binary_path, num_cases=100, strategy="mutation")

        # Run tests in parallel
        threads = []
        for _ in range(self.config.parallel_executions):
            thread = threading.Thread(
                target=self._worker, args=(binary_path,), daemon=True
            )
            thread.start()
            threads.append(thread)

        # Wait for completion
        self._execution_queue.join()
        self._stop_event.set()

        for thread in threads:
            thread.join(timeout=1.0)

        # Compile results
        return self._compile_results()

    def _worker(self, binary_path: str):
        """Worker thread for executing tests"""
        while not self._stop_event.is_set():
            try:
                test_id = self._execution_queue.get(timeout=1.0)
                test_case = self.test_cases[test_id]
                self.execute_test(binary_path, test_case)
                self._execution_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
                self._execution_queue.task_done()

    def _compile_results(self) -> Dict[str, Any]:
        """Compile analysis results into a summary"""
        total_tests = len(self.results)
        crashes = sum(1 for r in self.results.values() if r.crashed)
        vulnerabilities = []
        for result in self.results.values():
            vulnerabilities.extend(result.vulnerabilities)

        # Calculate coverage
        total_coverage = set()
        for result in self.results.values():
            if result.coverage:
                for func, lines in result.coverage.items():
                    total_coverage.update(lines)

        summary = {
            "total_tests": total_tests,
            "crashes": crashes,
            "vulnerabilities": len(vulnerabilities),
            "vulnerability_types": self._count_vulnerability_types(vulnerabilities),
            "coverage": {
                "total_lines": len(total_coverage),
                "functions": len(self.coverage_map),
            },
            "unique_crashes": self._deduplicate_crashes(),
            "execution_times": {
                "min": min(
                    (r.execution_time for r in self.results.values()),
                    default=0,
                ),
                "max": max(
                    (r.execution_time for r in self.results.values()),
                    default=0,
                ),
                "avg": sum(r.execution_time for r in self.results.values())
                / max(total_tests, 1),
            },
        }

        return summary

    def _count_vulnerability_types(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    def _deduplicate_crashes(self) -> int:
        """Deduplicate crashes based on crash signal and stack trace"""
        unique_crashes = set()
        for result in self.results.values():
            if result.crashed:
                # Simple deduplication by signal
                unique_crashes.add(result.crash_signal)
        return len(unique_crashes)

    def add_taint_source(self, source: TaintSource):
        """Register a taint source"""
        self.taint_sources[source.source_id] = source
        logger.info(f"Added taint source: {source.source_id}")

    def add_taint_sink(self, sink: TaintSink):
        """Register a taint sink"""
        self.taint_sinks[sink.sink_id] = sink
        logger.info(f"Added taint sink: {sink.sink_id}")

    def analyze_taint_flow(self) -> List[Dict[str, Any]]:
        """Analyze taint flow from sources to sinks"""
        flows = []

        for result in self.results.values():
            for flow in result.taint_flow:
                source_id = flow.get("source")
                sink_id = flow.get("sink")

                if source_id in self.taint_sources and sink_id in self.taint_sinks:
                    source = self.taint_sources[source_id]
                    sink = self.taint_sinks[sink_id]

                    flows.append(
                        {
                            "source": {
                                "id": source.source_id,
                                "type": source.source_type,
                                "location": source.location,
                            },
                            "sink": {
                                "id": sink.sink_id,
                                "type": sink.sink_type,
                                "location": sink.location,
                                "function": sink.function,
                            },
                            "risk_level": sink.risk_level,
                            "path": flow.get("path", []),
                        }
                    )

        return flows

    def export_results(self, output_path: str, format: str = "json"):
        """Export analysis results to file"""
        data = {
            "summary": self._compile_results(),
            "test_results": [
                {
                    "test_id": result.test_id,
                    "exit_code": result.exit_code,
                    "execution_time": result.execution_time,
                    "crashed": result.crashed,
                    "crash_signal": result.crash_signal,
                    "vulnerabilities": result.vulnerabilities,
                }
                for result in self.results.values()
            ],
            "taint_flows": self.analyze_taint_flow(),
        }

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Results exported to {output_path}")


# Helper functions
def create_taint_source(source_type: str, location: str) -> TaintSource:
    """Create a taint source"""
    source_id = f"source_{source_type}_{int(time.time() * 1000)}"
    return TaintSource(
        source_id=source_id,
        source_type=source_type,
        location=location,
        data_type="bytes",
    )


def create_taint_sink(sink_type: str, function: str, location: str) -> TaintSink:
    """Create a taint sink"""
    sink_id = f"sink_{sink_type}_{int(time.time() * 1000)}"
    return TaintSink(
        sink_id=sink_id, sink_type=sink_type, location=location, function=function
    )


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create analyzer
    config = DynamicAnalysisConfig(
        mode=AnalysisMode.FUZZING,
        enable_sanitizers=True,
        max_test_cases=1000,
        parallel_executions=4,
    )
    analyzer = DynamicAnalyzer(config)

    # Run analysis
    try:
        results = analyzer.run_analysis("/path/to/binary")
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Error: {e}")
