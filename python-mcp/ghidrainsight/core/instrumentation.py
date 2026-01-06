"""
Binary Instrumentation Module for GhidraInsight

This module provides dynamic binary instrumentation capabilities to complement
static analysis. It supports multiple instrumentation backends including Frida,
Intel Pin, and DynamoRIO.

Author: GhidraInsight Team
License: Apache 2.0
"""

import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class InstrumentationBackend(Enum):
    """Supported instrumentation backends"""

    FRIDA = "frida"
    PIN = "pin"
    DYNAMORIO = "dynamorio"
    QEMU = "qemu"
    CUSTOM = "custom"


class HookType(Enum):
    """Types of hooks that can be installed"""

    FUNCTION_ENTRY = "function_entry"
    FUNCTION_EXIT = "function_exit"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    SYSCALL = "syscall"
    API_CALL = "api_call"
    INSTRUCTION = "instruction"


@dataclass
class Hook:
    """Represents a single instrumentation hook"""

    hook_id: str
    hook_type: HookType
    target: str  # Function name, address, or pattern
    callback: Optional[Callable] = None
    enabled: bool = True
    hit_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InstrumentationTrace:
    """Stores execution trace from instrumentation"""

    trace_id: str
    binary_path: str
    start_time: float
    end_time: Optional[float] = None
    executed_functions: List[Dict[str, Any]] = field(default_factory=list)
    memory_accesses: List[Dict[str, Any]] = field(default_factory=list)
    syscalls: List[Dict[str, Any]] = field(default_factory=list)
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class InstrumentationConfig:
    """Configuration for instrumentation session"""

    backend: InstrumentationBackend = InstrumentationBackend.FRIDA
    trace_memory: bool = True
    trace_syscalls: bool = True
    trace_api_calls: bool = True
    collect_coverage: bool = True
    max_trace_size: int = 1000000  # Maximum trace entries
    timeout: int = 300  # Seconds
    follow_child_processes: bool = False
    custom_script_path: Optional[str] = None


class InstrumentationEngine:
    """
    Main instrumentation engine that manages dynamic binary instrumentation.
    """

    def __init__(self, config: Optional[InstrumentationConfig] = None):
        self.config = config or InstrumentationConfig()
        self.hooks: Dict[str, Hook] = {}
        self.active_sessions: Dict[str, Any] = {}
        self.traces: Dict[str, InstrumentationTrace] = {}
        self._lock = threading.Lock()
        self._validate_backend()

    def _validate_backend(self):
        """Validate that the selected backend is available"""
        backend = self.config.backend

        if backend == InstrumentationBackend.FRIDA:
            try:
                import frida

                logger.info("Frida backend available")
            except ImportError:
                logger.warning("Frida not installed. Install with: pip install frida")

        elif backend == InstrumentationBackend.PIN:
            # Check if Intel Pin is available
            pin_path = os.environ.get("PIN_ROOT")
            if not pin_path:
                logger.warning("PIN_ROOT environment variable not set")

        elif backend == InstrumentationBackend.DYNAMORIO:
            # Check if DynamoRIO is available
            dr_path = os.environ.get("DYNAMORIO_HOME")
            if not dr_path:
                logger.warning("DYNAMORIO_HOME environment variable not set")

    def add_hook(self, hook: Hook) -> str:
        """Add a new instrumentation hook"""
        with self._lock:
            self.hooks[hook.hook_id] = hook
            logger.info(f"Added hook: {hook.hook_id} ({hook.hook_type.value})")
            return hook.hook_id

    def remove_hook(self, hook_id: str) -> bool:
        """Remove an instrumentation hook"""
        with self._lock:
            if hook_id in self.hooks:
                del self.hooks[hook_id]
                logger.info(f"Removed hook: {hook_id}")
                return True
            return False

    def enable_hook(self, hook_id: str) -> bool:
        """Enable a disabled hook"""
        with self._lock:
            if hook_id in self.hooks:
                self.hooks[hook_id].enabled = True
                return True
            return False

    def disable_hook(self, hook_id: str) -> bool:
        """Disable a hook without removing it"""
        with self._lock:
            if hook_id in self.hooks:
                self.hooks[hook_id].enabled = False
                return True
            return False

    def instrument_binary(
        self,
        binary_path: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        trace_id: Optional[str] = None,
    ) -> InstrumentationTrace:
        """
        Instrument and execute a binary, collecting runtime information.

        Args:
            binary_path: Path to the binary to instrument
            args: Command-line arguments for the binary
            env: Environment variables
            trace_id: Optional unique ID for this trace

        Returns:
            InstrumentationTrace object with collected data
        """
        if not trace_id:
            trace_id = f"trace_{int(time.time() * 1000)}"

        trace = InstrumentationTrace(
            trace_id=trace_id, binary_path=binary_path, start_time=time.time()
        )

        self.traces[trace_id] = trace

        try:
            if self.config.backend == InstrumentationBackend.FRIDA:
                self._instrument_with_frida(binary_path, args, env, trace)
            elif self.config.backend == InstrumentationBackend.PIN:
                self._instrument_with_pin(binary_path, args, env, trace)
            elif self.config.backend == InstrumentationBackend.DYNAMORIO:
                self._instrument_with_dynamorio(binary_path, args, env, trace)
            elif self.config.backend == InstrumentationBackend.QEMU:
                self._instrument_with_qemu(binary_path, args, env, trace)
            else:
                raise ValueError(f"Unsupported backend: {self.config.backend}")

            trace.end_time = time.time()
            logger.info(f"Instrumentation complete: {trace_id}")

        except Exception as e:
            logger.error(f"Instrumentation failed: {e}")
            trace.exceptions.append(
                {"timestamp": time.time(), "error": str(e), "type": type(e).__name__}
            )
            trace.end_time = time.time()

        return trace

    def _instrument_with_frida(
        self,
        binary_path: str,
        args: Optional[List[str]],
        env: Optional[Dict[str, str]],
        trace: InstrumentationTrace,
    ):
        """Instrument binary using Frida"""
        try:
            import frida
        except ImportError:
            raise ImportError("Frida not installed. Install with: pip install frida")

        # Generate Frida script
        script_content = self._generate_frida_script()

        # Spawn the process
        device = frida.get_local_device()
        pid = device.spawn([binary_path] + (args or []))
        session = device.attach(pid)

        script = session.create_script(script_content)

        # Set up message handler
        def on_message(message, data):
            self._handle_frida_message(message, data, trace)

        script.on("message", on_message)
        script.load()

        # Resume execution
        device.resume(pid)

        # Wait for completion or timeout
        start = time.time()
        while time.time() - start < self.config.timeout:
            if not session.is_detached:
                time.sleep(0.1)
            else:
                break

        # Clean up
        try:
            script.unload()
            session.detach()
        except:
            pass

    def _generate_frida_script(self) -> str:
        """Generate Frida instrumentation script based on hooks"""
        script_parts = ["// Auto-generated Frida script", "", "// Function tracing"]

        # Add function hooks
        for hook_id, hook in self.hooks.items():
            if not hook.enabled:
                continue

            if hook.hook_type == HookType.FUNCTION_ENTRY:
                script_parts.append(f"""
Interceptor.attach(Module.findExportByName(null, '{hook.target}'), {{
    onEnter: function(args) {{
        send({{
            type: 'function_entry',
            hook_id: '{hook_id}',
            function: '{hook.target}',
            timestamp: Date.now(),
            args: [args[0], args[1], args[2], args[3]].map(ptr => ptr.toString())
        }});
    }},
    onLeave: function(retval) {{
        send({{
            type: 'function_exit',
            hook_id: '{hook_id}',
            function: '{hook.target}',
            timestamp: Date.now(),
            return: retval.toString()
        }});
    }}
}});
""")

        # Add memory access tracking if enabled
        if self.config.trace_memory:
            script_parts.append("""
// Memory access tracking (limited to specific regions)
Process.enumerateRanges('r--', {
    onMatch: function(range) {
        // Track memory reads/writes in executable regions
    },
    onComplete: function() {}
});
""")

        # Add syscall tracking if enabled
        if self.config.trace_syscalls:
            script_parts.append("""
// System call tracking
// Platform-specific implementation needed
""")

        return "\n".join(script_parts)

    def _handle_frida_message(
        self, message: Dict, data: Any, trace: InstrumentationTrace
    ):
        """Handle messages from Frida script"""
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type")

            if msg_type == "function_entry":
                trace.executed_functions.append(
                    {
                        "type": "entry",
                        "function": payload.get("function"),
                        "timestamp": payload.get("timestamp"),
                        "args": payload.get("args", []),
                    }
                )

                # Update hook hit count
                hook_id = payload.get("hook_id")
                if hook_id in self.hooks:
                    self.hooks[hook_id].hit_count += 1

            elif msg_type == "function_exit":
                trace.executed_functions.append(
                    {
                        "type": "exit",
                        "function": payload.get("function"),
                        "timestamp": payload.get("timestamp"),
                        "return_value": payload.get("return"),
                    }
                )

            elif msg_type == "memory_access":
                trace.memory_accesses.append(payload)

            elif msg_type == "syscall":
                trace.syscalls.append(payload)

            elif msg_type == "api_call":
                trace.api_calls.append(payload)

    def _instrument_with_pin(
        self,
        binary_path: str,
        args: Optional[List[str]],
        env: Optional[Dict[str, str]],
        trace: InstrumentationTrace,
    ):
        """Instrument binary using Intel Pin"""
        pin_root = os.environ.get("PIN_ROOT")
        if not pin_root:
            raise RuntimeError("PIN_ROOT environment variable not set")

        pin_executable = os.path.join(pin_root, "pin")
        pintool = self._generate_pintool()

        # Create output file for trace
        trace_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        trace_file.close()

        # Build Pin command
        cmd = [
            pin_executable,
            "-t",
            pintool,
            "-o",
            trace_file.name,
            "--",
            binary_path,
        ] + (args or [])

        # Execute with Pin
        result = subprocess.run(
            cmd, env=env, timeout=self.config.timeout, capture_output=True
        )

        # Parse trace output
        try:
            with open(trace_file.name, "r") as f:
                trace_data = json.load(f)
                self._parse_pin_trace(trace_data, trace)
        finally:
            os.unlink(trace_file.name)

    def _generate_pintool(self) -> str:
        """Generate or locate appropriate Pin tool"""
        # In a real implementation, this would generate a custom pintool
        # For now, return a placeholder path
        return "path/to/custom/pintool.so"

    def _parse_pin_trace(self, trace_data: Dict, trace: InstrumentationTrace):
        """Parse trace data from Pin"""
        trace.executed_functions = trace_data.get("functions", [])
        trace.memory_accesses = trace_data.get("memory", [])
        trace.coverage = trace_data.get("coverage", {})

    def _instrument_with_dynamorio(
        self,
        binary_path: str,
        args: Optional[List[str]],
        env: Optional[Dict[str, str]],
        trace: InstrumentationTrace,
    ):
        """Instrument binary using DynamoRIO"""
        dr_home = os.environ.get("DYNAMORIO_HOME")
        if not dr_home:
            raise RuntimeError("DYNAMORIO_HOME environment variable not set")

        logger.info("DynamoRIO instrumentation not yet fully implemented")
        # TODO: Implement DynamoRIO instrumentation

    def _instrument_with_qemu(
        self,
        binary_path: str,
        args: Optional[List[str]],
        env: Optional[Dict[str, str]],
        trace: InstrumentationTrace,
    ):
        """Instrument binary using QEMU user-mode emulation"""
        logger.info("QEMU instrumentation not yet fully implemented")
        # TODO: Implement QEMU instrumentation

    def get_trace(self, trace_id: str) -> Optional[InstrumentationTrace]:
        """Retrieve a trace by ID"""
        return self.traces.get(trace_id)

    def get_coverage(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Get code coverage information from a trace"""
        trace = self.get_trace(trace_id)
        if trace:
            return trace.coverage
        return None

    def get_execution_path(self, trace_id: str) -> List[str]:
        """Extract the execution path from a trace"""
        trace = self.get_trace(trace_id)
        if not trace:
            return []

        path = []
        for func in trace.executed_functions:
            if func.get("type") == "entry":
                path.append(func.get("function", "unknown"))

        return path

    def analyze_memory_accesses(self, trace_id: str) -> Dict[str, Any]:
        """Analyze memory access patterns from a trace"""
        trace = self.get_trace(trace_id)
        if not trace:
            return {}

        analysis = {
            "total_reads": 0,
            "total_writes": 0,
            "unique_addresses": set(),
            "hotspots": [],
        }

        address_counts = {}

        for access in trace.memory_accesses:
            access_type = access.get("type", "read")
            address = access.get("address")

            if access_type == "read":
                analysis["total_reads"] += 1
            elif access_type == "write":
                analysis["total_writes"] += 1

            if address:
                analysis["unique_addresses"].add(address)
                address_counts[address] = address_counts.get(address, 0) + 1

        # Find hotspots (most frequently accessed addresses)
        sorted_addresses = sorted(
            address_counts.items(), key=lambda x: x[1], reverse=True
        )
        analysis["hotspots"] = sorted_addresses[:10]
        analysis["unique_addresses"] = len(analysis["unique_addresses"])

        return analysis

    def export_trace(self, trace_id: str, output_path: str, format: str = "json"):
        """Export a trace to file"""
        trace = self.get_trace(trace_id)
        if not trace:
            raise ValueError(f"Trace not found: {trace_id}")

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(
                    {
                        "trace_id": trace.trace_id,
                        "binary_path": trace.binary_path,
                        "start_time": trace.start_time,
                        "end_time": trace.end_time,
                        "executed_functions": trace.executed_functions,
                        "memory_accesses": trace.memory_accesses[:1000],  # Limit size
                        "syscalls": trace.syscalls,
                        "api_calls": trace.api_calls,
                        "coverage": trace.coverage,
                        "exceptions": trace.exceptions,
                    },
                    f,
                    indent=2,
                )
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Trace exported to {output_path}")

    def cleanup(self):
        """Clean up resources"""
        with self._lock:
            for session_id in list(self.active_sessions.keys()):
                try:
                    session = self.active_sessions[session_id]
                    # Clean up session-specific resources
                    del self.active_sessions[session_id]
                except Exception as e:
                    logger.error(f"Error cleaning up session {session_id}: {e}")

            logger.info("Instrumentation engine cleanup complete")


def create_function_hook(function_name: str, hook_id: Optional[str] = None) -> Hook:
    """Convenience function to create a function entry/exit hook"""
    if not hook_id:
        hook_id = f"hook_{function_name}_{int(time.time() * 1000)}"

    return Hook(
        hook_id=hook_id, hook_type=HookType.FUNCTION_ENTRY, target=function_name
    )


def create_memory_hook(
    address: str, access_type: str = "rw", hook_id: Optional[str] = None
) -> Hook:
    """Convenience function to create a memory access hook"""
    if not hook_id:
        hook_id = f"hook_mem_{address}_{int(time.time() * 1000)}"

    hook_type = HookType.MEMORY_READ if "r" in access_type else HookType.MEMORY_WRITE

    return Hook(hook_id=hook_id, hook_type=hook_type, target=address)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create instrumentation engine
    config = InstrumentationConfig(
        backend=InstrumentationBackend.FRIDA, trace_memory=True, trace_syscalls=True
    )
    engine = InstrumentationEngine(config)

    # Add hooks
    hook = create_function_hook("main")
    engine.add_hook(hook)

    # Instrument binary (example)
    try:
        trace = engine.instrument_binary("/path/to/binary")
        print(f"Trace completed: {trace.trace_id}")
        print(f"Functions executed: {len(trace.executed_functions)}")
        print(f"Memory accesses: {len(trace.memory_accesses)}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        engine.cleanup()
