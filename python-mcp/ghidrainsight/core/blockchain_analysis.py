"""
Blockchain Smart Contract Analysis Module for GhidraInsight

This module provides comprehensive analysis of blockchain smart contracts,
including vulnerability detection, bytecode analysis, and security auditing
for Ethereum, Solana, and other blockchain platforms.

Author: GhidraInsight Team
License: Apache 2.0
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class BlockchainPlatform(Enum):
    """Supported blockchain platforms"""

    ETHEREUM = "ethereum"
    SOLANA = "solana"
    BINANCE_SMART_CHAIN = "bsc"
    POLYGON = "polygon"
    AVALANCHE = "avalanche"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    TRON = "tron"


class VulnerabilityType(Enum):
    """Smart contract vulnerability types"""

    REENTRANCY = "reentrancy"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    UNCHECKED_CALL = "unchecked_call"
    DELEGATECALL = "delegatecall"
    TX_ORIGIN = "tx_origin_authentication"
    UNPROTECTED_SELFDESTRUCT = "unprotected_selfdestruct"
    TIMESTAMP_DEPENDENCE = "timestamp_dependence"
    BLOCK_NUMBER_DEPENDENCE = "block_number_dependence"
    FRONT_RUNNING = "front_running"
    ACCESS_CONTROL = "access_control"
    UNINITIALIZED_STORAGE = "uninitialized_storage"
    ARITHMETIC = "arithmetic"
    DOS = "denial_of_service"
    LOGIC_ERROR = "logic_error"
    RANDOMNESS = "weak_randomness"
    FLASH_LOAN = "flash_loan_attack"


class Severity(Enum):
    """Vulnerability severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ContractFunction:
    """Smart contract function information"""

    name: str
    selector: str  # Function signature hash
    signature: str  # Full function signature
    visibility: str  # public, external, internal, private
    mutability: str  # view, pure, payable, nonpayable
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: List[Dict[str, str]] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    gas_cost: Optional[int] = None


@dataclass
class ContractEvent:
    """Smart contract event information"""

    name: str
    signature: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    indexed_count: int = 0


@dataclass
class Vulnerability:
    """Detected vulnerability"""

    vuln_id: str
    vuln_type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    location: str  # Function name or line number
    recommendation: str
    references: List[str] = field(default_factory=list)
    code_snippet: Optional[str] = None
    confidence: float = 1.0


@dataclass
class SmartContractAnalysis:
    """Results of smart contract analysis"""

    contract_address: Optional[str]
    contract_name: str
    platform: BlockchainPlatform
    compiler_version: Optional[str] = None
    optimization_enabled: bool = False
    bytecode_hash: str = ""
    source_hash: Optional[str] = None

    # Contract structure
    functions: List[ContractFunction] = field(default_factory=list)
    events: List[ContractEvent] = field(default_factory=list)
    state_variables: List[Dict[str, Any]] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)

    # Security analysis
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    security_score: float = 0.0
    risk_level: str = "unknown"

    # Code quality
    code_complexity: int = 0
    lines_of_code: int = 0
    test_coverage: float = 0.0

    # Gas analysis
    total_gas_cost: int = 0
    gas_optimizations: List[str] = field(default_factory=list)

    # Dependencies
    imported_contracts: List[str] = field(default_factory=list)
    external_calls: List[str] = field(default_factory=list)

    # Metadata
    analyzed_at: float = field(default_factory=time.time)
    analysis_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BlockchainAnalysisConfig:
    """Configuration for blockchain analysis"""

    platform: BlockchainPlatform = BlockchainPlatform.ETHEREUM
    enable_vulnerability_scan: bool = True
    enable_gas_analysis: bool = True
    enable_optimization_check: bool = True
    deep_analysis: bool = True
    check_external_calls: bool = True
    analyze_dependencies: bool = True
    max_analysis_time: int = 300  # seconds


class BlockchainAnalyzer:
    """
    Main blockchain smart contract analyzer.
    """

    def __init__(self, config: Optional[BlockchainAnalysisConfig] = None):
        self.config = config or BlockchainAnalysisConfig()
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        self.opcodes = self._initialize_opcodes()
        self.function_signatures = {}
        self.event_signatures = {}

    def _initialize_vulnerability_patterns(self) -> Dict[VulnerabilityType, Dict]:
        """Initialize vulnerability detection patterns"""
        return {
            VulnerabilityType.REENTRANCY: {
                "patterns": [
                    r"call\.value\(",
                    r"\.call\{value:",
                    r"\.send\(",
                    r"\.transfer\(",
                ],
                "severity": Severity.CRITICAL,
                "description": "Potential reentrancy vulnerability",
            },
            VulnerabilityType.INTEGER_OVERFLOW: {
                "patterns": [r"\+\s*=", r"\*\s*=", r"unchecked"],
                "severity": Severity.HIGH,
                "description": "Potential integer overflow",
            },
            VulnerabilityType.UNCHECKED_CALL: {
                "patterns": [r"\.call\(", r"\.delegatecall\(", r"\.staticcall\("],
                "severity": Severity.HIGH,
                "description": "Unchecked external call",
            },
            VulnerabilityType.TX_ORIGIN: {
                "patterns": [r"tx\.origin"],
                "severity": Severity.MEDIUM,
                "description": "Use of tx.origin for authentication",
            },
            VulnerabilityType.TIMESTAMP_DEPENDENCE: {
                "patterns": [r"block\.timestamp", r"now"],
                "severity": Severity.MEDIUM,
                "description": "Timestamp dependence detected",
            },
            VulnerabilityType.UNPROTECTED_SELFDESTRUCT: {
                "patterns": [r"selfdestruct\(", r"suicide\("],
                "severity": Severity.CRITICAL,
                "description": "Unprotected selfdestruct",
            },
        }

    def _initialize_opcodes(self) -> Dict[int, str]:
        """Initialize EVM opcodes"""
        return {
            0x00: "STOP",
            0x01: "ADD",
            0x02: "MUL",
            0x03: "SUB",
            0x04: "DIV",
            0x05: "SDIV",
            0x06: "MOD",
            0x10: "LT",
            0x11: "GT",
            0x20: "SHA3",
            0x30: "ADDRESS",
            0x31: "BALANCE",
            0x32: "ORIGIN",
            0x33: "CALLER",
            0x34: "CALLVALUE",
            0x35: "CALLDATALOAD",
            0x36: "CALLDATASIZE",
            0x37: "CALLDATACOPY",
            0x40: "BLOCKHASH",
            0x41: "COINBASE",
            0x42: "TIMESTAMP",
            0x43: "NUMBER",
            0x50: "POP",
            0x51: "MLOAD",
            0x52: "MSTORE",
            0x53: "MSTORE8",
            0x54: "SLOAD",
            0x55: "SSTORE",
            0x56: "JUMP",
            0x57: "JUMPI",
            0x58: "PC",
            0x59: "MSIZE",
            0x5A: "GAS",
            0x5B: "JUMPDEST",
            0xA0: "LOG0",
            0xA1: "LOG1",
            0xA2: "LOG2",
            0xA3: "LOG3",
            0xA4: "LOG4",
            0xF0: "CREATE",
            0xF1: "CALL",
            0xF2: "CALLCODE",
            0xF3: "RETURN",
            0xF4: "DELEGATECALL",
            0xF5: "CREATE2",
            0xFA: "STATICCALL",
            0xFD: "REVERT",
            0xFE: "INVALID",
            0xFF: "SELFDESTRUCT",
        }

    def analyze_contract(
        self,
        bytecode: Optional[bytes] = None,
        source_code: Optional[str] = None,
        abi: Optional[List[Dict]] = None,
        contract_address: Optional[str] = None,
    ) -> SmartContractAnalysis:
        """
        Analyze a smart contract.

        Args:
            bytecode: Contract bytecode
            source_code: Contract source code (Solidity)
            abi: Contract ABI
            contract_address: Deployed contract address

        Returns:
            SmartContractAnalysis object
        """
        start_time = time.time()

        # Calculate bytecode hash
        bytecode_hash = ""
        if bytecode:
            bytecode_hash = hashlib.sha256(bytecode).hexdigest()

        # Calculate source hash
        source_hash = None
        if source_code:
            source_hash = hashlib.sha256(source_code.encode()).hexdigest()

        # Initialize analysis result
        analysis = SmartContractAnalysis(
            contract_address=contract_address,
            contract_name="Unknown",
            platform=self.config.platform,
            bytecode_hash=bytecode_hash,
            source_hash=source_hash,
        )

        # Parse ABI
        if abi:
            self._parse_abi(abi, analysis)

        # Analyze bytecode
        if bytecode:
            self._analyze_bytecode(bytecode, analysis)

        # Analyze source code
        if source_code:
            self._analyze_source_code(source_code, analysis)

        # Vulnerability scanning
        if self.config.enable_vulnerability_scan:
            self._scan_vulnerabilities(bytecode, source_code, analysis)

        # Gas analysis
        if self.config.enable_gas_analysis:
            self._analyze_gas_usage(bytecode, source_code, analysis)

        # Calculate security score
        self._calculate_security_score(analysis)

        analysis.analysis_time = time.time() - start_time
        logger.info(
            f"Contract analysis completed in {analysis.analysis_time:.2f}s - "
            f"Security score: {analysis.security_score:.2f}"
        )

        return analysis

    def _parse_abi(self, abi: List[Dict], analysis: SmartContractAnalysis):
        """Parse contract ABI"""
        for item in abi:
            item_type = item.get("type")

            if item_type == "function":
                func = ContractFunction(
                    name=item.get("name", ""),
                    selector=self._calculate_function_selector(item),
                    signature=self._get_function_signature(item),
                    visibility=item.get("stateMutability", "nonpayable"),
                    mutability=item.get("stateMutability", "nonpayable"),
                    parameters=item.get("inputs", []),
                    returns=item.get("outputs", []),
                )
                analysis.functions.append(func)

            elif item_type == "event":
                event = ContractEvent(
                    name=item.get("name", ""),
                    signature=self._get_event_signature(item),
                    parameters=item.get("inputs", []),
                    indexed_count=sum(
                        1 for inp in item.get("inputs", []) if inp.get("indexed")
                    ),
                )
                analysis.events.append(event)

            elif item_type == "constructor":
                analysis.metadata["has_constructor"] = True

        logger.info(
            f"Parsed ABI: {len(analysis.functions)} functions, "
            f"{len(analysis.events)} events"
        )

    def _calculate_function_selector(self, func_item: Dict) -> str:
        """Calculate function selector (first 4 bytes of keccak256)"""
        signature = self._get_function_signature(func_item)
        # In production, use Web3.keccak()
        hash_bytes = hashlib.sha256(signature.encode()).digest()[:4]
        return "0x" + hash_bytes.hex()

    def _get_function_signature(self, func_item: Dict) -> str:
        """Get function signature string"""
        name = func_item.get("name", "")
        inputs = func_item.get("inputs", [])
        param_types = [inp.get("type", "") for inp in inputs]
        return f"{name}({','.join(param_types)})"

    def _get_event_signature(self, event_item: Dict) -> str:
        """Get event signature string"""
        name = event_item.get("name", "")
        inputs = event_item.get("inputs", [])
        param_types = [inp.get("type", "") for inp in inputs]
        return f"{name}({','.join(param_types)})"

    def _analyze_bytecode(self, bytecode: bytes, analysis: SmartContractAnalysis):
        """Analyze contract bytecode"""
        # Disassemble bytecode
        instructions = self._disassemble_bytecode(bytecode)

        # Analyze control flow
        self._analyze_control_flow(instructions, analysis)

        # Detect patterns
        self._detect_bytecode_patterns(instructions, analysis)

        # Extract metadata
        self._extract_bytecode_metadata(bytecode, analysis)

        logger.info(f"Bytecode analysis complete: {len(instructions)} instructions")

    def _disassemble_bytecode(self, bytecode: bytes) -> List[Dict[str, Any]]:
        """Disassemble bytecode to instructions"""
        instructions = []
        pc = 0

        while pc < len(bytecode):
            opcode = bytecode[pc]
            mnemonic = self.opcodes.get(opcode, f"UNKNOWN_{opcode:02x}")

            instruction = {"pc": pc, "opcode": opcode, "mnemonic": mnemonic}

            # Handle PUSH instructions (0x60-0x7F)
            if 0x60 <= opcode <= 0x7F:
                push_size = opcode - 0x5F
                if pc + push_size < len(bytecode):
                    push_data = bytecode[pc + 1 : pc + 1 + push_size]
                    instruction["data"] = push_data.hex()
                    pc += push_size

            instructions.append(instruction)
            pc += 1

        return instructions

    def _analyze_control_flow(
        self, instructions: List[Dict], analysis: SmartContractAnalysis
    ):
        """Analyze control flow of bytecode"""
        jumps = []
        jumpdests = []

        for inst in instructions:
            if inst["mnemonic"] == "JUMP":
                jumps.append(inst["pc"])
            elif inst["mnemonic"] == "JUMPI":
                jumps.append(inst["pc"])
            elif inst["mnemonic"] == "JUMPDEST":
                jumpdests.append(inst["pc"])

        # Calculate code complexity based on control flow
        analysis.code_complexity = len(jumps) + len(jumpdests)

    def _detect_bytecode_patterns(
        self, instructions: List[Dict], analysis: SmartContractAnalysis
    ):
        """Detect security patterns in bytecode"""
        # Check for dangerous opcodes
        dangerous_opcodes = ["DELEGATECALL", "SELFDESTRUCT", "CALLCODE"]

        for inst in instructions:
            if inst["mnemonic"] in dangerous_opcodes:
                vuln_id = f"bytecode_{inst['pc']}"
                vuln = Vulnerability(
                    vuln_id=vuln_id,
                    vuln_type=VulnerabilityType.DELEGATECALL
                    if inst["mnemonic"] == "DELEGATECALL"
                    else VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
                    severity=Severity.HIGH,
                    title=f"Dangerous opcode: {inst['mnemonic']}",
                    description=f"Bytecode contains {inst['mnemonic']} at PC {inst['pc']}",
                    location=f"PC: {inst['pc']}",
                    recommendation="Ensure proper access control",
                )
                analysis.vulnerabilities.append(vuln)

    def _extract_bytecode_metadata(
        self, bytecode: bytes, analysis: SmartContractAnalysis
    ):
        """Extract metadata from bytecode"""
        # Check for metadata at the end (Solidity compiler adds metadata)
        if len(bytecode) > 50:
            # Look for CBOR-encoded metadata
            # Format: 0xa2 0x64 'i' 'p' 'f' 's' 0x58 0x22 <34 bytes> 0x64 's' 'o' 'l' 'c' 0x43 <3 bytes>
            last_bytes = bytecode[-50:]
            if b"ipfs" in last_bytes or b"solc" in last_bytes:
                analysis.metadata["has_metadata"] = True

                # Try to extract compiler version
                solc_pos = last_bytes.find(b"solc")
                if solc_pos != -1 and solc_pos + 5 < len(last_bytes):
                    version_bytes = last_bytes[solc_pos + 5 : solc_pos + 8]
                    if len(version_bytes) == 3:
                        analysis.compiler_version = (
                            f"{version_bytes[0]}.{version_bytes[1]}.{version_bytes[2]}"
                        )

    def _analyze_source_code(self, source_code: str, analysis: SmartContractAnalysis):
        """Analyze contract source code"""
        # Extract contract name
        contract_match = re.search(r"contract\s+(\w+)", source_code)
        if contract_match:
            analysis.contract_name = contract_match.group(1)

        # Count lines of code
        analysis.lines_of_code = len(
            [line for line in source_code.split("\n") if line.strip()]
        )

        # Extract state variables
        state_vars = re.findall(
            r"(public|private|internal)?\s+(uint|int|address|bool|string|bytes\d*)\s+(\w+)",
            source_code,
        )
        for visibility, var_type, var_name in state_vars:
            analysis.state_variables.append(
                {
                    "name": var_name,
                    "type": var_type,
                    "visibility": visibility or "internal",
                }
            )

        # Extract imported contracts
        imports = re.findall(r'import\s+["\'](.+?)["\']', source_code)
        analysis.imported_contracts = imports

        logger.info(
            f"Source code analysis: {analysis.lines_of_code} LOC, "
            f"{len(analysis.state_variables)} state variables"
        )

    def _scan_vulnerabilities(
        self,
        bytecode: Optional[bytes],
        source_code: Optional[str],
        analysis: SmartContractAnalysis,
    ):
        """Scan for vulnerabilities"""
        if source_code:
            self._scan_source_vulnerabilities(source_code, analysis)

        if bytecode:
            self._scan_bytecode_vulnerabilities(bytecode, analysis)

        logger.info(
            f"Vulnerability scan complete: {len(analysis.vulnerabilities)} issues found"
        )

    def _scan_source_vulnerabilities(
        self, source_code: str, analysis: SmartContractAnalysis
    ):
        """Scan source code for vulnerabilities"""
        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for pattern in vuln_info["patterns"]:
                matches = re.finditer(pattern, source_code, re.IGNORECASE)
                for match in matches:
                    # Get line number
                    line_num = source_code[: match.start()].count("\n") + 1

                    # Check for mitigations
                    if not self._has_mitigation(source_code, match, vuln_type):
                        vuln_id = f"src_{vuln_type.value}_{line_num}"
                        vuln = Vulnerability(
                            vuln_id=vuln_id,
                            vuln_type=vuln_type,
                            severity=vuln_info["severity"],
                            title=f"{vuln_type.value.replace('_', ' ').title()}",
                            description=vuln_info["description"],
                            location=f"Line {line_num}",
                            recommendation=self._get_recommendation(vuln_type),
                            code_snippet=self._get_code_snippet(source_code, line_num),
                        )
                        analysis.vulnerabilities.append(vuln)

    def _has_mitigation(
        self, source_code: str, match: re.Match, vuln_type: VulnerabilityType
    ) -> bool:
        """Check if vulnerability has mitigation"""
        # Check for common mitigation patterns
        context_start = max(0, match.start() - 500)
        context_end = min(len(source_code), match.end() + 500)
        context = source_code[context_start:context_end]

        if vuln_type == VulnerabilityType.REENTRANCY:
            # Check for reentrancy guard
            if "nonReentrant" in context or "ReentrancyGuard" in context:
                return True
            # Check for checks-effects-interactions pattern
            if "require(" in context and context.index("require(") < context.index(
                match.group()
            ):
                return True

        elif vuln_type == VulnerabilityType.UNCHECKED_CALL:
            # Check if return value is checked
            if "require(" in context or "assert(" in context or "if (" in context:
                return True

        return False

    def _get_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get recommendation for vulnerability"""
        recommendations = {
            VulnerabilityType.REENTRANCY: "Use ReentrancyGuard or checks-effects-interactions pattern",
            VulnerabilityType.INTEGER_OVERFLOW: "Use SafeMath library or Solidity 0.8+ with automatic checks",
            VulnerabilityType.UNCHECKED_CALL: "Always check return values of external calls",
            VulnerabilityType.TX_ORIGIN: "Use msg.sender instead of tx.origin for authentication",
            VulnerabilityType.TIMESTAMP_DEPENDENCE: "Avoid using timestamp for critical logic",
            VulnerabilityType.UNPROTECTED_SELFDESTRUCT: "Add access control to selfdestruct",
        }
        return recommendations.get(
            vuln_type, "Review and fix the identified vulnerability"
        )

    def _get_code_snippet(self, source_code: str, line_num: int) -> str:
        """Get code snippet around vulnerability"""
        lines = source_code.split("\n")
        start = max(0, line_num - 3)
        end = min(len(lines), line_num + 2)
        return "\n".join(lines[start:end])

    def _scan_bytecode_vulnerabilities(
        self, bytecode: bytes, analysis: SmartContractAnalysis
    ):
        """Scan bytecode for vulnerabilities"""
        # Already done in _detect_bytecode_patterns
        pass

    def _analyze_gas_usage(
        self,
        bytecode: Optional[bytes],
        source_code: Optional[str],
        analysis: SmartContractAnalysis,
    ):
        """Analyze gas usage and suggest optimizations"""
        if source_code:
            # Check for gas optimization opportunities
            optimizations = []

            # Storage optimization
            if "storage" in source_code:
                if re.search(r"uint8|uint16|uint32|uint64|uint128", source_code):
                    optimizations.append(
                        "Consider using uint256 for storage variables to save gas"
                    )

            # Loop optimization
            if ".length" in source_code and "for" in source_code:
                optimizations.append(
                    "Cache array length in loops to save gas: uint len = arr.length"
                )

            # Function visibility
            if "public" in source_code:
                optimizations.append(
                    "Use external instead of public for functions not called internally"
                )

            # Short-circuit evaluation
            if "||" in source_code or "&&" in source_code:
                optimizations.append(
                    "Order conditions by gas cost (cheapest first) in boolean expressions"
                )

            analysis.gas_optimizations = optimizations

        # Estimate gas cost from bytecode
        if bytecode:
            # Simple estimation based on bytecode size
            analysis.total_gas_cost = len(bytecode) * 200  # Rough estimate

    def _calculate_security_score(self, analysis: SmartContractAnalysis):
        """Calculate overall security score"""
        score = 100.0

        # Deduct points based on vulnerabilities
        for vuln in analysis.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                score -= 25
            elif vuln.severity == Severity.HIGH:
                score -= 15
            elif vuln.severity == Severity.MEDIUM:
                score -= 8
            elif vuln.severity == Severity.LOW:
                score -= 3

        score = max(0.0, score)
        analysis.security_score = score

        # Determine risk level
        if score >= 90:
            analysis.risk_level = "low"
        elif score >= 70:
            analysis.risk_level = "medium"
        elif score >= 50:
            analysis.risk_level = "high"
        else:
            analysis.risk_level = "critical"

    def export_report(
        self, analysis: SmartContractAnalysis, output_path: str, format: str = "json"
    ):
        """Export analysis report"""
        report = {
            "contract_name": analysis.contract_name,
            "contract_address": analysis.contract_address,
            "platform": analysis.platform.value,
            "compiler_version": analysis.compiler_version,
            "bytecode_hash": analysis.bytecode_hash,
            "security_score": analysis.security_score,
            "risk_level": analysis.risk_level,
            "functions": [
                {
                    "name": f.name,
                    "selector": f.selector,
                    "visibility": f.visibility,
                    "mutability": f.mutability,
                }
                for f in analysis.functions
            ],
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "type": v.vuln_type.value,
                    "severity": v.severity.value,
                    "title": v.title,
                    "description": v.description,
                    "location": v.location,
                    "recommendation": v.recommendation,
                }
                for v in analysis.vulnerabilities
            ],
            "gas_optimizations": analysis.gas_optimizations,
            "analysis_time": analysis.analysis_time,
        }

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)

        logger.info(f"Report exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create analyzer
    config = BlockchainAnalysisConfig(
        platform=BlockchainPlatform.ETHEREUM,
        enable_vulnerability_scan=True,
        enable_gas_analysis=True,
    )
    analyzer = BlockchainAnalyzer(config)

    # Example Solidity source code
    source_code = """
    pragma solidity ^0.8.0;

    contract VulnerableContract {
        mapping(address => uint) public balances;

        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
    }
    """

    # Analyze contract
    analysis = analyzer.analyze_contract(source_code=source_code)

    print(f"Contract: {analysis.contract_name}")
    print(f"Security Score: {analysis.security_score:.2f}")
    print(f"Risk Level: {analysis.risk_level}")
    print(f"Vulnerabilities: {len(analysis.vulnerabilities)}")

    for vuln in analysis.vulnerabilities:
        print(f"  [{vuln.severity.value}] {vuln.title} - {vuln.location}")

    # Export report
    analyzer.export_report(analysis, "contract_analysis_report.json")
