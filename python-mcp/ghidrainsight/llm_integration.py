"""
LLM Integration Module for GhidraInsight

Provides AI-powered analysis capabilities for binary reverse engineering:
- Function name generation from IL
- Automatic comment generation
- Vulnerability explanation and context
- Code pattern recognition and suggestions
"""

import os
import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.core.credentials import AzureKeyCredential
from azure.core.exceptions import AzureError

from .config import Settings
from .logging_config import get_logger

logger = get_logger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers"""
    GITHUB = "github"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMModel(Enum):
    """Available LLM models for different tasks"""
    # GitHub Models (free tier available)
    GPT_4_1_MINI = "openai/gpt-4.1-mini"
    GPT_4_1 = "openai/gpt-4.1"
    GPT_5_MINI = "openai/gpt-5-mini"
    CODESTRAL = "mistral-ai/codestral-2501"

    # OpenAI direct
    GPT_4O_MINI = "gpt-4o-mini"
    GPT_4O = "gpt-4o"


@dataclass
class LLMConfig:
    """Configuration for LLM integration"""
    provider: LLMProvider
    model: str
    api_key: str
    endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2000
    timeout: int = 30


@dataclass
class AnalysisContext:
    """Context information for LLM analysis"""
    function_name: Optional[str] = None
    function_address: Optional[str] = None
    disassembly: Optional[str] = None
    pseudocode: Optional[str] = None
    binary_type: Optional[str] = None
    architecture: Optional[str] = None
    compiler: Optional[str] = None


class LLMClient:
    """Client for interacting with LLM services"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the LLM client based on provider"""
        try:
            if self.config.provider == LLMProvider.GITHUB:
                self.client = ChatCompletionsClient(
                    endpoint=self.config.endpoint or "https://models.github.ai/inference",
                    credential=AzureKeyCredential(self.config.api_key)
                )
            elif self.config.provider == LLMProvider.OPENAI:
                # For OpenAI, we'd use openai SDK directly
                # But for consistency, we'll use Azure AI Inference SDK
                self.client = ChatCompletionsClient(
                    endpoint=self.config.endpoint or "https://api.openai.com/v1",
                    credential=AzureKeyCredential(self.config.api_key)
                )
            else:
                raise ValueError(f"Unsupported provider: {self.config.provider}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            self.client = None

    async def generate_function_name(self, context: AnalysisContext) -> Optional[str]:
        """Generate a meaningful function name from disassembly/pseudocode"""
        if not self.client or not context.disassembly:
            return None

        system_prompt = """You are an expert reverse engineer. Given disassembly or pseudocode,
        generate a concise, meaningful function name that describes its purpose.
        Follow these rules:
        - Use camelCase for function names
        - Be descriptive but not verbose (max 30 chars)
        - Focus on the primary action/purpose
        - Avoid generic names like 'func1', 'sub_123'
        - Return only the function name, no explanation"""

        user_prompt = f"""
Disassembly:
{context.disassembly[:1000]}

{f'Pseudocode: {context.pseudocode[:500]}' if context.pseudocode else ''}

Generate a function name:"""

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.complete(
                    messages=[
                        SystemMessage(system_prompt),
                        UserMessage(user_prompt)
                    ],
                    temperature=0.3,  # Lower temperature for more consistent naming
                    max_tokens=50,
                    model=self.config.model
                )
            )

            function_name = response.choices[0].message.content.strip()
            # Clean up the response
            function_name = function_name.replace('```', '').strip()
            if function_name.startswith('function ') or function_name.startswith('def '):
                function_name = function_name.split(' ', 1)[1]

            return function_name if len(function_name) <= 30 else None

        except Exception as e:
            logger.error(f"Failed to generate function name: {e}")
            return None

    async def generate_comments(self, context: AnalysisContext) -> Optional[str]:
        """Generate helpful comments for a function"""
        if not self.client or not (context.disassembly or context.pseudocode):
            return None

        system_prompt = """You are an expert reverse engineer. Generate clear, concise comments
        that explain what a function does. Focus on:
        - Overall purpose
        - Key operations
        - Important parameters or return values
        - Any security implications

        Keep comments brief but informative."""

        user_prompt = f"""
Function: {context.function_name or 'Unknown'}
Address: {context.function_address or 'Unknown'}

{f'Disassembly: {context.disassembly[:800]}' if context.disassembly else ''}
{f'Pseudocode: {context.pseudocode[:600]}' if context.pseudocode else ''}

Generate comments:"""

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.complete(
                    messages=[
                        SystemMessage(system_prompt),
                        UserMessage(user_prompt)
                    ],
                    temperature=0.5,
                    max_tokens=300,
                    model=self.config.model
                )
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"Failed to generate comments: {e}")
            return None

    async def explain_vulnerability(self, vulnerability: Dict[str, Any],
                                  context: AnalysisContext) -> Optional[str]:
        """Explain a detected vulnerability in natural language"""
        if not self.client:
            return None

        system_prompt = """You are a cybersecurity expert. Explain vulnerabilities clearly,
        including:
        - What the vulnerability is
        - Why it's dangerous
        - How it could be exploited
        - Potential impact
        - Remediation suggestions

        Use simple language but be technically accurate."""

        vuln_info = f"""
Type: {vulnerability.get('type', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Location: {vulnerability.get('address', 'Unknown')}

Description: {vulnerability.get('description', '')}
"""

        user_prompt = f"""
{vuln_info}

Context:
- Function: {context.function_name or 'Unknown'}
- Binary Type: {context.binary_type or 'Unknown'}
- Architecture: {context.architecture or 'Unknown'}

Explain this vulnerability:"""

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.complete(
                    messages=[
                        SystemMessage(system_prompt),
                        UserMessage(user_prompt)
                    ],
                    temperature=0.3,
                    max_tokens=500,
                    model=self.config.model
                )
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"Failed to explain vulnerability: {e}")
            return None

    async def analyze_pattern(self, code_pattern: str, context: AnalysisContext) -> Optional[str]:
        """Analyze a code pattern and provide insights"""
        if not self.client:
            return None

        system_prompt = """You are an expert in binary analysis and reverse engineering.
        Analyze code patterns and provide insights about:
        - What the pattern does
        - Common uses or anti-patterns
        - Security implications
        - Optimization opportunities"""

        user_prompt = f"""
Pattern:
{code_pattern}

Context:
- Architecture: {context.architecture or 'Unknown'}
- Compiler: {context.compiler or 'Unknown'}

Analyze this pattern:"""

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.complete(
                    messages=[
                        SystemMessage(system_prompt),
                        UserMessage(user_prompt)
                    ],
                    temperature=0.4,
                    max_tokens=400,
                    model=self.config.model
                )
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"Failed to analyze pattern: {e}")
            return None


class LLMIntegration:
    """Main LLM integration class for GhidraInsight"""

    def __init__(self, config: Settings):
        self.config = config
        self.client: Optional[LLMClient] = None
        self._initialize_integration()

    def _initialize_integration(self):
        """Initialize LLM integration based on configuration"""
        llm_config = self._load_llm_config()
        if llm_config:
            try:
                self.client = LLMClient(llm_config)
                logger.info(f"LLM integration initialized with {llm_config.provider.value} provider")
            except Exception as e:
                logger.error(f"Failed to initialize LLM integration: {e}")
        else:
            logger.warning("LLM configuration not found, integration disabled")

    def _load_llm_config(self) -> Optional[LLMConfig]:
        """Load LLM configuration from environment and config"""
        # Check for GitHub token (preferred for free tier)
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            return LLMConfig(
                provider=LLMProvider.GITHUB,
                model=LLMModel.GPT_4_1_MINI.value,
                api_key=github_token,
                endpoint="https://models.github.ai/inference"
            )

        # Check for OpenAI API key
        openai_key = os.environ.get('OPENAI_API_KEY')
        if openai_key:
            return LLMConfig(
                provider=LLMProvider.OPENAI,
                model=LLMModel.GPT_4O_MINI.value,
                api_key=openai_key
            )

        # Check config file for other providers
        if hasattr(self.config, 'llm') and self.config.llm:
            llm_cfg = self.config.llm
            return LLMConfig(
                provider=LLMProvider(llm_cfg.get('provider', 'github')),
                model=llm_cfg.get('model', LLMModel.GPT_4_1_MINI.value),
                api_key=llm_cfg.get('api_key', ''),
                endpoint=llm_cfg.get('endpoint'),
                temperature=llm_cfg.get('temperature', 0.7),
                max_tokens=llm_cfg.get('max_tokens', 2000)
            )

        return None

    async def enhance_function_analysis(self, function_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance function analysis with LLM insights"""
        if not self.client:
            return function_data

        context = AnalysisContext(
            function_name=function_data.get('name'),
            function_address=function_data.get('address'),
            disassembly=function_data.get('disassembly'),
            pseudocode=function_data.get('pseudocode'),
            binary_type=function_data.get('binary_type'),
            architecture=function_data.get('architecture')
        )

        # Generate function name if not present or generic
        if not context.function_name or context.function_name.startswith(('sub_', 'func', 'unk')):
            generated_name = await self.client.generate_function_name(context)
            if generated_name:
                function_data['suggested_name'] = generated_name
                logger.info(f"Generated function name: {generated_name}")

        # Generate comments
        comments = await self.client.generate_comments(context)
        if comments:
            function_data['ai_comments'] = comments

        return function_data

    async def explain_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]],
                                    binary_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Add AI explanations to vulnerabilities"""
        if not self.client:
            return vulnerabilities

        context = AnalysisContext(
            binary_type=binary_context.get('type'),
            architecture=binary_context.get('architecture'),
            compiler=binary_context.get('compiler')
        )

        enhanced_vulns = []
        for vuln in vulnerabilities:
            explanation = await self.client.explain_vulnerability(vuln, context)
            if explanation:
                vuln_copy = vuln.copy()
                vuln_copy['ai_explanation'] = explanation
                enhanced_vulns.append(vuln_copy)
            else:
                enhanced_vulns.append(vuln)

        return enhanced_vulns

    async def analyze_code_patterns(self, patterns: List[str],
                                  binary_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze code patterns with AI insights"""
        if not self.client:
            return [{'pattern': p, 'analysis': None} for p in patterns]

        context = AnalysisContext(
            architecture=binary_context.get('architecture'),
            compiler=binary_context.get('compiler')
        )

        results = []
        for pattern in patterns:
            analysis = await self.client.analyze_pattern(pattern, context)
            results.append({
                'pattern': pattern,
                'ai_analysis': analysis
            })

        return results

    def is_available(self) -> bool:
        """Check if LLM integration is available"""
        return self.client is not None
