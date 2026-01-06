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
    GOOGLE = "google"


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
    GPT_4 = "gpt-4"
    GPT_3_5_TURBO = "gpt-3.5-turbo"
    
    # Anthropic Claude
    CLAUDE_3_OPUS = "claude-3-opus-20240229"
    CLAUDE_3_SONNET = "claude-3-sonnet-20240229"
    CLAUDE_3_HAIKU = "claude-3-haiku-20240307"
    CLAUDE_2 = "claude-2"
    
    # Google Gemini
    GEMINI_PRO = "gemini-pro"
    GEMINI_PRO_VISION = "gemini-pro-vision"


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
    optimize_context: bool = True  # Enable context optimization for cheaper inference
    max_context_length: int = 4000  # Maximum context length before optimization


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
    
    def optimize(self, max_length: int = 4000) -> "AnalysisContext":
        """
        Optimize context by truncating and summarizing long content.
        This reduces token usage and costs while preserving key information.
        """
        optimized = AnalysisContext(
            function_name=self.function_name,
            function_address=self.function_address,
            binary_type=self.binary_type,
            architecture=self.architecture,
            compiler=self.compiler
        )
        
        # Truncate disassembly if too long
        if self.disassembly:
            if len(self.disassembly) > max_length:
                # Keep first and last parts, remove middle
                half = max_length // 2
                optimized.disassembly = (
                    self.disassembly[:half] + 
                    "\n[... truncated for context optimization ...]\n" +
                    self.disassembly[-half:]
                )
            else:
                optimized.disassembly = self.disassembly
        
        # Truncate pseudocode if too long
        if self.pseudocode:
            if len(self.pseudocode) > max_length:
                half = max_length // 2
                optimized.pseudocode = (
                    self.pseudocode[:half] + 
                    "\n[... truncated ...]\n" +
                    self.pseudocode[-half:]
                )
            else:
                optimized.pseudocode = self.pseudocode
        
        return optimized


class LLMClient:
    """Client for interacting with LLM services"""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = None
        self._client_type = None
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
                try:
                    import openai
                    self.client = openai.AsyncOpenAI(api_key=self.config.api_key)
                    self._client_type = "openai"
                except ImportError:
                    # Fallback to Azure AI Inference SDK
                    self.client = ChatCompletionsClient(
                        endpoint=self.config.endpoint or "https://api.openai.com/v1",
                        credential=AzureKeyCredential(self.config.api_key)
                    )
                    self._client_type = "azure"
            elif self.config.provider == LLMProvider.ANTHROPIC:
                try:
                    import anthropic
                    self.client = anthropic.AsyncAnthropic(api_key=self.config.api_key)
                    self._client_type = "anthropic"
                except ImportError:
                    logger.error("anthropic package not installed. Install with: pip install anthropic")
                    self.client = None
                    return
            elif self.config.provider == LLMProvider.GOOGLE:
                try:
                    import google.generativeai as genai
                    genai.configure(api_key=self.config.api_key)
                    self.client = genai
                    self._client_type = "google"
                except ImportError:
                    logger.error("google-generativeai package not installed. Install with: pip install google-generativeai")
                    self.client = None
                    return
            else:
                raise ValueError(f"Unsupported provider: {self.config.provider}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            self.client = None

    def _optimize_context_if_needed(self, context: AnalysisContext) -> AnalysisContext:
        """Optimize context if optimization is enabled and context is too long"""
        if self.config.optimize_context and context:
            total_length = (
                len(context.disassembly or "") + 
                len(context.pseudocode or "")
            )
            if total_length > self.config.max_context_length:
                return context.optimize(self.config.max_context_length)
        return context

    async def _call_llm(self, system_prompt: str, user_prompt: str, 
                       temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Unified LLM call method supporting all providers"""
        if not self.client:
            return None
        
        try:
            if hasattr(self, '_client_type'):
                client_type = self._client_type
            else:
                client_type = "azure"  # Default for GitHub/Azure
            
            if client_type == "openai":
                response = await self.client.chat.completions.create(
                    model=self.config.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens
                )
                return response.choices[0].message.content.strip()
            
            elif client_type == "anthropic":
                response = await self.client.messages.create(
                    model=self.config.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=[{"role": "user", "content": user_prompt}]
                )
                return response.content[0].text.strip()
            
            elif client_type == "google":
                model = self.client.GenerativeModel(self.config.model)
                prompt = f"{system_prompt}\n\n{user_prompt}"
                response = await model.generate_content_async(
                    prompt,
                    generation_config={
                        "temperature": temperature,
                        "max_output_tokens": max_tokens
                    }
                )
                return response.text.strip()
            
            else:  # Azure/GitHub
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.complete(
                        messages=[
                            SystemMessage(system_prompt),
                            UserMessage(user_prompt)
                        ],
                        temperature=temperature,
                        max_tokens=max_tokens,
                        model=self.config.model
                    )
                )
                return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return None

    async def generate_function_name(self, context: AnalysisContext) -> Optional[str]:
        """Generate a meaningful function name from disassembly/pseudocode"""
        if not self.client or not context.disassembly:
            return None

        # Optimize context if needed
        context = self._optimize_context_if_needed(context)

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
{context.disassembly[:1000] if context.disassembly else 'N/A'}

{f'Pseudocode: {context.pseudocode[:500]}' if context.pseudocode else ''}

Generate a function name:"""

        try:
            function_name = await self._call_llm(
                system_prompt, user_prompt, 
                temperature=0.3, max_tokens=50
            )
            
            if not function_name:
                return None
            
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

        # Optimize context if needed
        context = self._optimize_context_if_needed(context)

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

{f'Disassembly: {context.disassembly[:800] if context.disassembly else ""}'}
{f'Pseudocode: {context.pseudocode[:600] if context.pseudocode else ""}'}

Generate comments:"""

        try:
            return await self._call_llm(
                system_prompt, user_prompt,
                temperature=0.5, max_tokens=300
            )
        except Exception as e:
            logger.error(f"Failed to generate comments: {e}")
            return None

    async def explain_vulnerability(self, vulnerability: Dict[str, Any],
                                  context: AnalysisContext) -> Optional[str]:
        """Explain a detected vulnerability in natural language"""
        if not self.client:
            return None

        # Optimize context if needed
        context = self._optimize_context_if_needed(context)

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
            return await self._call_llm(
                system_prompt, user_prompt,
                temperature=0.3, max_tokens=500
            )
        except Exception as e:
            logger.error(f"Failed to explain vulnerability: {e}")
            return None

    async def analyze_pattern(self, code_pattern: str, context: AnalysisContext) -> Optional[str]:
        """Analyze a code pattern and provide insights"""
        if not self.client:
            return None

        # Optimize context if needed
        context = self._optimize_context_if_needed(context)

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
            return await self._call_llm(
                system_prompt, user_prompt,
                temperature=0.4, max_tokens=400
            )
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
        # Check for Anthropic/Claude API key
        anthropic_key = os.environ.get('ANTHROPIC_API_KEY')
        if anthropic_key:
            return LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model=LLMModel.CLAUDE_3_HAIKU.value,
                api_key=anthropic_key,
                optimize_context=True
            )

        # Check for Google/Gemini API key
        google_key = os.environ.get('GOOGLE_API_KEY')
        if google_key:
            return LLMConfig(
                provider=LLMProvider.GOOGLE,
                model=LLMModel.GEMINI_PRO.value,
                api_key=google_key,
                optimize_context=True
            )

        # Check for GitHub token (preferred for free tier)
        github_token = os.environ.get('GITHUB_TOKEN')
        if github_token:
            return LLMConfig(
                provider=LLMProvider.GITHUB,
                model=LLMModel.GPT_4_1_MINI.value,
                api_key=github_token,
                endpoint="https://models.github.ai/inference",
                optimize_context=True
            )

        # Check for OpenAI API key
        openai_key = os.environ.get('OPENAI_API_KEY')
        if openai_key:
            return LLMConfig(
                provider=LLMProvider.OPENAI,
                model=LLMModel.GPT_4O_MINI.value,
                api_key=openai_key,
                optimize_context=True
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
                max_tokens=llm_cfg.get('max_tokens', 2000),
                optimize_context=llm_cfg.get('optimize_context', True),
                max_context_length=llm_cfg.get('max_context_length', 4000)
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
