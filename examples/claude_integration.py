#!/usr/bin/env python3

"""Claude integration for GhidraInsight."""

import asyncio
import json
from typing import Generator, Optional

try:
    from anthropic import Anthropic
except ImportError:
    raise ImportError("Please install: pip install anthropic")

from ghidrainsight import GhidraInsightClient


class BinaryAnalyzer:
    """Analyzes binaries with Claude AI."""
    
    def __init__(self, ghidra_url: str = "http://localhost:8000"):
        """
        Initialize the analyzer.
        
        Args:
            ghidra_url: GhidraInsight server URL
        """
        self.ghidra_client = GhidraInsightClient(ghidra_url)
        self.claude_client = Anthropic()
        self.conversation_history = []
    
    async def analyze(
        self,
        binary_path: str,
        question: str,
    ) -> str:
        """
        Analyze a binary and answer a question.
        
        Args:
            binary_path: Path to binary file
            question: Question to ask Claude
            
        Returns:
            Claude's response
        """
        # Get analysis from GhidraInsight
        analysis = await self.ghidra_client.analyze_binary(
            binary_path,
            features=["crypto", "taint", "vulnerabilities"]
        )
        
        # Build context
        context = self._build_context(analysis, binary_path)
        
        # Ask Claude
        return self._query_claude(context, question)
    
    def analyze_stream(
        self,
        binary_path: str,
        question: str,
    ) -> Generator[str, None, None]:
        """Stream Claude's response."""
        analysis = asyncio.run(
            self.ghidra_client.analyze_binary(
                binary_path,
                features=["crypto", "taint", "vulnerabilities"]
            )
        )
        
        context = self._build_context(analysis, binary_path)
        
        yield from self._query_claude_stream(context, question)
    
    def _build_context(self, analysis: dict, binary_path: str) -> str:
        """Build analysis context for Claude."""
        context = f"""
## Binary Analysis Report

**File**: {binary_path}

### Detected Cryptographic Algorithms
{json.dumps(analysis.get('crypto', []), indent=2)}

### Vulnerabilities
{json.dumps(analysis.get('vulnerabilities', []), indent=2)}

### Taint Analysis
{json.dumps(analysis.get('taint', []), indent=2)}
"""
        return context
    
    def _query_claude(self, context: str, question: str) -> str:
        """Query Claude with context and question."""
        self.conversation_history.append({
            "role": "user",
            "content": f"{context}\n\nQuestion: {question}"
        })
        
        response = self.claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2048,
            messages=self.conversation_history
        )
        
        answer = response.content[0].text
        
        self.conversation_history.append({
            "role": "assistant",
            "content": answer
        })
        
        return answer
    
    def _query_claude_stream(
        self,
        context: str,
        question: str,
    ) -> Generator[str, None, None]:
        """Stream Claude's response."""
        self.conversation_history.append({
            "role": "user",
            "content": f"{context}\n\nQuestion: {question}"
        })
        
        with self.claude_client.messages.stream(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2048,
            messages=self.conversation_history
        ) as stream:
            for text in stream.text_stream:
                yield text


async def main():
    """Example usage."""
    analyzer = BinaryAnalyzer()
    
    # Example binary analysis
    binary = "example.elf"
    question = "What are the main security vulnerabilities in this binary?"
    
    print(f"Analyzing: {binary}")
    print(f"Question: {question}\n")
    
    response = await analyzer.analyze(binary, question)
    print(f"Claude: {response}")


if __name__ == "__main__":
    asyncio.run(main())
