#!/usr/bin/env python3

"""ChatGPT integration for GhidraInsight."""

import asyncio
import json
from typing import Any, Dict, List, Optional

try:
    import openai
except ImportError:
    raise ImportError("Please install: pip install openai")

from ghidrainsight import GhidraInsightClient


class ChatGPTAnalyzer:
    """Analyzes binaries with ChatGPT."""
    
    def __init__(self, ghidra_url: str = "http://localhost:8000"):
        """Initialize analyzer with GhidraInsight client."""
        self.ghidra_client = GhidraInsightClient(ghidra_url)
    
    async def analyze_with_gpt(
        self,
        binary_path: str,
        question: str,
        model: str = "gpt-4",
    ) -> str:
        """
        Analyze binary and ask ChatGPT.
        
        Args:
            binary_path: Path to binary
            question: Question to ask
            model: GPT model to use
            
        Returns:
            ChatGPT response
        """
        # Get analysis
        analysis = await self.ghidra_client.analyze_binary(
            binary_path,
            features=["crypto", "taint", "vulnerabilities"]
        )
        
        # Create prompt
        prompt = self._create_prompt(analysis, question)
        
        # Query ChatGPT
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert analyzing binaries."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
        )
        
        return response.choices[0].message.content
    
    async def analyze_with_functions(
        self,
        binary_path: str,
        question: str,
    ) -> Dict[str, Any]:
        """
        Use ChatGPT function calling for complex analysis.
        
        Args:
            binary_path: Path to binary
            question: Question to ask
            
        Returns:
            Analysis results with function calls
        """
        functions = [
            {
                "name": "analyze_binary",
                "description": "Analyze a binary file with GhidraInsight",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "features": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Features: crypto, taint, vulnerabilities"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "analyze_function",
                "description": "Analyze a specific function",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex)"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Analysis depth"
                        }
                    },
                    "required": ["address"]
                }
            }
        ]
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system",
                    "content": "Analyze the binary and answer security questions."
                },
                {
                    "role": "user",
                    "content": f"Binary: {binary_path}\n\nQuestion: {question}"
                }
            ],
            functions=functions,
            function_call="auto",
        )
        
        return {
            "response": response.choices[0].message,
            "functions_called": response.choices[0].get("function_call")
        }
    
    def _create_prompt(self, analysis: Dict[str, Any], question: str) -> str:
        """Create prompt for ChatGPT."""
        return f"""
## Binary Analysis Results

### Cryptographic Algorithms
{json.dumps(analysis.get('crypto', []), indent=2)}

### Detected Vulnerabilities
{json.dumps(analysis.get('vulnerabilities', []), indent=2)}

### Taint Analysis
{json.dumps(analysis.get('taint', []), indent=2)}

## Question
{question}

Please provide a detailed security analysis based on the above data.
"""


async def main():
    """Example usage."""
    analyzer = ChatGPTAnalyzer()
    
    binary = "example.elf"
    question = "What are the critical security vulnerabilities?"
    
    print(f"Analyzing: {binary}")
    print(f"Question: {question}\n")
    
    response = await analyzer.analyze_with_gpt(binary, question)
    print(f"ChatGPT: {response}")


if __name__ == "__main__":
    asyncio.run(main())
