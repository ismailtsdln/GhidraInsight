# ChatGPT Integration Example

This example integrates GhidraInsight with ChatGPT for advanced binary analysis queries.

## Setup

```bash
pip install openai ghidrainsight
export OPENAI_API_KEY="sk-..."
```

## Usage

### Simple Query

```python
from openai_integration import BinaryAnalyzer

analyzer = BinaryAnalyzer()
result = analyzer.query_gpt(
    "example.elf",
    "Find all buffer overflow vulnerabilities"
)
print(result)
```

### Function Tool (GPT Function Calling)

```python
response = analyzer.ask_gpt_with_tools(
    "Find all crypto in example.elf",
    tools=[
        {
            "name": "analyze_binary",
            "description": "Analyze a binary file",
            "parameters": {"type": "object", ...}
        }
    ]
)
```

### Multi-turn Conversation

```python
queries = [
    "Analyze binary.elf",
    "What cryptographic methods are used?",
    "Are there any weaknesses?"
]

for q in queries:
    response = analyzer.query_gpt("binary.elf", q)
    print(response)
```

## Features

- Real-time binary analysis streaming
- Function calling with GhidraInsight API
- JSON output
- Error handling and retries
- Rate limit handling

---

See [claude_integration.py](./claude_integration.py) for detailed examples.
