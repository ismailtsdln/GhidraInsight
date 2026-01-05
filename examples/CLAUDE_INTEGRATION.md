# Claude Integration Example

This example shows how to integrate GhidraInsight with Claude API for AI-powered binary analysis.

## Setup

### 1. Install Dependencies

```bash
pip install anthropic ghidrainsight
```

### 2. Set API Keys

```bash
export CLAUDE_API_KEY="sk-ant-..."
export GHIDRA_API_KEY="your-ghidra-api-key"
```

### 3. Run the Example

```bash
python claude_integration.py --binary /path/to/binary --question "What vulnerabilities exist?"
```

## How It Works

1. **Upload Binary**: Sends binary to GhidraInsight for analysis
2. **Get Results**: Retrieves analysis results (crypto, vulnerabilities, taint)
3. **Build Context**: Creates a detailed context for Claude
4. **Query Claude**: Sends question + context to Claude API
5. **Stream Response**: Streams Claude's response in real-time

## Example Usage

### Basic Analysis

```python
from claude_integration import BinaryAnalyzer

analyzer = BinaryAnalyzer("http://localhost:8000")
result = analyzer.analyze(
    binary_path="binary.elf",
    question="What cryptographic algorithms are used?"
)
print(result)
```

### Advanced Queries

```python
queries = [
    "Identify all potential buffer overflow vulnerabilities",
    "Which functions handle user input and where does it flow?",
    "What cryptographic weaknesses exist?",
    "Suggest hardening recommendations",
]

for query in queries:
    result = analyzer.analyze("binary.elf", query)
    print(f"Q: {query}")
    print(f"A: {result}\n")
```

### Streaming Output

```python
for chunk in analyzer.analyze_stream("binary.elf", "What are the main security issues?"):
    print(chunk, end="", flush=True)
```

## Features

- ✅ Real-time binary analysis with GhidraInsight
- ✅ Claude API integration
- ✅ Multi-turn conversation support
- ✅ JSON output for integration
- ✅ Error handling and retries
- ✅ Streaming responses

## Output Format

```json
{
  "query": "What vulnerabilities exist?",
  "analysis": {
    "crypto": [...],
    "vulnerabilities": [...],
    "taint": [...]
  },
  "response": "Based on the analysis, I found...",
  "tokens_used": {
    "input": 2048,
    "output": 512
  }
}
```

---

**Note**: Requires Claude API access. Get your API key from https://console.anthropic.com
