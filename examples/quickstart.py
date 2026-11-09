import os
from wide_sdk import Agent, GeminiProvider, OllamaProvider

provider_type = os.environ.get("WIDE_PROVIDER", "ollama")

if provider_type == "gemini":
    api_key = os.environ.get("GEMINI_API_KEY", "your-api-key")
    provider = GeminiProvider(api_key=api_key)
else:
    provider = OllamaProvider(model="deepseek-r1:7b")

agent = Agent(
    provider=provider,
    working_directory=".",
    on_thought=lambda t: print(f"[Agent Thought]: {t[:100]}..."),
    on_tool_call=lambda tc: print(f"[Tool Call]: {tc.name}({tc.arguments})")
)

response = agent.run("List the files in this directory and check for any security vulnerabilities.")
print("\nFinal Response:\n", response)
