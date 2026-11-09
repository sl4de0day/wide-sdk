from abc import ABC, abstractmethod
from typing import List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall

class BaseProvider(ABC):
    name: str

    @abstractmethod
    def chat(
        self,
        messages: List[ChatMessage],
        tools: List[ToolDefinition]
    ) -> Tuple[str, Optional[List[ToolCall]]]:
        pass
