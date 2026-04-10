from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentMessage:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    from_agent: str = ""
    to_agent: str = ""
    msg_type: str = "INFORM"  # INFORM, BLOCK, REQUEST, ESCALATE, RESOLVE
    priority: str = "normal"  # low, normal, high, critical
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "from": self.from_agent,
            "to": self.to_agent,
            "type": self.msg_type,
            "priority": self.priority,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }


class MessageBus:
    """Central message bus for inter-agent communication."""

    def __init__(self):
        self.messages: List[AgentMessage] = []
        self.agents: Dict[str, Agent] = {}
        self.blocks: List[AgentMessage] = []

    def register(self, agent: Agent):
        self.agents[agent.name] = agent
        agent.bus = self

    def send(self, message: AgentMessage):
        self.messages.append(message)
        if message.msg_type == "BLOCK":
            self.blocks.append(message)
        if message.to_agent in self.agents:
            self.agents[message.to_agent].receive_message(message)

    def get_log(self) -> List[dict]:
        return [m.to_dict() for m in self.messages]

    def get_blocks(self) -> List[dict]:
        return [m.to_dict() for m in self.blocks]

    def has_unresolved_blocks(self) -> bool:
        block_ids = {m.payload.get("blocking_cve") for m in self.blocks}
        resolved_ids = {
            m.payload.get("resolved_cve")
            for m in self.messages
            if m.msg_type == "RESOLVE"
        }
        return bool(block_ids - resolved_ids)


class Agent:
    """Base agent class. All specialist agents inherit from this."""

    name: str = "base_agent"
    description: str = "Base agent"

    def __init__(self, name: Optional[str] = None):
        if name:
            self.name = name
        self.bus: Optional[MessageBus] = None
        self.log: List[str] = []

    def process(self, input_data: dict) -> dict:
        """Override in subclass. Process input and return output."""
        raise NotImplementedError

    def send_message(self, to: str, msg_type: str, payload: dict, priority: str = "normal"):
        msg = AgentMessage(
            from_agent=self.name,
            to_agent=to,
            msg_type=msg_type,
            priority=priority,
            payload=payload,
        )
        self._log(f"[{msg_type}] -> {to}: {payload.get('reason', payload.get('summary', ''))[:100]}")
        if self.bus:
            self.bus.send(msg)
        return msg

    def receive_message(self, message: AgentMessage):
        self._log(f"[{message.msg_type}] <- {message.from_agent}: {message.payload.get('reason', '')[:100]}")

    def _log(self, text: str):
        self.log.append(f"[{self.name}] {text}")
