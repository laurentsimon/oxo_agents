"""Sample agent implementation"""

import logging
from rich import logging as rich_logging
import struct
import time

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class PongAgent(
    agent.Agent, 
):
    """Pong agent."""

    # NOTE: We must follow Agent's __init__() declaration.
    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        super().__init__(agent_definition, agent_settings)
        logger.setLevel(self.args.get("log_level"))

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info(f"running start:\narg1: {self.args.get("arg1")}\narg2: {self.args.get("arg2")}")

    def process(self, message: m.Message) -> None:
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        # NOTE: message is defined in https://github.com/Ostorlab/oxo/blob/3f184897523525a5053341fa42155e6e259b17b6/src/ostorlab/agent/message/message.py#L33

        logger.debug(f"processing message: {message}")
        match message.selector:
            case s if s.startswith("v3.asset.ip."):
                # Asset message defined in https://github.com/Ostorlab/oxo/blob/main/src/ostorlab/agent/message/proto/v3/asset/ip.
                logger.info(f"ip asset: {message.data}")
                return
            case "v3.asset.file":
                # See example to read file https://github.com/Ostorlab/agent_virus_total/blob/f0c06214375a467cb2fd6537aa3928f6b8ef62a0/agent/file.py.
                # Asset message defined in https://github.com/Ostorlab/oxo/blob/main/src/ostorlab/agent/message/proto/v3/asset/file/file.proto
                logger.info(f"file asset: {message.data}")
                return
            case "v3.control":
                # Ignore our own messages.
                if message.data["message"].startswith(b"pong:"):
                    return
                pass
            case _:
                raise ValueError(f"unsupported selector: {message.selector}")

        # Process ping messages.
        ctr_bytes = message.data["message"][len("ping:"):]
        counter = struct.unpack(">i", ctr_bytes)[0]
        del message
        time.sleep(1)
        logger.info(f"pong {counter}")
        # NOTE: We must use an existing message type from
        # https://github.com/Ostorlab/oxo/blob/3f184897523525a5053341fa42155e6e259b17b6/src/ostorlab/agent/message/proto/v3
        self.emit("v3.control", {"message": b"pong:" + ctr_bytes})


if __name__ == "__main__":
    logger.info("starting pong agent ...")
    PongAgent.main()