"""Bind agent implementation"""

import logging
from rich import logging as rich_logging
import time
import struct

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb

from . import java_class

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class BindAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """Bind agent."""
    @staticmethod
    def _VULN_TITLE():
        return f"[yt-sec][bind]: Listening socket"
    @staticmethod
    def _VULN_DETAIL(frames: list[dict[str, str | int | list[dict [str, str | bytes]]]]):
        frame0 = frames[0]
        pkcls = f"{frame0['package_name']}.{frame0['class_name']}.{frame0['function_name']}"
        return f"We detected a socket bind() call from {pkcls}\nStack trace: {frames}"
    @staticmethod
    def _VULN_RISK():
        return agent_report_vulnerability_mixin.RiskRating.HIGH
    @staticmethod
    def _ALLOWED_CLASSES() -> java_class.JavaClass:
        # TODO: Populate the class after a successful run.
        return []

    # NOTE: We must follow Agent's __init__() declaration.
    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        super().__init__(agent_definition, agent_settings)

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info(f"running start")

    def process(self, message: m.Message) -> None:
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        # NOTE: message is defined in https://github.com/Ostorlab/oxo/blob/3f184897523525a5053341fa42155e6e259b17b6/src/ostorlab/agent/message/message.py#L33
        # NOTE: stack trace framees are declared in https://github.com/Ostorlab/oxo/blob/main/src/ostorlab/agent/message/proto/v3/capture/stack_trace/stack_trace.proto
        logger.debug(f"processing message: {message}")
        if message.selector != "v3.capture.stack_trace":
            raise ValueError(f"unexpected selector: ${message.selector}")
        frames = message.data.get("frames", []) 
        self._process_frames(frames)
        del message

    def _is_class_allowed(self, _package_name:str, _class_name:str) -> bool:
        pkcls = java_class.JavaClass(package_name=_package_name, class_name=_class_name)
        return pkcls in BindAgent._ALLOWED_CLASSES()

    def _is_frames_safe(self, frames: list[dict[str, str | int | list[dict [str, str | bytes]]]]) -> bool:
        # Frame 0 is the instrumentation function, frame 1, the parent frame, etc.
        # So we remove the bind() call at position 0.
        for frame in frames[1:]:
            if self._is_class_allowed(frame["package_name"], frame["class_name"]):
                return True
        return False

    def _is_empty_field(self, s:str | None) -> bool:
        return s is None or s == ""

    def _is_frame_bind_call(self, frame: dict[str, str | int | list[dict [str, str | bytes]]]) -> bool:
        # For native calls, class name is null/none, protobuf 2 will however default to empty string.
        # The arg type will contain the object type like Java class, like `java.io.String`, primitive type `int`, Dart class, etc.
        # The name value will in most cases match argument name as stated in the documentation.
        # The platform scraps API and SDK documentation to construct a corpus of interesting and dangerous functions,
        # and arguments are mapped from their memory reference/order to their documentation name.
        # There are exceptions to this when that information is missing or in the case of variadic functions.
        # Since the platform only hooks interesting functions that are known beforehand, it never instruments obfuscated methods directly.
        # SDK methods are never obfuscated as they don't get shipped with the application.
        # Library functions once obfuscated will get missed and won't be instrumented.
        # In Java, we can call java.net.Socket.bind() and java.net.ServerSocket.bind(),
        # which javax.net.ssl.SSLServerSocket inherits. All these end up calling native bind(),
        # so we do not look for them.
        return frame['function_name'] == "bind" and self._is_empty_field(frame['class_name'])


    # See example at https://oxo.ostorlab.co/docs/sample_agents/stack_traces_sample.
    def _process_frames(self, frames: list[dict[str, str | int | list[dict [str, str | bytes]]]]):
        if frames is None or len(frames) == 0:
            raise ValueError(f"received empty frames")
        if not self._is_frame_bind_call(frames[0]):
            return
        if self._is_frames_safe(frames):
            return                       
        kb_entry = kb.Entry(title=BindAgent._VULN_TITLE(),
                            risk_rating=BindAgent._VULN_RISK().name,
                            short_description='short_description',
                            description='description',
                            recommendation = 'some recommendation',
                            references = {'title': 'link to reference'},
                            security_issue = True,
                            privacy_issue = False,
                            has_public_exploit = False,
                            targeted_by_malware = False,
                            targeted_by_ransomware = False,
                            targeted_by_nation_state = False)
        self.report_vulnerability(
            risk_rating=BindAgent._VULN_RISK(),
            technical_detail=BindAgent._VULN_DETAIL(frames),
            entry=kb_entry,
        )

if __name__ == "__main__":
    logger.info("starting Bind agent ...")
    BindAgent.main()