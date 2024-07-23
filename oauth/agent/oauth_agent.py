"""Domain agent implementation"""

import logging
from rich import logging as rich_logging
import time
import struct

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class OAuthAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """Domain agent."""
    @staticmethod
    def _VULN_TITLE(tok_type: str):
        return f"[yt-sec][oauth]: {tok_type.capitalize()} OAuth to untrusted domain"
    @staticmethod
    def _VULN_DETAIL(tok_type: str, host: str, headers: list[dict[str, str]]):
        hdrs = ""
        for h in headers:
            name = h["name"].decode()
            value = h["value"].decode()
            hdrs += f"{name}: {value}\n"
        return f"{tok_type.capitalize()} OAuth token:\nHost: {host}\nHeaders:\n{hdrs}"
    @staticmethod
    def _VULN_RISK():
        return agent_report_vulnerability_mixin.RiskRating.HIGH
    @staticmethod
    def _ALLOWED_HOSTS():
        return []
    @staticmethod
    def _ALLOWED_DOMAINS():
        return ["google.com", "googleapis.com", "youtube.com", "googleusercontent.com"]
    @staticmethod
    def _REFRESH_TYPE():
        return "refresh"
    @staticmethod
    def _ACCESS_TYPE():
        return "access"
    @staticmethod
    def _DNA(tok_type: str, host: str):
        return f"{tok_type}|{host}"


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

        logger.debug(f"processing message: {message}")
        if message.selector != "v3.capture.http.request":
            raise ValueError(f"unexpected selector: ${message.selector}")
        # https://github.com/Ostorlab/oxo/blob/main/src/ostorlab/agent/message/proto/v3/capture/http/request/request.proto
        self._process_http_request(message)
        del message

    def _allowed_domain(self, host: str) -> bool:
        for allowed in OAuthAgent._ALLOWED_DOMAINS():
            if host == allowed:
                return True
            if host.endswith(f".{allowed}"):
                return True
        return False

    def _allowed_host(self, host: str) -> bool:
        return host in OAuthAgent._ALLOWED_HOSTS()

    def _trusted_host(self, host: str) -> bool:
        return self._allowed_host(host) or self._allowed_domain(host)

    def _process_http_request(self, message: m.Message):
        if "host" not in message.data:
            raise ValueError("no host in request")
        host = message.data["host"]

        # Check the host.
        if self._trusted_host(host):
            return

        # Get the Authoriation header.
        headers = message.data.get("headers")
        for header in headers:
            name = header["name"].decode()
            value = header["value"].decode()
            if name != "Authorization":
                continue
            tok_type = OAuthAgent._REFRESH_TYPE() if "1/" in value else OAuthAgent._ACCESS_TYPE() if "ya29." in value else None
            if tok_type is None:
                continue

            # We found some tokens.
            kb_entry = kb.Entry(title=OAuthAgent._VULN_TITLE(tok_type),
                        risk_rating=OAuthAgent._VULN_RISK().name,
                        short_description='short_description',
                        description='description',
                        recommendation = 'some recommendation',
                        references = {'title': 'link to reference'},
                        security_issue = False,
                        privacy_issue = True,
                        has_public_exploit = False,
                        targeted_by_malware = False,
                        targeted_by_ransomware = False,
                        targeted_by_nation_state = False)
            self.report_vulnerability(
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=OAuthAgent._VULN_DETAIL(tok_type, host, headers),
                dna=OAuthAgent._DNA(tok_type, host),
                entry=kb_entry,
            )        
        
if __name__ == "__main__":
    logger.info("starting OAuth agent ...")
    OAuthAgent.main()