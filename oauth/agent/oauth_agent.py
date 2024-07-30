"""Domain agent implementation"""

import logging
import enum
from rich import logging as rich_logging
import time
import struct
import urllib.parse

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
    """OAuth agent."""
    class TokenType(enum.Enum):
        NONE = enum.auto()
        ACCESS = enum.auto()
        REFRESH = enum.auto()
    class LocationType(enum.Enum):
        NONE = enum.auto()
        CONTENT = enum.auto()
        HEADER = enum.auto()
    @staticmethod
    def _VULN_TITLE(tok_type:TokenType):
        return f"[yt-sec][oauth]: {tok_type.name} OAuth to untrusted domain"
    @staticmethod
    def _VULN_DETAIL(tok_type:TokenType, host:str, headers:list[dict[str, str]] = None, content:str = None):
        not_recorded = "--not recorded--"
        hdrs = None
        if headers is not None:
            hdrs = ""
            for h in headers:
                name = h["name"].decode()
                value = h["value"].decode()
                hdrs += f"{name}: {value}\n"
        return f"{tok_type.name} OAuth token:\nHost: {host}\nHeaders:\n{hdrs if hdrs is not None else not_recorded}\nontent:{content if content is not None else not_recorded}"
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
    def _DNA(tok_type:TokenType, host:str, location:LocationType):
        return f"{tok_type.name}|{host}|{location.name}"
    @staticmethod
    def _DECODE_CONTENT(method_:str, _content:str) -> str:
        decoded_content = _content
        m = method_.upper()
        match m:
            case "GET" | "HEAD":
                # NOTE: Convert to a string to help debuggging.
                decoded_content = str(urllib.parse.parse_qs(_content))
            case _:
                pass
        return decoded_content

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

    def _oauth_type(self, value:str) -> TokenType:
        return OAuthAgent.TokenType.REFRESH if "1/" in value else OAuthAgent.TokenType.ACCESS if "ya29." in value else OAuthAgent.TokenType.NONE

    def _create_vuln(self, tok_type:TokenType, host:str, headers:list[dict[str, str]] = None, content:str = None):
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
            technical_detail=OAuthAgent._VULN_DETAIL(tok_type, host, headers, content),
            dna=OAuthAgent._DNA(tok_type, host, OAuthAgent.LocationType.HEADER if content is None else OAuthAgent.LocationType.CONTENT),
            entry=kb_entry,
        )

    def _process_headers(self, host:str, headers_:list[dict[str, str]]):
        for header in headers_:
            name = header["name"].decode()
            value = header["value"].decode()
            if name != "Authorization":
                continue
            tok_type = self._oauth_type(value)
            if tok_type == OAuthAgent.TokenType.NONE:
                continue
            self._create_vuln(tok_type, host, headers=headers_)

    def _process_content(self, host:str, method_:str, content_:str):
        dcontent = OAuthAgent._DECODE_CONTENT(method_, content_)
        tok_type = self._oauth_type(dcontent)
        if tok_type == OAuthAgent.TokenType.NONE:
            return
        self._create_vuln(tok_type, host, content=dcontent)

    def _process_http_request(self, message: m.Message):
        if "host" not in message.data:
            raise ValueError("no host in request")
        host = message.data.get("host")

        # Check the host.
        if self._trusted_host(host):
            return
        self._process_headers(host, message.data.get("headers"))
        self._process_content(host, message.data.get("method"), message.data.get("content").decode())
        
        
if __name__ == "__main__":
    logger.info("starting OAuth agent ...")
    OAuthAgent.main()