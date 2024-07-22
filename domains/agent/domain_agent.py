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


class DomainAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """Domain agent."""
    @staticmethod
    def _VULN_TITLE(name: str):
        return f"yt-sec: Domain {name}"
    @staticmethod
    def _VULN_DETAIL(name: str):
        return f"We detected a DNS resolution request to {name}"
    @staticmethod
    def _VULN_RISK():
        return "INFO"

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
        if message.selector != "v3.asset.domain_name":
            raise ValueError(f"unexpected selector: ${message.selector}")
        # https://github.com/Ostorlab/oxo/blob/3f184897523525a5053341fa42155e6e259b17b6/src/ostorlab/agent/message/proto/v3/asset/domain_name/domain_name.proto
        self._process_domain_name(message.data["name"])
        del message

    def _process_domain_name(self, domain_name: str):
        logger.info(f"DNS domain: {domain_name}")
        if domain_name == "":
            raise ValueError("empty domain name")
        kb_entry = kb.Entry(title=DomainAgent._VULN_TITLE(domain_name),
                    risk_rating=DomainAgent._VULN_RISK(),
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
            risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO,
            technical_detail=DomainAgent._VULN_DETAIL(domain_name),
            entry=kb_entry,
        )        
        
if __name__ == "__main__":
    logger.info("starting Domain agent ...")
    DomainAgent.main()