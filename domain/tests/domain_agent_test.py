"""Unittests for domain agent."""

import pathlib
import re
from typing import Any

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import domain_agent

def testDomainAgent_whenValidInMessage_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        message: msg.Message,
) -> None:
    domain_agent.process(message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == domain_agent._VULN_RISK().name
    assert agent_mock[0].data["title"] == domain_agent._VULN_TITLE(message.data.get("name"))
    assert agent_mock[0].data["technical_detail"] == domain_agent._VULN_DETAIL(message.data.get("name"))

def testDomainAgent_whenInvalidInMessageSelector_raisesValueError(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        invalid_selector_message: msg.Message,
) -> None:

    try:
        domain_agent.process(invalid_selector_message)
    except ValueError:
        return
    
    pytest.fail("Unexpected lack of exception (ValueError)")

def testDomainAgent_whenEmptyNameMessageSelector_raisesValueError(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        empty_name_message: msg.Message,
) -> None:

    try:
        domain_agent.process(empty_name_message)
    except ValueError:
        return
    
    pytest.fail("Unexpected lack of exception (ValueError)")

