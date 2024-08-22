"""Unittests for domain agent."""

import pathlib
import re
from typing import Any

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import domain_agent

def _helperValidate(m:msg.Message, domain_agent: domain_agent.DomainAgent, host:str):
    assert m.selector == "v3.report.vulnerability"
    assert m.data["risk_rating"] == domain_agent._VULN_RISK().name
    assert m.data["title"] == domain_agent._VULN_TITLE()
    assert m.data["dna"] == domain_agent._DNA(host)
    assert m.data["technical_detail"] == domain_agent._VULN_DETAIL(host)

def testDomainAgent_whenUntrustedHostMessage_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        untrusted_host_message: msg.Message,
) -> None:
    domain_agent.process(untrusted_host_message)
    assert len(agent_mock) == 1
    host = untrusted_host_message.data.get("name")
    _helperValidate(agent_mock[0], domain_agent, host)

def testDomainAgent_whenUntrustedDomainMessage_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        untrusted_domain_message: msg.Message,
) -> None:
    domain_agent.process(untrusted_domain_message)
    assert len(agent_mock) == 1
    host = untrusted_domain_message.data.get("name")
    _helperValidate(agent_mock[0], domain_agent, host)

def testDomainAgent_whenTrustedDomainMessage_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        trusted_domain_message: msg.Message,
) -> None:
    domain_agent.process(trusted_domain_message)
    assert len(agent_mock) == 0

def testDomainAgent_whenTrustedDomainAsHostMessage_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        domain_agent: domain_agent.DomainAgent,
        trusted_domain_as_host_message: msg.Message,
) -> None:
    domain_agent.process(trusted_domain_as_host_message)
    assert len(agent_mock) == 0

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
    
    pytest.fail("Unexpected exception (ValueError)")

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
    
    pytest.fail("Unexpected exception (ValueError)")

