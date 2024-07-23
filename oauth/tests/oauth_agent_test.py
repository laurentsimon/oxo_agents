"""Unittests for oauth agent."""

import pathlib
import re
from typing import Any

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import oauth_agent

def testOAuthAgent_whenRefreshTokenInHeadersToUntrustedHost_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        refresh_untrusted_message: msg.Message,
) -> None:
    oauth_agent.process(refresh_untrusted_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == oauth_agent._VULN_RISK()
    assert agent_mock[0].data["title"] == oauth_agent._VULN_TITLE(oauth_agent._REFRESH_TYPE(), refresh_untrusted_message.data['host'])
    assert agent_mock[0].data["technical_detail"] == oauth_agent._VULN_DETAIL(oauth_agent._REFRESH_TYPE(), refresh_untrusted_message.data['host'])

def testOAuthAgent_whenAccessTokenInHeadersToUntrustedHost_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_untrusted_message: msg.Message,
) -> None:
    oauth_agent.process(access_untrusted_message)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == oauth_agent._VULN_RISK()
    assert agent_mock[0].data["title"] == oauth_agent._VULN_TITLE(oauth_agent._ACCESS_TYPE(), access_untrusted_message.data['host'])
    assert agent_mock[0].data["technical_detail"] == oauth_agent._VULN_DETAIL(oauth_agent._ACCESS_TYPE(), access_untrusted_message.data['host'])

def testOAuthAgent_whenAccessTokenInHeadersToTrustedHost_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_trusted_message: msg.Message,
) -> None:
    oauth_agent.process(access_trusted_message)

    assert len(agent_mock) == 0

def testOAuthAgent_whenRefreshTokenInHeadersToTrustedHost_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        refresh_trusted_message: msg.Message,
) -> None:
    oauth_agent.process(refresh_trusted_message)

    assert len(agent_mock) == 0

def testOAuthAgent_whenInvalidInMessageSelector_raisesValueError(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        invalid_selector_message: msg.Message,
) -> None:

    try:
        oauth_agent.process(invalid_selector_message)
    except ValueError:
        return
    
    pytest.fail("Unexpected lack of exception (ValueError)")

def testOAuthAgent_whenInvalidInMessageSelector_raisesValueError(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        no_host_message: msg.Message,
) -> None:

    try:
        oauth_agent.process(no_host_message)
    except ValueError:
        return
    
    pytest.fail("Unexpected lack of exception (ValueError)")
