"""Unittests for oauth agent."""

import pathlib
import re
from typing import Any

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import oauth_agent


def _helperValidate(m:msg.Message, oauth_agent: oauth_agent.OAuthAgent, tok_type: oauth_agent.OAuthAgent.TokenType, host:str, loc:oauth_agent.OAuthAgent.LocationType, headers:list[dict[str, str]], content:str):
    assert m.selector == "v3.report.vulnerability"
    assert m.data["risk_rating"] == oauth_agent._VULN_RISK().name
    assert m.data["title"] == oauth_agent._VULN_TITLE(tok_type)
    assert m.data["dna"] == oauth_agent._DNA(tok_type, host, loc)
    assert m.data["technical_detail"] == oauth_agent._VULN_DETAIL(tok_type, host, headers, content)

def testOAuthAgent_whenRefreshTokenInHeadersToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        refresh_untrusted_message: msg.Message,
) -> None:
    oauth_agent.process(refresh_untrusted_message)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.REFRESH
    host = msg.data["host"]
    headers = msg.data['headers']
    loc = oauth_agent.LocationType.CONTENT

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, headers, None)


def testOAuthAgent_whenRefreshTokenInContentToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        refresh_untrusted_content_message: msg.Message,
) -> None:
    msg = refresh_untrusted_content_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.REFRESH
    host = msg.data["host"]
    content = msg.data['content'].decode()
    loc = oauth_agent.LocationType.CONTENT

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, None, content)

def testOAuthAgent_whenRefreshTokenInHeadersToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        refresh_untrusted_message: msg.Message,
) -> None:
    msg = refresh_untrusted_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.REFRESH
    host = msg.data["host"]
    headers = msg.data['headers']
    loc = oauth_agent.LocationType.CONTENT

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, headers, None)

def testOAuthAgent_whenAccessTokenInHeadersToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_untrusted_message: msg.Message,
) -> None:
    msg = access_untrusted_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.ACCESS
    host = msg.data["host"]
    headers = msg.data['headers']
    loc = oauth_agent.LocationType.HEADER

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, headers, None)

def testOAuthAgent_whenAccessTokenInContentToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_untrusted_content_message: msg.Message,
) -> None:
    msg = access_untrusted_content_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.ACCESS
    host = msg.data["host"]
    content = msg.data['content'].decode()
    loc = oauth_agent.LocationType.CONTENT

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, None, content)

def testOAuthAgent_whenAccessTokenInContentAsHostToTrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_trusted_content_as_host_message: msg.Message,
) -> None:
    msg = access_trusted_content_as_host_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 0

def testOAuthAgent_whenAccessTokenInContentAsHostToTrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_trusted_content_message: msg.Message,
) -> None:
    msg = access_trusted_content_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 0

def testOAuthAgent_whenRefreshTokenInHeadersToUntrusted_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_untrusted_message: msg.Message,
) -> None:
    msg = access_untrusted_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 1

    tok_type = oauth_agent.TokenType.ACCESS
    host = msg.data["host"]
    headers = msg.data['headers']
    loc = oauth_agent.LocationType.HEADER

    _helperValidate(agent_mock[0], oauth_agent, tok_type, host, loc, headers, None)

def testOAuthAgent_whenAccessTokenInHeadersAsHostToTrusted_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_trusted_as_host_message: msg.Message,
) -> None:
    msg = access_trusted_as_host_message
    oauth_agent.process(msg)

    assert len(agent_mock) == 0

def testOAuthAgent_whenAccessTokenInHeadersToTrusted_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        oauth_agent: oauth_agent.OAuthAgent,
        access_trusted_message: msg.Message,
) -> None:
    oauth_agent.process(access_trusted_message)

    assert len(agent_mock) == 0

def testOAuthAgent_whenRefreshTokenInHeadersToTrusted_noEmits(
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
