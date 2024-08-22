"""Unittests for bind agent."""

import pathlib
import re
from typing import Any

import pytest
from ostorlab.agent.message import message as msg
from pytest_mock import plugin

from agent import bind_agent

def _helperValidate(m:msg.Message, bind_agent: bind_agent.BindAgent, frames: list[dict[str, str | int | list[dict [str, str | bytes]]]]):
    assert m.selector == "v3.report.vulnerability"
    assert m.data["risk_rating"] == bind_agent._VULN_RISK().name
    assert m.data["title"] == bind_agent._VULN_TITLE()
    assert m.data["technical_detail"] == bind_agent._VULN_DETAIL(frames)

def testBindAgent_whenNoBindFrameMessage_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        bind_agent: bind_agent.BindAgent,
        no_bind_message: msg.Message,
) -> None:
    msg = no_bind_message
    bind_agent.process(msg)

    assert len(agent_mock) == 0

def testBindAgent_whenBindNativeMiddleframeFrameMessage_noEmits(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        bind_agent: bind_agent.BindAgent,
        native_bind_middle_message: msg.Message,
) -> None:
    msg = native_bind_middle_message
    bind_agent.process(msg)

    assert len(agent_mock) == 0

def testBindAgent_whenBindNativeInstrumentedframeFrameMessage_emitsVulnerabilityReport(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        bind_agent: bind_agent.BindAgent,
        java_native_bind_instrumented_message: msg.Message,
) -> None:
    msg = java_native_bind_instrumented_message
    bind_agent.process(msg)

    assert len(agent_mock) == 1
    _helperValidate(agent_mock[0], bind_agent, msg.data['frames'])

def testBindAgent_whenInvalidInMessageSelector_raisesValueError(
        mocker: plugin.MockerFixture,
        agent_mock: list[msg.Message],
        bind_agent: bind_agent.BindAgent,
        invalid_selector_message: msg.Message,
) -> None:

    try:
        bind_agent.process(invalid_selector_message)
    except ValueError:
        return
    
    pytest.fail("Unexpected exception (ValueError)")