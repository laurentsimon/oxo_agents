"""Pytest fixtures for the oauth agent."""

import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.runtimes import definitions as runtime_definitions

from agent import oauth_agent

@pytest.fixture(name="refresh_untrusted_message")
def create_refresh_untrusted_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {
        "host": "www.untrusted.com",
        "headers": [
            {
                "name": b"User-Agent",
                "value": b"Chromium v1.2.3",
            },
            {
                "name": b"Authorization",
                "value": b"random-value",
            },
            {
                "name": b"Authorization",
                "value": b"1/blabla",
            },
            {
                "name": b"X-Name",
                "value": b"other value",
            },
        ]
    }
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="access_untrusted_message")
def create_access_untrusted_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {
        "host": "www.untrusted.com",
        "headers": [
            {
                "name": b"User-Agent",
                "value": b"Chromium v1.2.3",
            },
            {
                "name": b"Authorization",
                "value": b"random-value",
            },
            {
                "name": b"Authorization",
                "value": b"ya29.blabla",
            },
            {
                "name": b"X-Name",
                "value": b"other value",
            },
        ]
    }
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="refresh_trusted_message")
def create_refresh_trusted_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {
        "host": "www.googleapis.com",
        "headers": [
            {
                "name": b"User-Agent",
                "value": b"Chromium v1.2.3",
            },
            {
                "name": b"Authorization",
                "value": b"random-value",
            },
            {
                "name": b"Authorization",
                "value": b"1/blabla",
            },
            {
                "name": b"X-Name",
                "value": b"other value",
            },
        ]
    }
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="access_trusted_message")
def create_access_trusted_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {
        "host": "www.googleapis.com",
        "headers": [
            {
                "name": b"User-Agent",
                "value": b"Chromium v1.2.3",
            },
            {
                "name": b"Authorization",
                "value": b"random-value",
            },
            {
                "name": b"Authorization",
                "value": b"ya29.blabla",
            },
            {
                "name": b"X-Name",
                "value": b"other value",
            },
        ]
    }
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="no_token_message")
def create_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {
        "host": "www.googleapis.com",
        "headers": [
            {
                "name": b"User-Agent",
                "value": b"Chromium v1.2.3",
            },
            {
                "name": b"Authorization",
                "value": b"random-value",
            },
            {
                "name": b"X-Name",
                "value": b"other value",
            },
        ]
    }
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="invalid_selector_message")
def create_invalid_selector_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.response to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.response"
    msg_data = {"content": b"some content"}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="no_host_message")
def create_no_host_message() -> msg.Message:
    """Creates a dummy message of type v3.capture.http.request to be used by the agent for testing purposes.
    """
    selector = "v3.capture.http.request"
    msg_data = {"content": b"some content"}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="oauth_agent")
def create_domain_agent(
    agent_mock: list[msg.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> oauth_agent.OAuthAgent:
    """Instantiate a OAuth agent."""

    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "oxo.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/dev/oauth_agent",
        )
        agent = oauth_agent.OAuthAgent(
            definition,
            settings,
        )
        return agent