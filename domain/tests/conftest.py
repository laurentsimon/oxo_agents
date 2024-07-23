"""Pytest fixtures for the domains agent."""

import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.runtimes import definitions as runtime_definitions

from agent import domain_agent

@pytest.fixture(name="untrusted_message")
def create_untrusted_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = "v3.asset.domain_name"
    msg_data = {"name": "www.test.com"}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="trusted_message")
def create_trusted_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = "v3.asset.domain_name"
    msg_data = {"name": "www.googleapis.com"}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="invalid_selector_message")
def create_invalid_selector_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.dns_record to be used by the agent for testing purposes.
    """
    selector = "v3.asset.domain_name.dns_record"
    msg_data = {"name": "www.test.com"}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="empty_name_message")
def create_empty_name_message() -> msg.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = "v3.asset.domain_name.dns_record"
    msg_data = {"name": ""}
    return msg.Message.from_data(selector, data=msg_data)


@pytest.fixture(name="domain_agent")
def create_domain_agent(
    agent_mock: list[msg.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> domain_agent.DomainAgent:
    """Instantiate a Domain agent."""

    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "oxo.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/dev/domain_agent",
        )
        agent = domain_agent.DomainAgent(
            definition,
            settings,
        )
        return agent