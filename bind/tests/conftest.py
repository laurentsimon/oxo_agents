"""Pytest fixtures for the bind agent."""

import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.runtimes import definitions as runtime_definitions

from agent import bind_agent

def create_base_frames():
    frameN = {
        "package_name": "pkgN",
        "class_name": "clsN",
        "function_name": "funcN",
        "args": [
            {
                "name": "arg0",
                "value": b"val0"
            },
            {
                "name": "arg1",
                "value": b"val1"
            }
        ]
    }
    frame0 = {
        "package_name": "pkg0",
        "class_name": "cls0",
        "function_name": "func0"
        }
    return list([frame0] + [frameN])

def create_native_bind_frame():
    return {
        "package_name": "some.package",
        "class_name": "",
        "function_name": "bind"
        }

def create_bind_middle(frame_create_fn):
    selector = "v3.capture.stack_trace"
    frames = create_base_frames()
    frames = frames[:1] + [frame_create_fn()] + frames[1:]
    msg_data = {"frames": frames}
    return msg.Message.from_data(selector, data=msg_data)

def create_bind_instrumented(frame_create_fn):
    selector = "v3.capture.stack_trace"
    frames = create_base_frames()
    frames = [frame_create_fn()] + frames
    msg_data = {"frames": frames}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="no_bind_message")
def create_no_bind_message() -> msg.Message:
    selector = "v3.capture.stack_trace"
    frames = create_base_frames()
    msg_data = {"frames": frames}
    return msg.Message.from_data(selector, data=msg_data)

@pytest.fixture(name="native_bind_middle_message")
def create_native_bind_middle_message() -> msg.Message:
    return create_bind_middle(create_native_bind_frame)
    selector = "v3.capture.stack_trace"

@pytest.fixture(name="java_native_bind_instrumented_message")
def create_native_bind_instrumented_message() -> msg.Message:
    return create_bind_instrumented(create_native_bind_frame)

@pytest.fixture(name="bind_agent")
def create_bind_agent(
    agent_mock: list[msg.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> bind_agent.BindAgent:
    """Instantiate a Bind agent."""

    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "oxo.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/dev/bind_agent",
        )
        agent = bind_agent.BindAgent(
            definition,
            settings,
        )
        return agent