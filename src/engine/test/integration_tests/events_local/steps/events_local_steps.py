import os

import httpx
from behave import when, then

ENV_DIR = os.environ.get("ENV_DIR", "")
EVENTS_SOCKET = ENV_DIR + "/queue/sockets/queue-http.sock"


def post_local_event(body: str):
    transport = httpx.HTTPTransport(uds=EVENTS_SOCKET)
    with httpx.Client(transport=transport) as client:
        response = client.post(
            "http://localhost/events/local",
            content=body,
            headers={"Content-Type": "application/x-wev1"},
        )
    return response.status_code, response.text


@when("I send a local event with header and one event")
def step_send_single(context):
    body = (
        "H {\"agent\":{\"id\":\"001\",\"name\":\"tomas2\"}}\n"
        "E w:wazuh-remoted:{\"event\":{\"collector\":\"manager\",\"action\":\"agent-added\"}}"
    )
    status, resp_body = post_local_event(body)
    context.shared_data["status"] = status
    context.shared_data["body"] = resp_body


@when("I send a local event with header and two events")
def step_send_multiple(context):
    body = (
        "H {\"agent\":{\"id\":\"001\",\"name\":\"tomas2\"}}\n"
        "E w:wazuh-remoted:{\"event\":{\"collector\":\"manager\",\"action\":\"agent-added\"}}\n"
        "E w:wazuh-monitord:{\"event\":{\"collector\":\"manager\",\"action\":\"manager-started\"}}"
    )
    status, resp_body = post_local_event(body)
    context.shared_data["status"] = status
    context.shared_data["body"] = resp_body


@when("I send a local event with invalid body")
def step_send_invalid(context):
    body = "H {invalid\nE w:wazuh-remoted:{\"event\":{\"collector\":\"manager\"}}"
    status, resp_body = post_local_event(body)
    context.shared_data["status"] = status
    context.shared_data["body"] = resp_body


@when("I send a local event without header line")
def step_send_no_header(context):
    body = "E w:wazuh-remoted:{\"event\":{\"collector\":\"manager\"}}"
    status, resp_body = post_local_event(body)
    context.shared_data["status"] = status
    context.shared_data["body"] = resp_body


@when("I send a local event with empty body")
def step_send_empty(context):
    status, resp_body = post_local_event("")
    context.shared_data["status"] = status
    context.shared_data["body"] = resp_body


@then("the response status should be {expected_status:d}")
def step_check_status(context, expected_status):
    assert context.shared_data["status"] == expected_status, (
        f"Expected {expected_status}, got {context.shared_data['status']}. "
        f"Body: {context.shared_data['body']}"
    )
