from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, Response
from hmac import compare_digest
import opensearchpy
import os
from typing import Annotated

from auth import JWTBearer, generate_token, decode_token
from commands_manager import commands_manager
from models import Credentials, GetCommandsResponse, EventsBody, TokenResponse
from opensearch import indexer_client, AGENTS_INDEX_NAME, METRICS_INDEX_NAME

from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry import metrics, trace
from opentelemetry.sdk.trace import Span, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader, ConsoleMetricExporter

from telemetry_exporter import custom_metrics_exporter, custom_span_exporter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

router = APIRouter(prefix="/api/v1")

resource = Resource(attributes={
    SERVICE_NAME: "agent-comms-api"
})

# Set up the meter provider and metric reader with the custom exporter
reader = PeriodicExportingMetricReader(custom_metrics_exporter, export_interval_millis=60000)
# reader = PeriodicExportingMetricReader(ConsoleMetricExporter(), export_interval_millis=60000)
provider = MeterProvider(resource=resource, metric_readers=[reader])
metrics.set_meter_provider(provider)

# Acquire a meter.
meter = metrics.get_meter("agent.comms.meter")

# Counter instrument count number of authentication requests
auth_counter = meter.create_counter(
    "agent.comms.auth",
    description="The number of auth requests made",
)
auth_counter_client_error = meter.create_counter(
    "agent.comms.auth_client_error",
    description="The number of auth client error responses",
)

# Set up the tracer provider and add the custom span exporter
# trace.set_tracer_provider(TracerProvider(resource=resource))
# tracer_provider = trace.get_tracer_provider()
# # span_processor = SimpleSpanProcessor(custom_span_exporter)
# span_processor = SimpleSpanProcessor(ConsoleSpanExporter())
# tracer_provider.add_span_processor(span_processor)
#
# # Get a tracer
# tracer = trace.get_tracer(__name__)


@router.get("/commands")
async def get_commands(token: Annotated[str, Depends(JWTBearer())]) -> GetCommandsResponse:
    try:
        uuid = decode_token(token)["uuid"]
    except Exception as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": str(exc)})

    commands = await commands_manager.get_commands(uuid)
    if commands:
        return GetCommandsResponse(commands=commands)
    else:
        raise HTTPException(status.HTTP_408_REQUEST_TIMEOUT, {"message": "No commands found"})

@router.get("/files", dependencies=[Depends(JWTBearer())])
async def get_files(file_name: str):
    path = os.path.join(BASE_DIR, "files", file_name)
    return FileResponse(path, media_type="application/octet-stream", filename=file_name)

@router.post("/events/stateless", dependencies=[Depends(JWTBearer())])
async def post_stateless_events(body: EventsBody):
    # TODO: send event to the engine
    _ = body.events
    return Response(status_code=status.HTTP_200_OK)

@router.post("/events/stateful", dependencies=[Depends(JWTBearer())])
async def post_stateful_events(body: EventsBody):
    # TODO: send event to the indexer
    _ = body.events
    return Response(status_code=status.HTTP_200_OK)

@router.post("/authentication")
async def authentication(creds: Credentials):
    try:
        data = indexer_client.get_document(index_name=AGENTS_INDEX_NAME, doc_id=creds.uuid)
    except opensearchpy.exceptions.NotFoundError:
        # Create and start a span
        # with tracer.start_as_current_span("auth_span") as span:
        #     span.set_attribute("key", "value")
        #     span.add_event("Agent Not Found in OpenSearch", {"event_name": "agent_not_found"})

        auth_counter_client_error.add(1)
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": "UUID not found"})
    except opensearchpy.exceptions.ConnectionError as exc:
        auth_counter_client_error.add(1)
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": f"Couldn't connect to the indexer: {exc}"})
    finally:
        auth_counter.add(1)

    if not compare_digest(data["_source"]["key"], creds.key):
        auth_counter_client_error.add(1)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, {"message": "Invalid Key"})

    token = generate_token(creds.uuid)
    return TokenResponse(token=token)


@router.post("/index")
async def create_index(index_name: str = METRICS_INDEX_NAME):
    try:
        indexer_client.create_index(index_name)
    except opensearchpy.exceptions.ConnectionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {"message": f"Couldn't connect to the indexer: {exc}"})

    return Response(status_code=status.HTTP_200_OK)
