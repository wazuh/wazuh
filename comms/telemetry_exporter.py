from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from opensearch import indexer_client, METRICS_INDEX_NAME, TRACES_INDEX_NAME
import json


class OpenSearchMetricExporter(MetricExporter):
    def __init__(self, opensearch_client, index_name, **kwargs):
        self.opensearch_client = opensearch_client
        self.index_name = index_name
        super().__init__(**kwargs)

    def export(self, metrics_data, timeout_millis):
        # Process and store the metrics data
        try:
            data = json.loads(metrics_data.to_json())['resource_metrics'][0]['scope_metrics']
            self.opensearch_client.send_metrics(data, self.index_name)
            return MetricExportResult.SUCCESS
        except Exception as e: #TODO: Enhance exception handling
            raise e

    def shutdown(self, timeout_millis):
        super().shutdown(timeout_millis)

    def force_flush(self, timeout_millis):
        pass


class OpenSearchSpanExporter(SpanExporter):
    def __init__(self, opensearch_client, index_name, **kwargs):
        self.opensearch_client = opensearch_client
        self.index_name = index_name
        super().__init__(**kwargs)

    def export(self, spans):
        # Process the spans
        trace = []
        try:
            for span in spans:
                trace.append(json.loads(span.to_json()))
            self.opensearch_client.send_trace(trace, self.index_name)
            return SpanExportResult.SUCCESS
        except Exception as e: #TODO: Enhance exception handling
            raise e


custom_metrics_exporter = OpenSearchMetricExporter(indexer_client, METRICS_INDEX_NAME)

custom_span_exporter = OpenSearchSpanExporter(indexer_client, TRACES_INDEX_NAME)
