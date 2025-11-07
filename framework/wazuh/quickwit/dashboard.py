# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Dashboard integration for Quickwit.

This module provides utilities for building dashboards and visualizations
on top of Quickwit data.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .client import QuickwitClient


class QuickwitDashboard:
    """Dashboard utilities for Quickwit queries."""

    def __init__(self, client: QuickwitClient):
        """Initialize dashboard with Quickwit client.

        Args:
            client: QuickwitClient instance
        """
        self.client = client

    def get_alerts_summary(self, index: str = "wazuh-alerts",
                          time_range_hours: int = 24,
                          group_by: str = "rule.level") -> Dict[str, Any]:
        """Get summary of alerts grouped by specified field.

        Args:
            index: Index name
            time_range_hours: Time range in hours (from now)
            group_by: Field to group alerts by

        Returns:
            Aggregated alert statistics
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        # Build aggregation query
        aggregations = {
            "alert_counts": {
                "terms": {
                    "field": group_by,
                    "size": 100
                }
            }
        }

        results = self.client.search(
            index=index,
            max_hits=0,  # We only want aggregations
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            aggregations=aggregations
        )

        return {
            'total_alerts': results.get('num_hits', 0),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'grouped_by': group_by,
            'aggregations': results.get('aggregations', {})
        }

    def get_top_agents(self, index: str = "wazuh-alerts",
                      time_range_hours: int = 24,
                      limit: int = 10) -> List[Dict[str, Any]]:
        """Get top agents by alert count.

        Args:
            index: Index name
            time_range_hours: Time range in hours
            limit: Number of top agents to return

        Returns:
            List of agents with alert counts
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        aggregations = {
            "top_agents": {
                "terms": {
                    "field": "agent.id",
                    "size": limit
                }
            }
        }

        results = self.client.search(
            index=index,
            max_hits=0,
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            aggregations=aggregations
        )

        agents = []
        if 'aggregations' in results and 'top_agents' in results['aggregations']:
            for bucket in results['aggregations']['top_agents'].get('buckets', []):
                agents.append({
                    'agent_id': bucket['key'],
                    'alert_count': bucket['doc_count']
                })

        return agents

    def get_alert_timeline(self, index: str = "wazuh-alerts",
                          time_range_hours: int = 24,
                          interval: str = "1h") -> Dict[str, Any]:
        """Get alert count timeline with specified interval.

        Args:
            index: Index name
            time_range_hours: Time range in hours
            interval: Time bucket interval (e.g., "1h", "30m", "1d")

        Returns:
            Timeline data with alert counts per interval
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        aggregations = {
            "timeline": {
                "date_histogram": {
                    "field": "timestamp",
                    "interval": interval
                }
            }
        }

        results = self.client.search(
            index=index,
            max_hits=0,
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            aggregations=aggregations
        )

        return {
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'interval': interval,
            'timeline': results.get('aggregations', {}).get('timeline', {})
        }

    def get_critical_alerts(self, index: str = "wazuh-alerts",
                           time_range_hours: int = 24,
                           min_level: int = 12,
                           max_hits: int = 100) -> List[Dict[str, Any]]:
        """Get critical alerts above specified severity level.

        Args:
            index: Index name
            time_range_hours: Time range in hours
            min_level: Minimum alert level (default 12 for critical)
            max_hits: Maximum number of alerts to return

        Returns:
            List of critical alerts
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        query = f"rule.level:>={min_level}"

        results = self.client.search(
            index=index,
            query=query,
            max_hits=max_hits,
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            sort_by="-timestamp"  # Most recent first
        )

        return results.get('hits', [])

    def get_rule_statistics(self, index: str = "wazuh-alerts",
                           time_range_hours: int = 24) -> Dict[str, Any]:
        """Get statistics about triggered rules.

        Args:
            index: Index name
            time_range_hours: Time range in hours

        Returns:
            Rule statistics
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        aggregations = {
            "top_rules": {
                "terms": {
                    "field": "rule.id",
                    "size": 20
                }
            },
            "severity_distribution": {
                "terms": {
                    "field": "rule.level",
                    "size": 20
                }
            }
        }

        results = self.client.search(
            index=index,
            max_hits=0,
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            aggregations=aggregations
        )

        return {
            'total_alerts': results.get('num_hits', 0),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'top_rules': results.get('aggregations', {}).get('top_rules', {}),
            'severity_distribution': results.get('aggregations', {}).get('severity_distribution', {})
        }

    def search_events(self, index: str, query: str,
                     time_range_hours: Optional[int] = None,
                     max_hits: int = 100,
                     fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Search for events with custom query.

        Args:
            index: Index name
            query: Quickwit query string
            time_range_hours: Optional time range in hours
            max_hits: Maximum number of results
            fields: Optional list of fields to return

        Returns:
            List of matching events
        """
        kwargs = {
            'index': index,
            'query': query,
            'max_hits': max_hits,
            'sort_by': '-timestamp'
        }

        if time_range_hours:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=time_range_hours)
            kwargs['start_timestamp'] = int(start_time.timestamp())
            kwargs['end_timestamp'] = int(end_time.timestamp())

        results = self.client.search(**kwargs)
        return results.get('hits', [])

    def get_agent_statistics(self, agent_id: str,
                            index: str = "wazuh-alerts",
                            time_range_hours: int = 24) -> Dict[str, Any]:
        """Get detailed statistics for specific agent.

        Args:
            agent_id: Agent ID
            index: Index name
            time_range_hours: Time range in hours

        Returns:
            Agent statistics
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)

        query = f"agent.id:{agent_id}"

        aggregations = {
            "severity_levels": {
                "terms": {
                    "field": "rule.level",
                    "size": 20
                }
            },
            "top_rules": {
                "terms": {
                    "field": "rule.id",
                    "size": 10
                }
            }
        }

        results = self.client.search(
            index=index,
            query=query,
            max_hits=0,
            start_timestamp=int(start_time.timestamp()),
            end_timestamp=int(end_time.timestamp()),
            aggregations=aggregations
        )

        return {
            'agent_id': agent_id,
            'total_alerts': results.get('num_hits', 0),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'severity_distribution': results.get('aggregations', {}).get('severity_levels', {}),
            'top_rules': results.get('aggregations', {}).get('top_rules', {})
        }
