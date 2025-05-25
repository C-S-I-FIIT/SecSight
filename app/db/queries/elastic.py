import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from app.collectors.elastic_collector import ElasticCollector
from loguru import logger

class ElasticQueries:
    """Static methods for querying Elasticsearch for chart data"""
    
    @staticmethod
    def get_logs_per_host(index: str, start_date: Optional[datetime] = None, 
                         end_date: Optional[datetime] = None, top_n: int = 10, 
                         reverse: bool = False) -> pd.DataFrame:
        """
        Get top N hosts with most/least logs in the given time range
        
        Args:
            index: Elasticsearch index to search
            start_date: Start date for search
            end_date: End date for search
            top_n: Number of hosts to return
            reverse: If True, returns hosts with least logs instead
            
        Returns:
            DataFrame with host and log count data
        """
        collector = ElasticCollector()
        
        aggregations = {
            "hosts": {
                "terms": {
                    "field": "host.name",
                    "size": 1000  # Get a large number to ensure we have enough for filtering
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('hosts', {}).get('buckets', [])
        
        if not buckets:
            logger.warning(f"No host data found in index {index}")
            return pd.DataFrame(columns=['host', 'log_count'])
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"host": bucket['key'], "log_count": bucket['doc_count']}
            for bucket in buckets
        ])
        
        # Sort by log count (ascending if reverse=True, descending otherwise)
        df = df.sort_values('log_count', ascending=reverse).head(top_n).reset_index(drop=True)
        
        return df
    
    @staticmethod
    def get_logs_by_provider(index: str, start_date: Optional[datetime] = None, 
                           end_date: Optional[datetime] = None) -> pd.DataFrame:
        """
        Get count of logs by event provider
        
        Args:
            index: Elasticsearch index to search
            start_date: Start date for search
            end_date: End date for search
            
        Returns:
            DataFrame with provider and log count data
        """
        collector = ElasticCollector()
        
        aggregations = {
            "providers": {
                "terms": {
                    "field": "event.provider",
                    "size": 50  # Get top 50 providers
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('providers', {}).get('buckets', [])
        
        if not buckets:
            logger.warning(f"No provider data found in index {index}")
            return pd.DataFrame(columns=['provider', 'log_count'])
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"provider": bucket['key'], "log_count": bucket['doc_count']}
            for bucket in buckets
        ])
        
        # Sort by log count descending
        df = df.sort_values('log_count', ascending=False).reset_index(drop=True)
        
        return df
    
    @staticmethod
    def get_logs_by_device_role(index: str, hosts_metadata: List[Dict], 
                               start_date: Optional[datetime] = None, 
                               end_date: Optional[datetime] = None) -> pd.DataFrame:
        """
        Get count of logs by device role from database host metadata
        
        Args:
            index: Elasticsearch index to search
            hosts_metadata: List of host metadata from database
            start_date: Start date for search
            end_date: End date for search
            
        Returns:
            DataFrame with device role and log count data
        """
        collector = ElasticCollector()
        
        # Debug log the hosts metadata
        logger.debug(f"Processing {len(hosts_metadata)} hosts with roles")
        
        # First get log counts by host
        aggregations = {
            "hosts": {
                "terms": {
                    "field": "host.name",
                    "size": 1000  # Get a large number
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('hosts', {}).get('buckets', [])
        
        logger.debug(f"Found {len(buckets)} host buckets from Elasticsearch")
        
        if not buckets:
            logger.warning(f"No host data found in index {index}")
            return pd.DataFrame(columns=['role', 'log_count'])
        
        # Create mapping of hostname to device role
        host_role_map = {}
        for host in hosts_metadata:
            if 'hostname' in host and 'role' in host and host['role']:
                host_role_map[host['hostname']] = host['role']
        
        logger.debug(f"Created role mapping for {len(host_role_map)} hosts")
        
        # Group logs by role
        role_counts = {}
        matched_hosts = 0
        
        for bucket in buckets:
            hostname = bucket['key']
            count = bucket['doc_count']
            
            # Try to match with different hostname formats
            role = None
            # Try exact match
            if hostname in host_role_map:
                role = host_role_map[hostname]
            # Try lowercase
            elif hostname.lower() in {k.lower(): v for k, v in host_role_map.items()}:
                role = host_role_map[next(k for k in host_role_map if k.lower() == hostname.lower())]
            # Try without domain
            elif '.' in hostname and hostname.split('.')[0] in host_role_map:
                role = host_role_map[hostname.split('.')[0]]
            else:
                role = 'Unknown'
            
            if role != 'Unknown':
                matched_hosts += 1
            
            if role in role_counts:
                role_counts[role] += count
            else:
                role_counts[role] = count
        
        logger.debug(f"Matched {matched_hosts} hosts with roles out of {len(buckets)} total hosts")
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"role": role, "log_count": count}
            for role, count in role_counts.items()
        ])
        
        # Sort by log count descending
        if not df.empty:
            df = df.sort_values('log_count', ascending=False).reset_index(drop=True)
            logger.info(f"Created role dataframe with {len(df)} roles")
        else:
            logger.warning("No role data found after processing")
        
        return df
    
    @staticmethod
    def get_logs_by_device_tags(index: str, hosts_metadata: List[Dict], 
                              start_date: Optional[datetime] = None, 
                              end_date: Optional[datetime] = None) -> pd.DataFrame:
        """
        Get count of logs by device tags from database host metadata
        
        Args:
            index: Elasticsearch index to search
            hosts_metadata: List of host metadata from database
            start_date: Start date for search
            end_date: End date for search
            
        Returns:
            DataFrame with tag and log count data
        """
        collector = ElasticCollector()
        
        # Debug log the hosts metadata
        logger.debug(f"Processing {len(hosts_metadata)} hosts with tags")
        hosts_with_tags = sum(1 for host in hosts_metadata if host.get('tags'))
        logger.debug(f"Found {hosts_with_tags} hosts with tags defined")
        
        # First get log counts by host
        aggregations = {
            "hosts": {
                "terms": {
                    "field": "host.name",
                    "size": 1000  # Get a large number
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('hosts', {}).get('buckets', [])
        
        logger.debug(f"Found {len(buckets)} host buckets from Elasticsearch")
        
        if not buckets:
            logger.warning(f"No host data found in index {index}")
            return pd.DataFrame(columns=['tag', 'log_count'])
        
        # Create mapping of hostname to device tags
        host_tags_map = {}
        for host in hosts_metadata:
            if 'hostname' in host and host.get('tags'):
                host_tags_map[host['hostname']] = host['tags']
                # Also add lowercase version for case-insensitive matching
                host_tags_map[host['hostname'].lower()] = host['tags']
                # Add hostname without domain
                if '.' in host['hostname']:
                    host_tags_map[host['hostname'].split('.')[0]] = host['tags']
        
        logger.debug(f"Created tags mapping for {len(host_tags_map)} hosts")
        
        # Group logs by tag
        tag_counts = {}
        matched_hosts = 0
        
        for bucket in buckets:
            hostname = bucket['key']
            count = bucket['doc_count']
            
            # Try to match with different hostname formats
            tags = None
            # Try exact match
            if hostname in host_tags_map:
                tags = host_tags_map[hostname]
            # Try lowercase
            elif hostname.lower() in host_tags_map:
                tags = host_tags_map[hostname.lower()]
            # Try without domain
            elif '.' in hostname and hostname.split('.')[0] in host_tags_map:
                tags = host_tags_map[hostname.split('.')[0]]
            else:
                tags = []
            
            if tags:
                matched_hosts += 1
                for tag in tags:
                    tag_name = tag.get('name', 'Unknown')
                    if tag_name in tag_counts:
                        tag_counts[tag_name] += count
                    else:
                        tag_counts[tag_name] = count
        
        logger.debug(f"Matched {matched_hosts} hosts with tags out of {len(buckets)} total hosts")
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"tag": tag, "log_count": count}
            for tag, count in tag_counts.items()
        ])
        
        # Sort by log count descending
        if not df.empty:
            df = df.sort_values('log_count', ascending=False).reset_index(drop=True)
            logger.info(f"Created tag dataframe with {len(df)} tags")
        else:
            logger.warning("No tag data found after processing")
        
        return df
    
    @staticmethod
    def get_logs_timeline(index: str, start_date: Optional[datetime] = None, 
                        end_date: Optional[datetime] = None, interval: str = "day") -> pd.DataFrame:
        """
        Get log count over time
        
        Args:
            index: Elasticsearch index to search
            start_date: Start date for search
            end_date: End date for search
            interval: Time interval (hour, day, week, month)
            
        Returns:
            DataFrame with timestamp and log count data
        """
        collector = ElasticCollector()
        
        aggregations = {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": interval
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('timeline', {}).get('buckets', [])
        
        if not buckets:
            logger.warning(f"No timeline data found in index {index}")
            return pd.DataFrame(columns=['timestamp', 'log_count'])
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"timestamp": bucket['key_as_string'], "log_count": bucket['doc_count']}
            for bucket in buckets
        ])
        
        # Convert string timestamp to datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df
    
    @staticmethod
    def get_logs_by_severity(index: str, start_date: Optional[datetime] = None, 
                           end_date: Optional[datetime] = None) -> pd.DataFrame:
        """
        Get count of logs by severity/level
        
        Args:
            index: Elasticsearch index to search
            start_date: Start date for search
            end_date: End date for search
            
        Returns:
            DataFrame with severity and log count data
        """
        collector = ElasticCollector()
        
        aggregations = {
            "levels": {
                "terms": {
                    "field": "log.level",
                    "size": 20
                }
            }
        }
        
        result, _ = collector.search_logs(
            index=index,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        buckets = result.get('aggregations', {}).get('levels', {}).get('buckets', [])
        
        if not buckets:
            logger.warning(f"No severity data found in index {index}")
            return pd.DataFrame(columns=['severity', 'log_count'])
        
        # Convert to DataFrame
        df = pd.DataFrame([
            {"severity": bucket['key'], "log_count": bucket['doc_count']}
            for bucket in buckets
        ])
        
        # Sort by log count descending
        df = df.sort_values('log_count', ascending=False).reset_index(drop=True)
        
        return df
    
    @staticmethod
    def perform_query_with_scroll(index: str, query: Dict, filters: Optional[Dict] = None, 
                                aggregations: Optional[Dict] = None, 
                                start_date: Optional[datetime] = None, 
                                end_date: Optional[datetime] = None,
                                size: int = 100) -> Dict:
        """
        Universal function to perform Elasticsearch queries with scrolling
        
        Args:
            index: Elasticsearch index to search
            query: Elasticsearch query DSL
            filters: Additional filters to apply
            aggregations: Elasticsearch aggregations
            start_date: Start date for search
            end_date: End date for search
            size: Number of results per page
            
        Returns:
            Dictionary with search results
        """
        collector = ElasticCollector()
        
        # Initial search
        result, scroll_id = collector.search_logs(
            index=index,
            query=query,
            filters=filters,
            aggregations=aggregations,
            start_date=start_date,
            end_date=end_date,
            size=size
        )
        
        all_hits = result['hits']
        
        # Continue scrolling until we get all results
        while scroll_id and len(result['hits']) > 0:
            scroll_result = collector.scroll_logs(scroll_id)
            
            if not scroll_result.get('hits'):
                break
                
            all_hits.extend(scroll_result['hits'])
            scroll_id = scroll_result.get('scroll_id')
            
            # Safety check to prevent infinite loops
            if len(all_hits) >= 10000:  # Limit to 10K results
                logger.warning("Reached maximum result limit (10000), stopping scroll")
                break
                
        # Clean up
        if scroll_id:
            collector.clear_scroll(scroll_id)
            
        # Replace hits with full collection
        result['hits'] = all_hits
        
        return result
