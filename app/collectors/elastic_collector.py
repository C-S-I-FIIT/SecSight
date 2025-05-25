import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from loguru import logger
from app.clients.vault_client import VaultClient


class ElasticCollector:
    def __init__(self):
        vault = VaultClient()
        secret = vault.get_secret('elk/elastic')
        
        self.es_url = secret.get('host', 'localhost')
        self.es_port = secret.get('port', 9200)
        self.es_user = secret.get('user', None)
        self.es_pass = secret.get('pass', None)
        
        self.verify_certs = False
        
        if not self.es_user or not self.es_pass:
            _error_msg = "[ElasticCollector] Elasticsearch credentials not found in vault"
            logger.error(_error_msg)
            raise ValueError(_error_msg)

        self.es = Elasticsearch(
            hosts=[f"{self.es_url}:{self.es_port}"],
            basic_auth=(self.es_user, self.es_pass),
            verify_certs=self.verify_certs,
            ssl_show_warn=False
        )
        
        if not self.es.ping():
            _error_msg = "[ElasticCollector] Could not connect to Elasticsearch"
            logger.error(_error_msg)
            raise ConnectionError(_error_msg)
        
        #logger.success("[ElasticCollector] Successfully connected to Elasticsearch")
    
    def _calculate_time_range(self, days_back=30, start_date=None, end_date=None, from_date=None):
        """Calculate time range for Elasticsearch query."""
        now = datetime.now()
        
        if start_date and end_date:
            # Parse dates if they're strings
            if isinstance(start_date, str):
                start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            if isinstance(end_date, str):
                end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            
            time_range = {
                "gte": start_date.isoformat(),
                "lte": end_date.isoformat()
            }
        elif from_date:
            time_range = {
                "gte": from_date.isoformat(),  
                "lte": now.isoformat()
            }
        else:
            # Default time range
            time_range = {
                "gte": (now - timedelta(days=days_back)).isoformat(),
                "lte": now.isoformat()
            }
        
        return time_range
    
    def search_logs(self, index, query=None, filters=None, aggregations=None, 
                   days_back=30, start_date=None, end_date=None, size=100, 
                   time_field="@timestamp", scroll="5m"):
        """
        Search logs in specified Elasticsearch index with filters and aggregations.
        
        Args:
            index (str): Elasticsearch index to search
            query (dict, optional): Elasticsearch query DSL query part
            filters (dict, optional): Dictionary of field filters
            aggregations (dict, optional): Elasticsearch aggregations
            days_back (int, optional): Days to look back if no date range
            start_date (str/datetime, optional): Start date for search
            end_date (str/datetime, optional): End date for search
            size (int, optional): Max number of results per scroll
            time_field (str, optional): Name of the timestamp field
            scroll (str, optional): Scroll timeout
            
        Returns:
            dict: Search results including hits and aggregations
        """
        # Build base query
        search_body = {
            "size": size,
            "query": {
                "bool": {
                    "must": query if query else {"match_all": {}},
                    "filter": [
                        {
                            "range": {
                                time_field: self._calculate_time_range(days_back, start_date, end_date)
                            }
                        }
                    ]
                }
            }
        }
        
        # Add filters
        if filters:
            for field, value in filters.items():
                if isinstance(value, list):
                    search_body["query"]["bool"]["filter"].append({"terms": {field: value}})
                else:
                    search_body["query"]["bool"]["filter"].append({"term": {field: value}})
        
        # Add aggregations
        if aggregations:
            search_body["aggs"] = aggregations
        
        try:
            # Initialize the search
            #logger.debug(f"[ElasticCollector] Searching index {index} with query: {search_body}")
            
            # Don't use scroll for aggregation-only queries (size=0)
            if size == 0:
                search_response = self.es.search(
                    index=index,
                    body=search_body
                )
                
                result = {
                    'hits': [],
                    'total': search_response['hits']['total']['value'] 
                             if isinstance(search_response['hits']['total'], dict) 
                             else search_response['hits']['total'],
                    'aggregations': search_response.get('aggregations', {})
                }
                
                #logger.info(f"[ElasticCollector] Found {result['total']} logs in index {index}")
                
                return result, None
            else:
                # Use scroll for queries that return documents
                search_response = self.es.search(
                    index=index,
                    body=search_body,
                    scroll=scroll
                )
                
                # Process scroll results
                scroll_id = search_response['_scroll_id']
                scroll_size = len(search_response['hits']['hits'])
                
                result = {
                    'hits': search_response['hits']['hits'],
                    'total': search_response['hits']['total']['value'] 
                             if isinstance(search_response['hits']['total'], dict) 
                             else search_response['hits']['total'],
                    'aggregations': search_response.get('aggregations', {})
                }
                
                #logger.info(f"[ElasticCollector] Found {result['total']} logs in index {index}")
                
                return result, scroll_id
            
        except Exception as e:
            logger.exception(f"[ElasticCollector] Error searching logs: {str(e)}")
            return {'hits': [], 'total': 0, 'aggregations': {}}, None
    
    def scroll_logs(self, scroll_id, scroll="5m"):
        """
        Continue scrolling for more results with given scroll_id.
        
        Args:
            scroll_id (str): Elasticsearch scroll ID
            scroll (str, optional): Scroll timeout
            
        Returns:
            dict: Next page of results
        """
        try:
            scroll_response = self.es.scroll(
                scroll_id=scroll_id,
                scroll=scroll
            )
            
            result = {
                'hits': scroll_response['hits']['hits'],
                'scroll_id': scroll_response.get('_scroll_id')
            }
            
            return result
            
        except Exception as e:
            logger.exception(f"[ElasticCollector] Error scrolling logs: {str(e)}")
            return {'hits': [], 'scroll_id': None}
    
    def clear_scroll(self, scroll_id):
        """Clear an active scroll."""
        try:
            self.es.clear_scroll(scroll_id=scroll_id)
            return True
        except Exception as e:
            logger.error(f"[ElasticCollector] Error clearing scroll: {str(e)}")
            return False
    
    def get_logs_by_host(self, index, hostname=None, ip=None, days_back=30, 
                        start_date=None, end_date=None, size=100):
        """
        Get logs filtered by hostname or IP address.
        
        Args:
            index (str): Elasticsearch index to search
            hostname (str, optional): Host name to filter by
            ip (str, optional): IP address to filter by
            days_back (int, optional): Days to look back
            start_date (str/datetime, optional): Start date
            end_date (str/datetime, optional): End date
            size (int, optional): Max results per page
            
        Returns:
            dict: Search results
        """
        filters = {}
        
        if hostname:
            filters["host.name"] = hostname
        
        if ip:
            filters["host.ip"] = ip
            
        return self.search_logs(
            index=index,
            filters=filters,
            days_back=days_back,
            start_date=start_date,
            end_date=end_date,
            size=size
        )
    
    def get_log_statistics(self, index, field, days_back=30, start_date=None, end_date=None):
        """
        Get statistics/aggregations for a specific field.
        
        Args:
            index (str): Elasticsearch index to search
            field (str): Field to get statistics for
            days_back (int, optional): Days to look back
            start_date (str/datetime, optional): Start date
            end_date (str/datetime, optional): End date
            
        Returns:
            dict: Aggregation results
        """
        aggregations = {
            "stats": {
                "terms": {
                    "field": field,
                    "size": 50
                }
            }
        }
        
        result, _ = self.search_logs(
            index=index,
            aggregations=aggregations,
            days_back=days_back,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        return result.get('aggregations', {})
    
    def get_log_timeline(self, index, interval="day", days_back=30, start_date=None, end_date=None):
        """
        Get logs grouped by time intervals for timeline visualization.
        
        Args:
            index (str): Elasticsearch index to search
            interval (str, optional): Time interval (minute, hour, day, week, month)
            days_back (int, optional): Days to look back
            start_date (str/datetime, optional): Start date
            end_date (str/datetime, optional): End date
            
        Returns:
            dict: Timeline data
        """
        aggregations = {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": interval
                }
            }
        }
        
        result, _ = self.search_logs(
            index=index,
            aggregations=aggregations,
            days_back=days_back,
            start_date=start_date,
            end_date=end_date,
            size=0  # We only need aggregations
        )
        
        return result.get('aggregations', {})
