"""Cribl Stream API service for data pipeline management."""

import logging
import requests
from typing import Optional, List, Dict, Any
import json
from datetime import datetime
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class CriblService:
    """Service for interacting with Cribl Stream API."""
    
    def __init__(self, server_url: str, username: str, password: str, 
                 verify_ssl: bool = False):
        """
        Initialize Cribl Stream service.
        
        Args:
            server_url: Cribl Stream server URL (e.g., "https://cribl.example.com:9000")
            username: Username for authentication
            password: Password for authentication
            verify_ssl: Whether to verify SSL certificates (default: False)
        """
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.auth_token: Optional[str] = None
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def authenticate(self) -> bool:
        """
        Authenticate with Cribl Stream server and get auth token.
        
        Returns:
            True if authentication successful, False otherwise.
        """
        try:
            auth_url = f"{self.server_url}/api/v1/auth/login"
            data = {
                'username': self.username,
                'password': self.password
            }
            
            response = self.session.post(auth_url, json=data)
            
            if response.status_code == 200:
                result = response.json()
                self.auth_token = result.get('token')
                if self.auth_token:
                    self.session.headers.update({
                        'Authorization': f'Bearer {self.auth_token}'
                    })
                    logger.info(f"Successfully authenticated to Cribl Stream as {self.username}")
                    return True
                else:
                    logger.error("No auth token returned from Cribl Stream")
                    return False
            else:
                logger.error(f"Authentication failed: HTTP {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return False
    
    def test_connection(self) -> tuple[bool, str]:
        """
        Test connection to Cribl Stream server.
        
        Returns:
            Tuple of (success, message)
        """
        try:
            if not self.authenticate():
                return False, "Authentication failed"
            
            # Try to get system info
            response = self.session.get(f"{self.server_url}/api/v1/system/info")
            
            if response.status_code == 200:
                info = response.json()
                version = info.get('version', 'unknown')
                return True, f"Connected to Cribl Stream v{version}"
            else:
                return False, f"Connection failed: HTTP {response.status_code}"
        
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
    
    def get_pipelines(self, worker_group: str = "default") -> Optional[List[Dict]]:
        """
        Get list of configured pipelines.
        
        Args:
            worker_group: Worker group to query (default: "default")
        
        Returns:
            List of pipeline configurations or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(
                f"{self.server_url}/api/v1/m/{worker_group}/pipelines"
            )
            
            if response.status_code == 200:
                data = response.json()
                pipelines = data.get('items', [])
                logger.info(f"Retrieved {len(pipelines)} pipelines")
                return pipelines
            else:
                logger.error(f"Failed to get pipelines: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting pipelines: {e}")
            return None
    
    def get_routes(self, worker_group: str = "default") -> Optional[List[Dict]]:
        """
        Get list of configured routes.
        
        Args:
            worker_group: Worker group to query (default: "default")
        
        Returns:
            List of route configurations or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(
                f"{self.server_url}/api/v1/m/{worker_group}/routes"
            )
            
            if response.status_code == 200:
                data = response.json()
                routes = data.get('routes', [])
                logger.info(f"Retrieved {len(routes)} routes")
                return routes
            else:
                logger.error(f"Failed to get routes: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting routes: {e}")
            return None
    
    def get_sources(self, worker_group: str = "default") -> Optional[List[Dict]]:
        """
        Get list of configured data sources.
        
        Args:
            worker_group: Worker group to query (default: "default")
        
        Returns:
            List of source configurations or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(
                f"{self.server_url}/api/v1/m/{worker_group}/inputs"
            )
            
            if response.status_code == 200:
                data = response.json()
                sources = data.get('items', [])
                logger.info(f"Retrieved {len(sources)} data sources")
                return sources
            else:
                logger.error(f"Failed to get sources: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting sources: {e}")
            return None
    
    def get_destinations(self, worker_group: str = "default") -> Optional[List[Dict]]:
        """
        Get list of configured data destinations.
        
        Args:
            worker_group: Worker group to query (default: "default")
        
        Returns:
            List of destination configurations or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(
                f"{self.server_url}/api/v1/m/{worker_group}/outputs"
            )
            
            if response.status_code == 200:
                data = response.json()
                destinations = data.get('items', [])
                logger.info(f"Retrieved {len(destinations)} destinations")
                return destinations
            else:
                logger.error(f"Failed to get destinations: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting destinations: {e}")
            return None
    
    def get_metrics(self, worker_group: str = "default", 
                   time_range: str = "1h") -> Optional[Dict]:
        """
        Get system metrics for data throughput and performance.
        
        Args:
            worker_group: Worker group to query (default: "default")
            time_range: Time range for metrics (e.g., "1h", "24h")
        
        Returns:
            Dictionary of metrics or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(
                f"{self.server_url}/api/v1/m/{worker_group}/metrics",
                params={'range': time_range}
            )
            
            if response.status_code == 200:
                metrics = response.json()
                logger.info(f"Retrieved metrics for time range: {time_range}")
                return metrics
            else:
                logger.error(f"Failed to get metrics: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return None
    
    def create_pipeline(self, pipeline_id: str, config: Dict, 
                       worker_group: str = "default") -> Optional[Dict]:
        """
        Create a new pipeline configuration.
        
        Args:
            pipeline_id: ID for the new pipeline
            config: Pipeline configuration dictionary
            worker_group: Worker group (default: "default")
        
        Returns:
            Created pipeline config or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.post(
                f"{self.server_url}/api/v1/m/{worker_group}/pipelines/{pipeline_id}",
                json=config
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"Created pipeline: {pipeline_id}")
                return result
            else:
                logger.error(f"Failed to create pipeline: {response.status_code} - {response.text}")
                return None
        
        except Exception as e:
            logger.error(f"Error creating pipeline: {e}")
            return None
    
    def apply_route(self, source_filter: str, pipeline: str, destination: str,
                   worker_group: str = "default") -> Optional[Dict]:
        """
        Create or update a route to direct data flow.
        
        Args:
            source_filter: Filter expression for source data
            pipeline: Pipeline ID to apply
            destination: Destination ID for output
            worker_group: Worker group (default: "default")
        
        Returns:
            Route configuration or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            route_config = {
                'filter': source_filter,
                'pipeline': pipeline,
                'output': destination,
                'description': f'Route from {source_filter} via {pipeline} to {destination}'
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/m/{worker_group}/routes",
                json=route_config
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                logger.info(f"Created route for {source_filter}")
                return result
            else:
                logger.error(f"Failed to create route: {response.status_code} - {response.text}")
                return None
        
        except Exception as e:
            logger.error(f"Error creating route: {e}")
            return None
    
    def get_health_status(self) -> Optional[Dict]:
        """
        Get health status of Cribl Stream system.
        
        Returns:
            Health status dictionary or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            response = self.session.get(f"{self.server_url}/api/v1/health")
            
            if response.status_code == 200:
                health = response.json()
                return health
            else:
                logger.error(f"Failed to get health status: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return None
    
    def preview_pipeline(self, pipeline_id: str, sample_data: List[Dict],
                        worker_group: str = "default") -> Optional[Dict]:
        """
        Preview how a pipeline would transform sample data.
        
        Args:
            pipeline_id: Pipeline to test
            sample_data: Sample events to transform
            worker_group: Worker group (default: "default")
        
        Returns:
            Preview results showing transformed data or None
        """
        try:
            if not self.auth_token:
                if not self.authenticate():
                    return None
            
            payload = {
                'pipelineId': pipeline_id,
                'sampleData': sample_data
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/m/{worker_group}/pipelines/preview",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Preview completed for pipeline: {pipeline_id}")
                return result
            else:
                logger.error(f"Failed to preview pipeline: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"Error previewing pipeline: {e}")
            return None

