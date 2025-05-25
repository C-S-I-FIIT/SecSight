import json
import requests
from datetime import datetime, timedelta
from thehive4py.api import TheHiveApi
from thehive4py.query import Eq, And, Between
from loguru import logger
from app.clients.vault_client import VaultClient
from app.db.database import Database
from app.db.models import (
    TheHiveCase,
    TheHiveAlert,
    TheHiveArtifact,
    alert_artifact_map,
)


class TheHiveCollector:
    def __init__(self):
        """
        Initialize TheHiveCollector with credentials from vault.
        """
        vault = VaultClient()
        secret = vault.get_secret("thehive")

        if not secret:
            _error_msg = "[TheHiveCollector] TheHive credentials not found in vault"
            logger.error(_error_msg)
            raise ValueError(_error_msg)

        self.api_url = secret.get("url")
        self.api_key = secret.get("token")
        self.cert = secret.get("cert", False)
        self.version = secret.get("version", 4)

        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        if not self.api_url or not self.api_key:
            _error_msg = "[TheHiveCollector] Missing API URL or API key"
            logger.error(_error_msg)
            raise ValueError(_error_msg)

        try:
            self.api = TheHiveApi(
                self.api_url, self.api_key, version=self.version, cert=self.cert
            )
            logger.success("[TheHiveCollector] Successfully connected to TheHive")
            self.db = Database()
        except Exception as e:
            _error_msg = f"[TheHiveCollector] Failed to connect to TheHive: {str(e)}"
            logger.error(_error_msg)
            raise ConnectionError(_error_msg)

    def _map_tlp(self, tlp_value):
        """Map TLP numeric value to string representation"""
        tlp_map = {0: "TLP:WHITE", 1: "TLP:GREEN", 2: "TLP:AMBER", 3: "TLP:RED"}
        return tlp_map.get(tlp_value, f"TLP:{tlp_value}")

    def _map_pap(self, pap_value):
        """Map PAP numeric value to string representation"""
        pap_map = {0: "PAP:WHITE", 1: "PAP:GREEN", 2: "PAP:AMBER", 3: "PAP:RED"}
        return pap_map.get(pap_value, f"PAP:{pap_value}")

    def _map_severity(self, severity_value):
        """Map severity numeric value to string representation"""
        severity_map = {1: "SEV:LOW", 2: "SEV:MEDIUM", 3: "SEV:HIGH", 4: "SEV:CRITICAL"}
        return severity_map.get(severity_value, f"SEV:{severity_value}")

    def _get_time_range(self, days_back=30, start_date=None, end_date=None):
        """
        Calculate time range for TheHive queries.

        Args:
            days_back (int): Number of days to look back (default: 30)
            start_date (datetime): Start date (overrides days_back)
            end_date (datetime): End date (defaults to now)

        Returns:
            tuple: (start_timestamp, end_timestamp) in milliseconds
        """
        now = datetime.now()

        if start_date is None:
            start_date = now - timedelta(days=days_back)

        if end_date is None:
            end_date = now

        # Convert to milliseconds for TheHive API
        start_timestamp = int(start_date.timestamp() * 1000)
        end_timestamp = int(end_date.timestamp() * 1000)

        return start_timestamp, end_timestamp

    def get_alerts(
        self, days_back=30, start_date=None, end_date=None, range_field="createdAt"
    ):
        """
        Get alerts from TheHive within a time range.

        Args:
            days_back (int): Number of days to look back (default: 30)
            start_date (datetime): Start date (overrides days_back)
            end_date (datetime): End date (defaults to now)
            range_field (str): Field to use for time range filtering

        Returns:
            list: List of TheHive alerts
        """
        start_timestamp, end_timestamp = self._get_time_range(
            days_back, start_date, end_date
        )

        # Build query
        query = And(Between(range_field, start_timestamp, end_timestamp))

        try:
            logger.info(f"[TheHiveCollector] Querying alerts from {start_timestamp} to {end_timestamp} ...")
            response = self.api.find_alerts(query=query)

            if response.status_code == 200:
                alerts = response.json()
                logger.info(f"[TheHiveCollector] Found {len(alerts)} alerts")
                return alerts
            else:
                logger.error(
                    f"[TheHiveCollector] Failed to get alerts: {response.text}"
                )
                return []
        except Exception as e:
            logger.exception(f"[TheHiveCollector] Error getting alerts: {str(e)}")
            return []

    def get_cases(
        self, days_back=30, start_date=None, end_date=None, range_field="createdAt"
    ):
        """
        Get cases from TheHive within a time range.

        Args:
            days_back (int): Number of days to look back (default: 30)
            start_date (datetime): Start date (overrides days_back)
            end_date (datetime): End date (defaults to now)
            range_field (str): Field to use for time range filtering

        Returns:
            list: List of TheHive cases
        """
        start_timestamp, end_timestamp = self._get_time_range(
            days_back, start_date, end_date
        )

        # Build query
        query = And(Between(range_field, start_timestamp, end_timestamp))

        try:
            logger.info(f"[TheHiveCollector] Querying cases from {start_timestamp} to {end_timestamp} ...")
            response = self.api.find_cases(query=query)

            if response.status_code == 200:
                cases = response.json()
                logger.info(f"[TheHiveCollector] Found {len(cases)} cases")
                return cases
            else:
                logger.error(f"[TheHiveCollector] Failed to get cases: {response.text}")
                return []
        except Exception as e:
            logger.exception(f"[TheHiveCollector] Error getting cases: {str(e)}")
            return []

    def get_alert_artifacts(self, alert_id: str):
        """
        Get artifacts for a specific alert.

        Args:
            alert_id (str): TheHive alert ID

        Returns:
            list: List of artifacts for the alert
        """
        try:
            # Make a direct API call instead of relying on theHive4py methods
            # This is more robust as API paths rarely change even if method names do

            url = f"{self.api_url}/api/v1/query?name=alert-observables"
            body = {
                "query": [
                    {"_name": "getAlert", "idOrName": alert_id},
                    {"_name": "observables"},
                    {"_name": "sort", "_fields": [{"startDate": "desc"}]},
                    {"_name": "page", "from": 0, "to": 200},
                ]
            }

            response = requests.post(url, headers=self.headers, verify=self.cert, json=body)

            if response.status_code == 200:
                artifacts = response.json()
                logger.info(
                    f"[TheHiveCollector] Found {len(artifacts)} artifacts for alert {alert_id}"
                )
                return artifacts
            else:
                logger.error(
                    f"[TheHiveCollector] Failed to get artifacts for alert {alert_id}: {response.text}"
                )
                return []
        except Exception as e:
            logger.exception(
                f"[TheHiveCollector] Error getting artifacts for alert {alert_id}: {str(e)}"
            )
            return []

    def sync_alert_to_db(self, alert_data):
        """
        Sync alert data to the database.

        Args:
            alert_data (dict): Alert data from TheHive API

        Returns:
            TheHiveAlert: Database alert object
        """
        with self.db.session() as session:
            case_id = None
            case_hive_id = alert_data.get("case", None)
            if case_hive_id:
                case = session.query(TheHiveCase).filter(TheHiveCase.hive_id == case_hive_id).first()
                if case:
                    case_id = case.id
                else:
                    logger.warning(f"[TheHiveCollector] Case {case_hive_id} not found in database")
            
            
            
            
            # Check if alert already exists
            existing_alert = (
                session.query(TheHiveAlert)
                .filter(TheHiveAlert.hive_id == alert_data.get("id"))
                .first()
            )

            if existing_alert:
                logger.debug(
                    f"[TheHiveCollector] Alert {alert_data.get('id')} already exists, updating"
                )
                # Update existing alert
                existing_alert.title = alert_data.get("title", existing_alert.title)
                existing_alert.description = alert_data.get(
                    "description", existing_alert.description
                )
                existing_alert.tlp = self._map_tlp(alert_data.get("tlp", 2))
                existing_alert.pap = self._map_pap(alert_data.get("pap", 2))
                existing_alert.severity = self._map_severity(
                    alert_data.get("severity", 2)
                )
                
                # Properly handle date conversion
                if alert_data.get("date"):
                    existing_alert.date = datetime.fromtimestamp(alert_data.get("date") / 1000)
                
                existing_alert.tags = json.dumps(alert_data.get("tags", []))
                existing_alert.type = alert_data.get("type", existing_alert.type)
                existing_alert.source = alert_data.get("source", existing_alert.source)
                existing_alert.source_ref = alert_data.get(
                    "sourceRef", existing_alert.source_ref
                )
                existing_alert.status = alert_data.get("status", existing_alert.status)
                existing_alert.case_id = case_id
                
                session.flush()

                # Process artifacts - first remove existing artifacts
                # Get existing artifacts for this alert
                existing_artifact_relations = (
                    session.query(alert_artifact_map)
                    .filter(alert_artifact_map.c.alert_id == existing_alert.id)
                    .all()
                )

                # Collect artifact IDs that will be removed from this alert
                artifact_ids = [relation.artifact_id for relation in existing_artifact_relations]
                
                # First delete all relationships from the junction table for this alert only
                session.query(alert_artifact_map).filter(
                    alert_artifact_map.c.alert_id == existing_alert.id
                ).delete(synchronize_session=False)
                
                session.flush()
                
                # Now check which artifacts aren't referenced by any other alerts
                if artifact_ids:
                    for artifact_id in artifact_ids:
                        # Check if the artifact is still referenced by any other alert
                        references = session.query(alert_artifact_map).filter(
                            alert_artifact_map.c.artifact_id == artifact_id
                        ).count()
                        
                        # If no references exist, delete the artifact
                        if references == 0:
                            session.query(TheHiveArtifact).filter(
                                TheHiveArtifact.id == artifact_id
                            ).delete(synchronize_session=False)
                
                session.flush()

                # Add new artifacts
                logger.info(f"[TheHiveCollector] Processing artifacts for alert {existing_alert.hive_id} ...")
                artifacts = alert_data.get("artifacts", [])
                #artifacts = self.get_alert_artifacts(alert_data.get("id"))
                if len(artifacts) > 0:
                    logger.info(f"[TheHiveCollector] Found {len(artifacts)} artifacts for alert {existing_alert.hive_id}")
                    for artifact_data in artifacts:
                        self.sync_artifact_to_db(artifact_data, existing_alert.id, session)
                else:
                    logger.info(f"[TheHiveCollector] No artifacts found for alert {existing_alert.hive_id}")

                logger.info(
                    f"[TheHiveCollector] Updated alert {existing_alert.hive_id} in database"
                )
                return existing_alert

            
            
            alert = TheHiveAlert(
                hive_id=alert_data.get("id"),
                title=alert_data.get("title"),
                description=alert_data.get("description"),
                tlp=self._map_tlp(alert_data.get("tlp", 2)),
                pap=self._map_pap(alert_data.get("pap", 2)),
                severity=self._map_severity(alert_data.get("severity", 2)),
                date=(
                    datetime.fromtimestamp(alert_data.get("date", 0) / 1000)
                    if alert_data.get("date")
                    else None
                ),
                tags=json.dumps(alert_data.get("tags", [])),
                type=alert_data.get("type"),
                source=alert_data.get("source"),
                source_ref=alert_data.get("sourceRef"),
                status=alert_data.get("status"),
                case_id=case_id
            )

            session.add(alert)
            session.flush()  # Flush to get the ID

            # Process artifacts
            #artifacts = self.get_alert_artifacts(alert_data.get("id"))
            artifacts = alert_data.get("artifacts", [])
            logger.info(f"[TheHiveCollector] Found {len(artifacts)} artifacts for alert {alert.hive_id}")
            logger.info(f"[TheHiveCollector] Processing artifacts for alert {alert.hive_id} ...")
            if len(artifacts) > 0:
                for artifact_data in artifacts:
                    self.sync_artifact_to_db(artifact_data, alert.id, session)
            else:
                logger.info(f"[TheHiveCollector] No artifacts found for alert {alert.hive_id}")

            logger.info(f"[TheHiveCollector] Added alert {alert.hive_id} to database")
            return alert

    def sync_artifact_to_db(self, artifact_data, alert_id, session=None):
        """
        Sync artifact data to the database.

        Args:
            artifact_data (dict): Artifact data from TheHive API
            alert_id (int): Database alert ID
            session (Session, optional): Database session to use

        Returns:
            TheHiveArtifact: Database artifact object
        """
        if session:
            
            db_artifact = session.query(TheHiveArtifact).filter(
                TheHiveArtifact.data_type == artifact_data.get("dataType"),
                TheHiveArtifact.message == artifact_data.get("message"),
                TheHiveArtifact.data == artifact_data.get("data")
            ).first()
            
            if db_artifact:
                artifact = db_artifact
            else:
                # Create artifact
                artifact = TheHiveArtifact(
                    data_type=artifact_data.get("dataType"),
                    message=artifact_data.get("message"),
                    data=artifact_data.get("data"),
                )
                session.add(artifact)
                session.flush()  # Flush to get the ID

            # Associate with alert
            stmt = alert_artifact_map.insert().values(
                alert_id=alert_id, artifact_id=artifact.id
            )
            session.execute(stmt)

            # logger.debug(f"[TheHiveCollector] Added artifact {artifact.id} to database")
            return artifact
        else:
            with self.db.session() as session:
                return self.sync_artifact_to_db(artifact_data, alert_id, session)

    def sync_case_to_db(self, case_data):
        """
        Sync case data to the database.

        Args:
            case_data (dict): Case data from TheHive API

        Returns:
            TheHiveCase: Database case object
        """
        with self.db.session() as session:
            # Check if case already exists
            existing_case = (
                session.query(TheHiveCase)
                .filter(TheHiveCase.hive_id == case_data.get("id"))
                .first()
            )

            if existing_case:
                logger.debug(
                    f"[TheHiveCollector] Case {case_data.get('id')} already exists, updating"
                )
                # Update existing case
                existing_case.title = case_data.get("title", existing_case.title)
                existing_case.description = case_data.get(
                    "description", existing_case.description
                )
                existing_case.severity = self._map_severity(
                    case_data.get("severity", 2)
                )
                
                # Properly handle date conversion for startDate
                if case_data.get("startDate"):
                    existing_case.startDate = datetime.fromtimestamp(case_data.get("startDate") / 1000)
                
                existing_case.owner = case_data.get("owner", existing_case.owner)
                existing_case.flag = case_data.get("flag", existing_case.flag)
                existing_case.tlp = self._map_tlp(case_data.get("tlp", 2))
                existing_case.pap = self._map_pap(case_data.get("pap", 2))
                existing_case.tags = json.dumps(case_data.get("tags", []))
                existing_case.status = case_data.get("status", existing_case.status)
                existing_case.resolution_status = case_data.get(
                    "resolutionStatus", existing_case.resolution_status
                )
                existing_case.impact_status = case_data.get(
                    "impactStatus", existing_case.impact_status
                )
                existing_case.summary = case_data.get("summary", existing_case.summary)
                
                # Properly handle date conversion for endDate
                if case_data.get("endDate"):
                    existing_case.end_date = datetime.fromtimestamp(case_data.get("endDate") / 1000)
                
                session.flush()

                logger.info(
                    f"[TheHiveCollector] Updated case {existing_case.hive_id} in database"
                )
                return existing_case

            # Create new case
            case = TheHiveCase(
                hive_id=case_data.get("id"),
                title=case_data.get("title"),
                description=case_data.get("description"),
                severity=self._map_severity(case_data.get("severity", 2)),
                start_date=(
                    datetime.fromtimestamp(case_data.get("startDate", 0) / 1000)
                    if case_data.get("startDate")
                    else None
                ),
                owner=case_data.get("owner"),
                flag=case_data.get("flag", False),
                tlp=self._map_tlp(case_data.get("tlp", 2)),
                pap=self._map_pap(case_data.get("pap", 2)),
                tags=json.dumps(case_data.get("tags", [])),
                status=case_data.get("status"),
                resolution_status=case_data.get("resolutionStatus"),
                impact_status=case_data.get("impactStatus"),
                summary=case_data.get("summary"),
                end_date=(
                    datetime.fromtimestamp(case_data.get("endDate", 0) / 1000)
                    if case_data.get("endDate")
                    else None
                ),
            )

            session.add(case)
            session.flush()  # Flush to get the ID

            logger.info(f"[TheHiveCollector] Added case {case.hive_id} to database")
            return case

    def sync_all(self, days_back=30, start_date=None, end_date=None):
        """
        Sync all alerts and cases from TheHive to the database.

        Args:
            days_back (int): Number of days to look back (default: 30)
            start_date (datetime): Start date (overrides days_back)
            end_date (datetime): End date (defaults to now)

        Returns:
            tuple: (alert_count, case_count) - Number of alerts and cases synced
        """
        logger.info(
            f"[TheHiveCollector] Starting sync of TheHive data for past {days_back} days"
        )
        # Get cases
        cases = self.get_cases(days_back, start_date, end_date)
        case_count = 0
        for case_data in cases:
            self.sync_case_to_db(case_data)
            case_count += 1
            
        # Get alerts
        alerts = self.get_alerts(days_back, start_date, end_date)
        alert_count = 0
        for alert_data in alerts:
            self.sync_alert_to_db(alert_data)
            alert_count += 1



        logger.success(
            f"[TheHiveCollector] Synced {alert_count} alerts and {case_count} cases from TheHive"
        )
        return alert_count, case_count
