import requests
import base64
import math
import pandas as pd
from loguru import logger
from dotenv import load_dotenv
import os
from app.db.models import SigmaRule, MitreTactic, MitreTechnique, MitreSubtechnique
from app.db.database import Database
from app.clients.vault_client import VaultClient
from sqlalchemy import or_, update

class KibanaCollector:
    def __init__(self):
        
        self.session = requests.Session()
        
        vault = VaultClient()
        secret = vault.get_secret('elk/kibana')
        self.base_url = secret.get('url', None)
        self.auth = f"{secret.get('user', None)}:{secret.get('pass', None)}".encode()

        
        if not self.base_url or not self.auth:
            logger.error("[Kibana] Kibana credentials not found in vault")
            raise ValueError("[Kibana] Kibana credentials not found in vault")
        
        self.verify_certs = False # os.getenv('KIBANA_VERIFY_CERTS', False)
        self.session.verify = self.verify_certs
        
        self.session.headers = {
            'Authorization': f"Basic {base64.b64encode(self.auth).decode()}",
            'Content-Type': 'application/json'
        }
        
        self.db = Database()

    def _fetch_rules_page(self, page_num=1, per_page=20):
        """Fetch a single page of rules from Kibana API."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/detection_engine/rules/_find",
                headers=self.session.headers,
                params={
                    'page': page_num,
                    'per_page': per_page,
                } if page_num > 1 else None,
                verify=self.verify_certs
            )
            return response.json()
        except Exception as e:
            logger.exception(f"[Kibana] Error fetching rules page {page_num}")
            return {'data': [], 'total': 0, 'per_page': per_page}

    def _fetch_all_rules(self):
        """Fetch all rules from Kibana using pagination."""
        try:
            # Get first page
            first_page = self._fetch_rules_page()
            rules = first_page.get('data', [])
            
            # Calculate pagination
            per_page = first_page.get('per_page', 20)
            total = first_page.get('total', 0)
            total_pages = math.ceil(total / per_page)
            
            logger.info(f"[Kibana] Discovered {total} rules from Kibana")
            
            # Fetch remaining pages
            for page_num in range(2, total_pages + 1):
                logger.info(f"[Kibana] Collecting rules from page {page_num} of {total_pages}...")
                page_data = self._fetch_rules_page(page_num, per_page)
                rules.extend(page_data.get('data', []))
            
            return rules
        except Exception as e:
            logger.exception("[Kibana] Error fetching all rules")
            return []

    def _update_sigma_rule(self, rule_data, sigma_rule):
        """Update a SigmaRule model instance from Kibana rule data.
        
        This method modifies the sigma_rule object in-place. The changes will be 
        persisted to the database when the session is committed.
        
        Args:
            rule_data: The rule data from Kibana API
            sigma_rule: The SigmaRule object to update
        """
        # Update Kibana specific fields
        sigma_rule.rule_kibana_id = rule_data.get('id', '')  # This is Kibana's internal ID
        sigma_rule.rule_kibana_custom_id = rule_data.get('rule_id', '')  # This is the custom rule ID
        sigma_rule.enabled = rule_data.get('enabled', False)
        sigma_rule.deleted = False  # Since we found it in Kibana, it's not deleted
        sigma_rule.risk_score = rule_data.get('risk_score', 0)
        sigma_rule.severity = rule_data.get('severity', '')
        
        # Update common fields if they're empty in the SigmaRule
        if not sigma_rule.name and rule_data.get('name'):
            sigma_rule.name = rule_data.get('name')
        if not sigma_rule.description and rule_data.get('description'):
            sigma_rule.description = rule_data.get('description')
        
        # No need to return the object as it's modified in-place
        # The modifications will be saved when the session is committed

    def _process_mitre_mappings(self, rule_data, rule_model, db_session):
        """Process MITRE ATT&CK mappings for a rule and create relationships."""
        if 'threat' not in rule_data:
            return

        for threat in rule_data['threat']:
            if threat.get('framework') != 'MITRE ATT&CK':
                continue

            # Process tactic
            tactic = threat.get('tactic', {})
            if tactic and tactic.get('id'):
                tactic_model = db_session.query(MitreTactic).filter_by(tactic_id=tactic.get('id')).first()
                if not tactic_model:
                    tactic_model = MitreTactic(
                        tactic_id=tactic.get('id'),
                        name=tactic.get('name', ''),
                        reference=tactic.get('reference', '')
                    )
                    db_session.add(tactic_model)
                rule_model.tactics.append(tactic_model)

            # Process techniques and subtechniques
            for technique in threat.get('technique', []):
                technique_id = technique.get('id')
                if not technique_id:
                    continue

                technique_model = db_session.query(MitreTechnique).filter_by(technique_id=technique_id).first()
                if not technique_model:
                    technique_model = MitreTechnique(
                        technique_id=technique_id,
                        name=technique.get('name', ''),
                        reference=technique.get('reference', '')
                    )
                    db_session.add(technique_model)
                rule_model.techniques.append(technique_model)

                # Process subtechniques
                for subtechnique in technique.get('subtechnique', []):
                    subtechnique_id = subtechnique.get('id')
                    if not subtechnique_id:
                        continue

                    subtechnique_model = db_session.query(MitreSubtechnique).filter_by(subtechnique_id=subtechnique_id).first()
                    if not subtechnique_model:
                        subtechnique_model = MitreSubtechnique(
                            subtechnique_id=subtechnique_id,
                            name=subtechnique.get('name', ''),
                            reference=subtechnique.get('reference', '')
                        )
                        db_session.add(subtechnique_model)

    def collect_kibana_rules(self):
        """Collect rules and MITRE mappings from Kibana and store in database."""
        try:
            # Fetch all rules from Kibana
            rules_data = self._fetch_all_rules()
            
            # Keep track of processed rules to identify deleted ones
            processed_rule_ids = set()
            
            with self.db.session() as db_session:
                # Process each rule
                for rule_data in rules_data:
                    kibana_rule_id = rule_data.get('id')
                    kibana_rule_custom_id = rule_data.get('rule_id')
                    
                    # Check if rule already exists by kibana_id
                    sigma_rule = db_session.query(SigmaRule).filter(
                        SigmaRule.rule_id == kibana_rule_id
                    ).first()
                    
                    if sigma_rule:                        # Update existing rule - the object is modified in-place
                        self._update_sigma_rule(rule_data, sigma_rule)
                        logger.debug(f"[Kibana] Updated rule [{kibana_rule_id}] (enabled={sigma_rule.enabled}, deleted={sigma_rule.deleted})")
                    else:
                        # Create new sigma rule
                        sigma_rule = SigmaRule(
                            rule_id=kibana_rule_id,
                            name=rule_data.get('name', ''),
                            description=rule_data.get('description', ''),
                            rule_kibana_id=kibana_rule_id,
                            rule_kibana_custom_id=kibana_rule_custom_id,
                            enabled=rule_data.get('enabled', False),
                            deleted=False,
                            risk_score=rule_data.get('risk_score', 0),
                            severity=rule_data.get('severity', '')
                        )
                        db_session.add(sigma_rule)
                        logger.debug(f"[Kibana] Created new rule from Kibana: {rule_data.get('name')} (enabled={sigma_rule.enabled}, deleted={sigma_rule.deleted})")

                    # Process MITRE mappings
                    self._process_mitre_mappings(rule_data, sigma_rule, db_session)
                    
                    # Add to processed list
                    if sigma_rule.rule_kibana_id is not None:
                        processed_rule_ids.add(sigma_rule.rule_kibana_id)
                    if sigma_rule.rule_kibana_custom_id is not None:
                        processed_rule_ids.add(sigma_rule.rule_kibana_custom_id)
                    if sigma_rule.rule_id is not None:
                        processed_rule_ids.add(sigma_rule.rule_id)
                
                # Save changes so far
                db_session.flush()
                
                # Mark rules as deleted if they weren't found in Kibana
                unprocessed_rules = db_session.query(SigmaRule).filter(
                    SigmaRule.deleted == False,  # Only check rules that are not already marked as deleted
                    SigmaRule.rule_kibana_id.isnot(None)  # Only check rules that were previously imported from Kibana
                ).all()
                
                # IDs of rules to mark as deleted
                rules_to_delete = []
                
                for rule in unprocessed_rules:
                    rule_missing = False
                    
                    if rule.rule_kibana_id is not None and rule.rule_kibana_id not in processed_rule_ids:
                        rule_missing = True
                    elif rule.rule_kibana_custom_id is not None and rule.rule_kibana_custom_id not in processed_rule_ids:
                        rule_missing = True
                    elif rule.rule_id is not None and rule.rule_id not in processed_rule_ids:
                        rule_missing = True
                        
                    if rule_missing:
                        logger.info(f"[Kibana] Marking rule as deleted: {rule.name} (ID: {rule.rule_id})")
                        # Add rule ID to the list of rules to delete
                        rules_to_delete.append(rule.id)
                
                # Update all rules to delete in a single statement
                if rules_to_delete:
                    logger.info(f"[Kibana] Marking {len(rules_to_delete)} rules as deleted")
                    db_session.execute(
                        update(SigmaRule)
                        .where(SigmaRule.id.in_(rules_to_delete))
                        .values(deleted=True)
                    )

                # Commit all changes
                db_session.commit()
                logger.info("[Kibana] All changes committed to database")
                
                # Log statistics
                rules_count = db_session.query(SigmaRule).count()
                enabled_rules_count = db_session.query(SigmaRule).filter_by(enabled=True).count()
                deleted_rules_count = db_session.query(SigmaRule).filter_by(deleted=True).count()
                tactics_count = db_session.query(MitreTactic).count()
                techniques_count = db_session.query(MitreTechnique).count()
                subtechniques_count = db_session.query(MitreSubtechnique).count()
                
                logger.info(f"[Kibana] Database now contains: {rules_count} sigma rules ({enabled_rules_count} enabled, {deleted_rules_count} deleted), "
                          f"{tactics_count} tactics, {techniques_count} techniques, {subtechniques_count} subtechniques")
                
                return True

        except Exception as e:
            logger.exception("[Kibana] Error collecting and storing Kibana rules")
            return False
        
    