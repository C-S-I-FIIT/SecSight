import requests
import json
from datetime import datetime
from stix2 import MemoryStore, Filter
from app.db.database import Database
from app.db.models import MitreTactic, MitreTechnique, MitreSubtechnique, Base, mitre_technique_tactic_map
from loguru import logger
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import or_

import os

class MitreCollector:
    
    
    attack_chain_mapping = {
        "reconnaissance": "Reconnaissance",
        "resource-development": "Resource Development",
        "initial-access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege-escalation": "Privilege Escalation",
        "defense-evasion": "Defense Evasion",
        "credential-access": "Credential Access",
        "discovery": "Discovery",
        "lateral-movement": "Lateral Movement",
        "collection": "Collection",
        "command-and-control": "Command and Control",
        "impact": "Impact",
        "exfiltration": "Exfiltration"
    }
    
    
    def __init__(self, version="16.0"):
        """
        Initialize the MITRE ATT&CK collector.
        
        Args:
            version (str): MITRE ATT&CK version to use (e.g., "16.0")
        """
        self.version = version
        self.db = Database()
    
    def data_exists(self):
        """Check if MITRE data already exists in the database."""
        with self.db.session() as session:
            tactics_count = session.query(MitreTactic).count()
            techniques_count = session.query(MitreTechnique).count()
            
            if tactics_count > 0 and techniques_count > 0:
                logger.info(f"MITRE data already exists in the database: {tactics_count} tactics, {techniques_count} techniques.")
                return True
            return False
        
    def download_stix_data(self):
        """Download MITRE ATT&CK STIX data for the specified version."""
        logger.info(f"Downloading MITRE ATT&CK v{self.version} data")
        url = f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{self.version}/enterprise-attack/enterprise-attack.json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                logger.info(f"Successfully downloaded MITRE ATT&CK v{self.version} data")
                with open(f"./data/mitre_data_{self.version}.json", "w") as f:
                    json.dump(response.json(), f)
                return response.json()
            else:
                logger.error(f"Failed to download MITRE ATT&CK data. Status code: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error downloading MITRE ATT&CK data: {str(e)}")
            return None

    def process_tactics(self, tactics):
        """Process and update tactics."""
        logger.info("Updating tactics...")
        tactics_updated = 0
        tactics_added = 0
        
        for tactic in tactics:
            with self.db.session() as session:
                try:
                    tactic_id = tactic["external_references"][0]["external_id"]
                    existing_tactic = session.query(MitreTactic).filter(MitreTactic.tactic_id == tactic_id).first()
                    
                    if existing_tactic:
                        # Update existing tactic
                        existing_tactic.name = tactic["name"]
                        existing_tactic.reference = tactic["external_references"][0]["url"]
                        tactics_updated += 1
                    else:
                        # Add new tactic
                        new_tactic = MitreTactic(
                            tactic_id=tactic_id,
                            name=tactic["name"],
                            reference=tactic["external_references"][0]["url"]
                        )
                        session.add(new_tactic)
                        tactics_added += 1
                    session.commit()
                except Exception as e:
                    session.rollback()
                    logger.warning(f"Error processing tactic {tactic.get('name', 'unknown')}: {str(e)}")
        
        logger.info(f"Processed tactics: {tactics_added} added, {tactics_updated} updated")
        return tactics_added + tactics_updated
        
    def process_techniques(self, techniques):
        """Process and update techniques. Returns subtechniques to process."""
        logger.info("Updating techniques...")
        techniques_updated = 0
        techniques_added = 0
        subtechniques_to_process = []
        
        for technique in techniques:
            with self.db.session() as session:
                try:
                    ext_refs = technique.get("external_references", [])
                    if not ext_refs:
                        continue
                        
                    technique_id = ext_refs[0]["external_id"]
                    
                    if "." in technique_id:
                        # Store subtechnique information for later processing
                        subtechniques_to_process.append({
                            "id": technique_id,
                            "name": technique["name"],
                            "reference": ext_refs[0]["url"],
                            "parent_id": technique_id.split(".")[0]
                        })
                    else:
                        
                        existing_technique = session.query(MitreTechnique).filter(
                            MitreTechnique.technique_id == technique_id
                        ).first()
                        
                        if existing_technique:
                            # Update existing technique
                            existing_technique.name = technique["name"]
                            existing_technique.reference = ext_refs[0]["url"]
                            techniques_updated += 1
                        else:
                            # Add new technique
                            new_technique = MitreTechnique(
                                technique_id=technique_id,
                                name=technique["name"],
                                reference=ext_refs[0]["url"]
                            )
                            
                            session.add(new_technique)
                            session.flush()
                            
                            existing_technique = new_technique
                            
                            techniques_added += 1
                        
                        # Process regular technique
                        tactics = [kill_chain['phase_name'] for kill_chain in technique.get("kill_chain_phases", []) if kill_chain.get("kill_chain_name") == "mitre-attack"]
                        
                        for tactic in tactics:
                            tactic_name_for_query = self.attack_chain_mapping.get(tactic)
                            q_tactic = session.query(MitreTactic).filter(MitreTactic.name == tactic_name_for_query).first()
                            if q_tactic:
                                check_if_exists = session.query(mitre_technique_tactic_map).filter(mitre_technique_tactic_map.c.technique_id == existing_technique.id, mitre_technique_tactic_map.c.tactic_id == q_tactic.id).first()
                                if not check_if_exists:
                                    _qry_mitre_technique_tactic_map = mitre_technique_tactic_map.insert().values(
                                        technique_id=existing_technique.id,
                                        tactic_id=q_tactic.id
                                    )
                                    session.execute(_qry_mitre_technique_tactic_map)
                        session.flush()
                        session.commit()
                        
                except Exception as e:
                    session.rollback()
                    logger.warning(f"Error processing technique {technique.get('name', 'unknown')}: {str(e)}")
        
        logger.info(f"Processed techniques: {techniques_added} added, {techniques_updated} updated")
        return subtechniques_to_process, techniques_added + techniques_updated
        
    def process_subtechniques(self, subtechniques_to_process):
        """Process and update subtechniques."""
        logger.info("Updating subtechniques...")
        subtechniques_updated = 0
        subtechniques_added = 0
        
        for subtech in subtechniques_to_process:
            with self.db.session() as session:
                try:
                    # First, ensure we get the correct parent technique
                    parent_id = subtech["parent_id"]
                    technique = session.query(MitreTechnique).filter(
                        MitreTechnique.technique_id == parent_id
                    ).first()
                    
                    if not technique:
                        logger.warning(f"Parent technique {parent_id} not found for subtechnique {subtech['id']}")
                        continue
                    
                    # Get technique id for foreign key
                    technique_id = technique.id
                    
                    # Now in a new transaction, process the subtechnique
                    existing_subtech = session.query(MitreSubtechnique).filter(
                        MitreSubtechnique.subtechnique_id == subtech["id"]
                    ).first()
                    
                    if existing_subtech:
                        # Update existing subtechnique
                        existing_subtech.name = subtech["name"]
                        existing_subtech.reference = subtech["reference"]
                        existing_subtech.technique_id = technique_id
                        subtechniques_updated += 1
                    else:
                        # Add new subtechnique
                        new_subtech = MitreSubtechnique(
                            subtechnique_id=subtech["id"],
                            name=subtech["name"],
                            reference=subtech["reference"],
                            technique_id=technique_id
                        )
                        session.add(new_subtech)
                        subtechniques_added += 1
                    
                    session.commit()
                except SQLAlchemyError as e:
                    session.rollback()
                    logger.warning(f"Database error processing subtechnique {subtech.get('id', 'unknown')}: {str(e)}")
                except Exception as e:
                    session.rollback()
                    logger.warning(f"Error processing subtechnique {subtech.get('id', 'unknown')}: {str(e)}")
        
        logger.info(f"Processed subtechniques: {subtechniques_added} added, {subtechniques_updated} updated")
        return subtechniques_added + subtechniques_updated

    def process_stix_data(self, stix_data):
        """Process STIX data and store in database."""
        logger.info(f"Processing MITRE ATT&CK v{self.version} data")
        
        try:
            mem_store = MemoryStore(stix_data=stix_data)
            
            # Get tactics
            tactics = mem_store.query([
                Filter("type", "=", "x-mitre-tactic")
            ])
            
            # Get techniques and subtechniques
            techniques = mem_store.query([
                Filter("type", "=", "attack-pattern")
            ])
            
            # Process in separate transactions to avoid long-running transaction issues
            tactics_count = self.process_tactics(tactics)
            subtechniques_to_process, techniques_count = self.process_techniques(techniques)
            subtechniques_count = self.process_subtechniques(subtechniques_to_process)
            
            logger.info(f"Successfully processed MITRE ATT&CK v{self.version} data")
            logger.info(f"Total tactics: {tactics_count}")
            logger.info(f"Total techniques: {techniques_count}")
            logger.info(f"Total subtechniques: {subtechniques_count}")
            
            return True
        except Exception as e:
            logger.error(f"Error processing MITRE ATT&CK data: {str(e)}")
            return False

    def collect(self, force_update=False):
        """Main method to collect and process MITRE ATT&CK data."""
        try:
            # Check if data exists and user doesn't want to force update
            if not force_update and self.data_exists():
                logger.info("MITRE data already exists. Use force_update=True to update anyway.")
                return True
                
            logger.info(f"Starting MITRE collection for version {self.version}...")
            
            # Check if data exists in the database
            if os.path.exists(f"./data/mitre_data_{self.version}.json"):
                logger.info("MITRE data already exists. Using existing data. Loading...")
                stix_data = json.load(open(f"./data/mitre_data_{self.version}.json"))
            else:
                stix_data = self.download_stix_data()
                if not stix_data:
                    logger.warning("Failed to download MITRE ATT&CK data. Using existing data if available.")
                    return True
                
            success = self.process_stix_data(stix_data)
            if success:
                logger.info("MITRE data update completed successfully.")
            else:
                logger.warning("MITRE data update completed with issues, but application will continue running.")
                
            return True
        except Exception as e:
            logger.error(f"Error during MITRE ATT&CK data collection: {str(e)}")
            # Continue execution instead of raising the exception
            return True
        