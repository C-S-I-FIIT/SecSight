import os
import yaml
from typing import List, Dict, Optional, Tuple
from app.db.database import Database
from app.db.models import SigmaRule, MitreTactic, MitreTechnique, MitreSubtechnique, rule_tactics_map, rule_techniques_map, rule_subtechniques_map, Base

from app.mappings.mitre_attack import mitre_attack_tactics, mitre_attack_techniques

from loguru import logger


class SigmaRuleParser:
    def __init__(self, sigma_rules_path: str):
        """Initialize the parser with database connection."""
        self.db = Database()
        self.sigma_rules_path = sigma_rules_path

    def parse_log_source(self, rule_data: Dict) -> Tuple[str, str, str]:
        """Extract log source category, service, and product from rule data."""
        category = ""
        service = ""
        product = ""
        
        if 'logsource' in rule_data:
            log_source_data = rule_data['logsource']
            if isinstance(log_source_data, dict):
                # Extract category
                if 'category' in log_source_data:
                    category = str(log_source_data['category'])
                
                # Extract service
                if 'service' in log_source_data:
                    service = str(log_source_data['service'])
                
                # Extract product
                if 'product' in log_source_data:
                    product = str(log_source_data['product'])
            
            elif isinstance(log_source_data, str):
                # If it's a simple string, try to split it
                parts = log_source_data.split(':')
                if len(parts) >= 3:
                    category = parts[0]
                    service = parts[1]
                    product = parts[2]
                elif len(parts) == 2:
                    category = parts[0]
                    product = parts[1]
                else:
                    category = log_source_data
        
        return category, service, product

    def parse_tags(self, rule_data: Dict) -> Tuple[List[str], List[str], List[str]]:
        """Parse tags from rule data."""
        tags = []
        if 'tags' in rule_data:
            tags = rule_data['tags']

        attack_tags = []
        for tag in tags:
            if 'attack.' in tag:
                attack_tags.append(tag)
                
        tactics: List[str] = []
        techniques: List[str] = []
        subtechniques: List[str] = []
        
        _mitre_attack_techniques_ids = list(mitre_attack_techniques.keys())
        
        for tag in attack_tags:
            was_tactic = False
            # Extract tactic ID from tag (e.g. 'attack.discovery' -> 'TA0007')
            split_tag = tag.replace('attack.', '')  # Get 'discovery' from 'attack.discovery'
            for tactic_id, name in mitre_attack_tactics.items():
                if name == split_tag:
                    tactics.append(tactic_id)
                    was_tactic = True
                    break
                
            if not was_tactic:
                split_tag_technique = split_tag.split('.')
                technique_tag = split_tag_technique[0]
                subtechnique_tag = None
                if len(split_tag_technique) > 1:
                    subtechnique_tag = split_tag_technique[0] + '.' + split_tag_technique[1]
                
                if technique_tag.upper() in _mitre_attack_techniques_ids:
                    techniques.append(technique_tag.upper())
                
                if subtechnique_tag:
                    if subtechnique_tag.upper() in _mitre_attack_techniques_ids:
                        subtechniques.append(subtechnique_tag.upper())
                    
            
        return tactics, techniques, subtechniques

    def parse_rule(self, file_path: str) -> Optional[Dict]:
        """Parse a single Sigma rule file and return rule data as a dictionary."""
        try:
            with open(file_path, 'r') as f:
                rule_data = yaml.safe_load(f)
                
                # Extract log source components
                log_source_category, log_source_service, log_source_product = self.parse_log_source(rule_data)
                
                # Get MITRE tactics and techniques
                tactics, techniques, subtechniques = self.parse_tags(rule_data)
                
                # Return rule data as dictionary
                return {
                    'rule_id': rule_data.get('id', ''),
                    'name': rule_data.get('title', ''),
                    'log_source_category': log_source_category,
                    'log_source_service': log_source_service,
                    'log_source_product': log_source_product,
                    'description': rule_data.get('description', ''),
                    'status': rule_data.get('status', ''),
                    'level': rule_data.get('level', ''),
                    'tags': ','.join(rule_data.get('tags', [])),
                    'author': rule_data.get('author', ''),
                    'date': rule_data.get('date', ''),
                    'modified': rule_data.get('modified', ''),
                    'file_path': file_path,
                    'tactics': tactics,
                    'techniques': techniques,
                    'subtechniques': subtechniques
                }
                
        except Exception as e:
            logger.error(f"Error parsing rule file {file_path}: {str(e)}")
            return None

    def parse_directory(self, directory_path: str) -> List[Dict]:
        """Parse all Sigma rules in a directory."""
        rules_data = []
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    rule_data = self.parse_rule(file_path)
                    if rule_data:
                        rules_data.append(rule_data)
                        
        logger.info(f"[SigmaRuleParser] Found {len(rules_data)} rules in {directory_path}")
        return rules_data

    def save_rules(self, rules_data: List[Dict]):
        """Save rules to the database."""
        try:

            for rule_data in rules_data:
                with self.db.session() as session:
                    # Check if rule already exists
                    existing_rule = session.query(SigmaRule).filter_by(rule_id=rule_data['rule_id']).first()
                    
                    if existing_rule:
                        # Update existing rule
                        session.query(SigmaRule).filter_by(id=existing_rule.id).update({
                            SigmaRule.name: rule_data['name'],
                            SigmaRule.log_source_category: rule_data['log_source_category'],
                            SigmaRule.log_source_service: rule_data['log_source_service'],
                            SigmaRule.log_source_product: rule_data['log_source_product'],
                            SigmaRule.description: rule_data['description'],
                            SigmaRule.status: rule_data['status'],
                            SigmaRule.level: rule_data['level'],
                            SigmaRule.tags: rule_data['tags'],
                            SigmaRule.author: rule_data['author'],
                            SigmaRule.date: rule_data['date'],
                            SigmaRule.modified: rule_data['modified'],
                            SigmaRule.file_path: rule_data['file_path']
                        })
                        
                        # Remove existing mappings
                        session.execute(rule_tactics_map.delete().where(rule_tactics_map.c.sigma_rule_id == existing_rule.id))
                        session.execute(rule_techniques_map.delete().where(rule_techniques_map.c.sigma_rule_id == existing_rule.id))
                        
                        rule_id = existing_rule.id
                    else:
                        # Create new rule
                        new_rule = SigmaRule(
                            rule_id=rule_data['rule_id'],
                            name=rule_data['name'],
                            log_source_category=rule_data['log_source_category'],
                            log_source_service=rule_data['log_source_service'],
                            log_source_product=rule_data['log_source_product'],
                            description=rule_data['description'],
                            status=rule_data['status'],
                            level=rule_data['level'],
                            tags=rule_data['tags'],
                            author=rule_data['author'],
                            date=rule_data['date'],
                            modified=rule_data['modified'],
                            file_path=rule_data['file_path']
                        )
                        session.add(new_rule)
                        session.flush()  # This assigns an ID to the new_rule
                        rule_id = new_rule.id
                    
                    # Create mappings for tactics
                    for tactic_id in rule_data['tactics']:
                        tactic = session.query(MitreTactic).filter(MitreTactic.tactic_id.ilike(tactic_id)).first()
                        if tactic:
                            stmt = rule_tactics_map.insert().values(
                                sigma_rule_id=rule_id,
                                tactic_id=tactic.id
                            )
                            session.execute(stmt)

                    # Create mappings for techniques
                    for technique_id in rule_data['techniques']:
                        technique = session.query(MitreTechnique).filter(MitreTechnique.technique_id.ilike(technique_id)).first()
                        if technique:
                            stmt = rule_techniques_map.insert().values(
                                sigma_rule_id=rule_id,
                                technique_id=technique.id
                            )
                            session.execute(stmt)
                            
                    # Create mappings for subtechniques
                    for subtechnique_id in rule_data['subtechniques']:
                        subtechnique = session.query(MitreSubtechnique).filter(MitreSubtechnique.subtechnique_id.ilike(subtechnique_id)).first()
                        if subtechnique:
                            stmt = rule_subtechniques_map.insert().values(
                                sigma_rule_id=rule_id,
                                subtechnique_id=subtechnique.id
                            )
                            session.execute(stmt)
                    session.commit()
                    
            logger.success(f"[SigmaRuleParser] Successfully saved {len(rules_data)} rules to database")
                
        except Exception as e:
            logger.error(f"[SigmaRuleParser] Error saving rules to database: {str(e)}")
            raise

    def process_sigma_rules(self):
        """Main method to process Sigma rules."""
        try:
            # Parse rules
            rules_data = self.parse_directory(self.sigma_rules_path)
            
            # Save rules to database
            self.save_rules(rules_data)
            
        except Exception as e:
            logger.error(f"[SigmaRuleParser] Error processing Sigma rules: {str(e)}")
            raise
