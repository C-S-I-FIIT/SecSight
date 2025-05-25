from sqlalchemy.orm import Session
from sqlalchemy import Column, func, select, case, cast, Float, literal, distinct, text
from app.db.database import Database
from app.db.models import Host, HostConfigReview, HostSigmaCompliance, SigmaRule, MitreTactic, MitreTechnique, MitreSubtechnique
from typing import List, Dict, Any, Union, Optional
import json
from datetime import datetime
import base64
import os
import tempfile
import time
import uuid
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import selenium.common.exceptions

from app.collectors.attack_svg_collector import export_mitre_attack_svg

from typing import Callable, Set

from enum import Enum

from app.db.queries.attack import AttackMatrixQueries

from loguru import logger

class SortingMode(Enum):
    NAME_ASC = 0
    NAME_DESC = 1
    SCORE_ASC = 2
    SCORE_DESC = 3


class MitreNavigatorGenerator:
    def __init__(self, attack_version: str = "16.1", navigator_version: str = "5.1.0", layer_version: str = "4.5"):
        self.db = Database()
        self.name = "MITRE ATT&CK Coverage"
        self.attack_version = attack_version
        self.navigator_version = navigator_version
        self.layer_version = layer_version
        
    def _gen_matrix_json(self, sorting_mode: SortingMode,
                          name: str,
                          description: str,
                          platforms: List[str] = ["Windows"],
                          techniques: List[Dict[str, Any]] = [],
                          global_show_subtechniques: bool = False,
                          hide_disabled: bool = False
                          ) -> Dict[str, Any]:
        """Get the base matrix JSON."""
        
        if global_show_subtechniques:
            expanded_subtechniques = "all"
        else:
            expanded_subtechniques = "none"
        
        navigator_json = {
            "versions": {
                "attack": self.attack_version,
                "navigator": self.navigator_version,
                "layer": self.layer_version
            },
            "name": name,
            "domain": "enterprise-attack",
            "description": description,
            "hideDisabled": hide_disabled,
            "filters": {
                "platforms": platforms
            },
            "layout": {
                "layout": "flat",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
                "expandedSubtechniques": expanded_subtechniques
            },
            "sorting": sorting_mode.value,
            #"viewMode": 0,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {
                    "label": "Covered",
                    "color": "#8ec843"
                },
                {
                    "label": "Partially Covered",
                    "color": "#ffe766"
                },
                {
                    "label": "Not Covered",
                    "color": "#ff6666"
                }
            ],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        return navigator_json
    
    # def _get_host_coverage(self, host_id: Union[int, Column[int]]) -> Dict[str, Any]:
    #     """Get the coverage data for a specific host."""
    #     with self.db.session() as session:
    #         # Get the latest config review for the host
    #         host = session.query(Host).filter(Host.id == host_id).first()
    #         if not host or not host.latest_config_review:
    #             return {}
                
    #         # Get all compliant Sigma rules for this host
    #         compliant_rules = session.query(HostSigmaCompliance).filter(
    #             HostSigmaCompliance.host_id == host_id,
    #             HostSigmaCompliance.host_config_review_id == host.latest_config_review.id
    #         ).all()
            
    #         # Get all enabled Sigma rules
    #         sigma_rules = session.query(SigmaRule).filter(
    #             SigmaRule.enabled == True,
    #             SigmaRule.deleted == False
    #         ).all()
            
    #         # Collect all tactics and techniques
    #         tactics = set()
    #         techniques = set()
            
    #         for rule in sigma_rules:
    #             for tactic in rule.tactics:
    #                 tactics.add(tactic.tactic_id)
    #             for technique in rule.techniques:
    #                 techniques.add(technique.technique_id)
                    
    #         return {
    #             "tactics": list(tactics),
    #             "techniques": list(techniques),
    #             "sigma_rules": [comp.sigma_rule.rule_id for comp in compliant_rules]
    #         }
        
    def _create_technique_entry(self, tactic_id: str, technique_id: str, subtechnique_id: Optional[str] = None, score: float = 100, rule_count: int = 0, bg_color: bool = False, hide_disabled: bool = False) -> Dict[str, Any]:
        """Create a technique entry for the navigator."""
        with self.db.session() as session:
            tactic_obj = session.query(MitreTactic).filter(MitreTactic.tactic_id == tactic_id).first()
            if not tactic_obj:
                # Handle case where tactic doesn't exist
                tactic_name = "unknown"
            else:
                tactic_name = tactic_obj.name
        
        tactic_name = tactic_name.replace(" ", "-").lower()
        
        # Check if the technique has a score (not unscored)
        has_score = rule_count > 0
        
        if hide_disabled:
            enabled = False
        else:
            enabled = True
            
            
        
        
        _data = {
            "techniqueID": technique_id if subtechnique_id is None else subtechnique_id,
            "tactic": tactic_name,
            "score": score ,
            "enabled": enabled,
            "comment": f"Rule count: {rule_count}",
            "showSubtechniques": False, # Handled later
            "color": "#43a7c8" if bg_color else ''
        }
        
        if rule_count <= 0:
            _data["comment"] = ''
            
        if score >= 100:
            _data["score"] = 100
        
        if has_score:
            _data["score"] = min(score, 100)  # Cap score at 100
            _data["comment"] = f"Rule count: {rule_count}"
            
        
        return _data
    
    def _resolve_techniques(self, techniques: Set[str], coverage_data, is_implemented_rules_query: bool = False, hide_disabled: bool = False) -> List[Dict[str, Any]]:
        """
        Resolve techniques and calculate scores based on subtechnique coverage.
        
        For each technique, this function:
        1. Finds all its subtechniques
        2. Calculates the technique's score based on its subtechniques' coverage
        3. Creates technique entries with appropriate coloring
        
        Args:
            techniques: Set of technique IDs to resolve
            coverage_data: Raw coverage data from the query
            is_implemented_rules_query: Whether this is the get_all_implemented_rules query
            
        Returns:
            List of technique entries to add to the MITRE Navigator
        """
        result = []
        
        # Convert coverage data to a dictionary for easier access
        coverage_dict = {}
        for item in coverage_data:
            tactic_id = item[0]
            technique_id = item[1]
            subtechnique_id = item[2]
            score = float(item[6])
            rule_count = int(item[7])
            
            # Skip if there's no technique_id (shouldn't happen)
            if not technique_id:
                continue
            
            # Create key based on tactic and technique
            key = (tactic_id, technique_id)
            
            # Initialize if not exists
            if key not in coverage_dict:
                coverage_dict[key] = {
                    'subtechniques': [],
                    'tactic_id': tactic_id,
                    'technique_id': technique_id,
                    'rule_count': 0
                }
            
            # Add subtechnique if it exists
            if subtechnique_id:
                coverage_dict[key]['subtechniques'].append({
                    'id': subtechnique_id,
                    'score': score,
                    'rule_count': rule_count
                })
            
            # Add to total rule count
            coverage_dict[key]['rule_count'] += rule_count
        
        with self.db.session() as session:
            # For each technique, calculate score and create entry
            for key, data in coverage_dict.items():
                tactic_id = data['tactic_id']
                technique_id = data['technique_id']
                rule_count = data['rule_count']
                
                # Get all subtechniques for this technique from database
                all_subtechniques = session.query(MitreSubtechnique).join(
                    MitreTechnique, 
                    MitreSubtechnique.technique_id == MitreTechnique.id
                ).filter(
                    MitreTechnique.technique_id == technique_id
                ).all()
                
                total_subtechniques = len(all_subtechniques)
                
                # If no subtechniques in DB for this technique, continue without creating entry
                # as it will be handled by regular processing
                if total_subtechniques == 0:
                    continue
                
                # Calculate score based on subtechnique coverage
                if total_subtechniques > 0:
                    # Get covered subtechnique IDs
                    covered_subtechniques = {st['id']: st['score'] for st in data['subtechniques']}
                    
                    # Sum scores of covered subtechniques
                    total_score = 0
                    for st in all_subtechniques:
                        if st.subtechnique_id in covered_subtechniques:
                            total_score += covered_subtechniques[st.subtechnique_id]
                    
                    # Calculate average score
                    avg_score = total_score / (total_subtechniques * 100) * 100
                else:
                    avg_score = 0
                
                # Determine color based on the query function and coverage
                color = ''
                if is_implemented_rules_query:
                    # Check if all subtechniques are covered
                    all_covered = len(data['subtechniques']) == total_subtechniques
                    if not all_covered:
                        color = '#ffa500'  # Light orange for partial coverage
                    else:
                        color = '#43a7c8'  # Default color for full coverage
                
                # Create technique entry
                entry = self._create_technique_entry(
                    tactic_id=tactic_id,
                    technique_id=technique_id,
                    subtechnique_id=None,  # This is the main technique
                    score=avg_score,
                    rule_count=rule_count,
                    bg_color=(is_implemented_rules_query and color != ''),
                    hide_disabled=hide_disabled
                )
                
                # Set the custom color if needed
                if color:
                    entry['color'] = color
                
                # Always show subtechniques for main techniques
                entry['showSubtechniques'] = True
                
                result.append(entry)
        
        return result
            
    def generate_navigator_json(self, name: str, description: str, query_function: Callable, hide_disabled: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Generate MITRE ATT&CK navigator JSON based on the results of a query function.
        
        Args:
            name: Name of the layer
            description: Description of the layer
            query_function: Function that returns coverage data
            **kwargs: Additional keyword arguments to pass to the query function
            
        Returns:
            Dictionary containing the ATT&CK Navigator layer data
        """
        # Flag to identify if the query is for implemented rules
        is_implemented_rules_query = (query_function == AttackMatrixQueries.get_all_implemented_rules)
        
        with self.db.session() as session:
            # Handle the case where session is already in kwargs
            if 'session' in kwargs:
                # Use the session from kwargs directly
                coverage = query_function(**kwargs)
            else:
                # Pass session and any additional kwargs to the query function
                coverage = query_function(session, **kwargs)
        
        # Create technique entries
        techniques_to_enable_show_subtechniques = set()
        
        techniques = []
        for tech in coverage:
            _tactic_id = tech[0]
            _technique_id = tech[1]
            _subtechnique_id = tech[2]
            _score = float(tech[6])
            _rule_count = int(tech[7])
            
            _bg_color = True if is_implemented_rules_query else False
            
            _entry = self._create_technique_entry(_tactic_id, _technique_id, _subtechnique_id, _score, _rule_count, _bg_color, hide_disabled)
            
            techniques.append(_entry)
            
            # If this is a subtechnique, mark its parent technique
            if _subtechnique_id and _technique_id:
                techniques_to_enable_show_subtechniques.add(_technique_id)
                
        for technique in techniques:
            if technique["techniqueID"] in techniques_to_enable_show_subtechniques:
                technique["showSubtechniques"] = True
                
        # Create technique entries for main techniques with subtechniques
        main_technique_entries = self._resolve_techniques(
            techniques_to_enable_show_subtechniques, 
            coverage, 
            is_implemented_rules_query
        )
        techniques.extend(main_technique_entries)
        
        name = f"MITRE ATT&CK Coverage - {name}" if name else "MITRE ATT&CK Coverage"
        
        # Create the final navigator JSON
        navigator_json = self._gen_matrix_json(
            sorting_mode=SortingMode.SCORE_DESC,
            name=name,
            description=description,
            techniques=techniques,
            hide_disabled=hide_disabled
        )
        
        return navigator_json
        

            
    # def generate_navigator_json_for_all_hosts(self) -> Dict[str, Any]:
    #     """Generate MITRE ATT&CK navigator JSON for all hosts."""
    #     with self.db.session() as session:
    #         # Get count of hosts with latest config reviews (for percentage calculation)
    #         total_hosts_with_reviews = session.query(func.count(Host.id)).filter(
    #             Host.latest_host_config_review_id.isnot(None)
    #         ).scalar()
            
    #         if total_hosts_with_reviews == 0:
    #             total_hosts_with_reviews = 1  # Avoid division by zero
                
    #         # Get all techniques
    #         all_techniques = session.query(MitreTechnique).all()
            
    #         # Create technique entries with calculated scores
    #         techniques = []
            
    #         for technique in all_techniques:
    #             # Make sure technique_id is a string
    #             technique_id_str = technique.technique_id
    #             if not isinstance(technique_id_str, str):
    #                 technique_id_str = str(technique_id_str)
                
    #             # Use SQLAlchemy's text() for raw SQL queries
    #             query = text(f"""
    #             SELECT CASE 
    #                 WHEN COUNT(DISTINCT h.id) = 0 THEN 0 
    #                 ELSE 100
    #             END as coverage_percentage
    #             FROM host h
    #             WHERE h.latest_host_config_review_id IS NOT NULL
    #             AND EXISTS (
    #                 SELECT 1 
    #                 FROM sigma_rule sr
    #                 JOIN mitre_technique_sigma_rule mtsr ON sr.id = mtsr.sigma_rule_id
    #                 JOIN mitre_technique mt ON mt.id = mtsr.technique_id
    #                 WHERE sr.enabled = true
    #                 AND sr.deleted = false
    #                 AND mt.technique_id = :technique_id
    #             )
    #             """)
                
    #             result = session.execute(query, {"technique_id": technique_id_str}).scalar() or 0
    #             score = float(result)
                
    #             # Add technique entry with calculated score
    #             techniques.append(self._create_technique_entry(
    #                 technique_id=technique_id_str,
    #                 score=score
    #             ))
            
    #         # Create the navigator JSON with calculated scores
    #         navigator_json = self._gen_matrix_json(
    #             sorting_mode=SortingMode.SCORE_DESC,
    #             name="MITRE ATT&CK Coverage",
    #             description="Generated from host rule coverage - score represents percentage of hosts covered",
    #             techniques=techniques
    #         )
            
    #         return navigator_json
        
    def convert_matrix_to_url_safe_base64(self, json_matrix_data: Dict[str, Any]):
        """Generate a data URL for a file."""
        json_str = json.dumps(json_matrix_data, indent=2)
        b64 = base64.b64encode(json_str.encode()).decode()
        data_url = f"data:application/json;base64,{b64}"
        formatted_data = data_url.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D").replace(":", "%3A")
        return formatted_data

    def create_local_json_file(self, json_matrix_data: Dict[str, Any], output_path: Union[str, None] = None) -> str:
        """Create a local JSON file and return its path."""
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(json_matrix_data, f, indent=2)
            return output_path
        
        # Create a temporary file
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, "attack_layer.json")
        
        with open(file_path, "w") as f:
            json.dump(json_matrix_data, f, indent=2)
        
        return file_path

    def get_download_link(self, json_matrix_data: Dict[str, Any]) -> str:
        """Generate a download link for a file."""
        json_str = json.dumps(json_matrix_data, indent=2)
        b64 = base64.b64encode(json_str.encode()).decode()
        href = f'<a href="data:application/json;base64,{b64}" download="attack_layer.json">Download ATT&CK Navigator Layer</a>'
        return href

    def generate_attack_navigator_url(self, json_matrix_data: Dict[str, Any]):
        data = self.convert_matrix_to_url_safe_base64(json_matrix_data)            
        # Create iframe URL
        attack_navigator_url = os.getenv("ATTACK_NAVIGATOR_URL")
        iframe_url = (
            f"{attack_navigator_url}"
            f"#layerURL={data}"
        )
            
        return iframe_url
    
    def _wait_for_table(self, driver):
        xpaths = [
            "/html/body/app-root/div/div/div/tabs/datatable/mat-drawer-container/mat-drawer-content/div/div/div/div/div/matrix-side/table",
            "/html/body/app-root/div/div/div/tabs/datatable/mat-drawer-container/mat-drawer-content/div/div/div/div/div/matrix-flat/table"
        ]
        for xpath in xpaths:
            try:
                element = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.XPATH, xpath))
                )
                return element
            except selenium.common.exceptions.TimeoutException:
                continue
        return None
    
    def take_screenshot(self, url):
        # Set up Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode (no GUI)

        # Path to your chromedriver
        service = Service('/usr/bin/chromedriver')  # Update this path

        # Initialize WebDriver
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_window_size(1536, 1800)

        # Open the webpage
        driver.get(url)

        # Wait for the page to load
        time.sleep(2)

        # Create temp file path with uuid
        temp_dir = tempfile.gettempdir()
        unique_id = str(uuid.uuid4())[:8]  # First 8 chars of UUID
        screenshot_path = os.path.join(temp_dir, f"attack_nav_{unique_id}.png")

        # Take screenshot
        # Find the table with class="matrix flat"
        #element = driver.find_element("css selector", "table.matrix.flat")
        #element.screenshot(screenshot_path)
        
        #driver.save_screenshot(screenshot_path)
         #Wait for the table to appear
        # Wait for the exact XPath element

        
        element = self._wait_for_table(driver)
        if element is None:
            return None
        
        # Optional scroll
        driver.execute_script("arguments[0].scrollIntoView();", element)
        
        driver.execute_script("""
            const container = document.querySelector('mat-drawer-content');
            if (container) {
                container.style.height = '1500px';
                container.scrollTop = 300;
            }
        """)
        
        time.sleep(1)

        # Screenshot the element
        element.screenshot(screenshot_path)

        # Clean up
        driver.quit()

        return screenshot_path
    
    def take_screenshot_svg(self, url):
        logger.debug("TAKING SCREENSHOT SVG")
        export_mitre_attack_svg(url)
    
