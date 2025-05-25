from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, UniqueConstraint, Boolean, Text, Float, Table
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base

# Host and Configuration Review models
class Host(Base):
    __tablename__ = 'host'
    
    id = Column(Integer, primary_key=True)
    netbox_id = Column(Integer, nullable=False)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    
    
    


    latest_host_config_review_id = Column(Integer, ForeignKey('host_config_review.id'), nullable=True)
    
    platform_os = Column(String) # Windows, Linux, etc.
    role = Column(String) # Server, Workstation, etc.
    manufacturer = Column(String) # Dell, HP, etc.
    model = Column(String) # Model name
    comment = Column(String)
    status = Column(String) # Active, Inactive, Unknown
    site = Column(String) # FIIT
    location = Column(String) # Room
    url = Column(String) # URL of the host
    
    is_vm = Column(Boolean, default=False)
    cluster = Column(String) # Cluster name
    
    # IP Address Info
    dns_name = Column(String)
    ip_description = Column(String)

    # Prefix Info
    prefix_name = Column(String)
    prefix_description = Column(String)
    vlan_id = Column(Integer)
    vlan_name = Column(String)
    vlan_display = Column(String)


    # Relationships
    config_reviews = relationship("HostConfigReview", back_populates="host", foreign_keys="HostConfigReview.host_id")
    latest_config_review = relationship("HostConfigReview", foreign_keys=[latest_host_config_review_id])
    

class NetBoxTag(Base):
    __tablename__ = 'netbox_tag'
    id = Column(Integer, primary_key=True)
    netbox_id = Column(Integer, nullable=False)
    name = Column(String)
    color = Column(String)
    
    
# Junction table for Netbox Tags and Hosts (many-to-many)
tag_device_rule_map = Table(
    'tag_device_rule',
    Base.metadata,
    Column('tag_id', Integer, ForeignKey('netbox_tag.id')),
    Column('device_id', Integer, ForeignKey('host.id')),
)


class HostConfigReview(Base):
    __tablename__ = 'host_config_review'
        
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('host.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed = Column(Boolean, default=False)
    
    # Relationships
    host = relationship("Host", back_populates="config_reviews", foreign_keys=[host_id])
    entries = relationship("HostConfigReviewEntry", back_populates="config_review")

class HostConfigReviewEntry(Base):
    __tablename__ = 'host_config_review_entry'
    
    id = Column(Integer, primary_key=True)
    host_config_review_id = Column(Integer, ForeignKey('host_config_review.id'), nullable=False)
    name = Column(String, nullable=False)
    event_id = Column(Integer, nullable=True)
    
    # Relationships
    config_review = relationship("HostConfigReview", back_populates="entries")
    
# class WindowsLogSource(Base):
#     __tablename__ = 'windows_log_source'
    
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     name = Column(String, nullable=False)
#     #mode = Column(String, nullable=False)
#     #max_size_bytes = Column(Integer, nullable=False)
#     #event_id = Column(Integer, nullable=True)
    
# class WinlogbeatConfig(Base):
#     __tablename__ = 'winlogbeat_config'
    
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     name = Column(String, nullable=False)
#     config = Column(Text, nullable=False)
    
    
# class WinlogSourceHostMap(Base):
#     __tablename__ = 'winlogsource_host_map'
    
#     id = Column(Integer, primary_key=True)
#     winlogsource_id = Column(Integer, ForeignKey('windows_log_source.id'))
#     host_id = Column(Integer, ForeignKey('host.id'))
#     enabled = Column(Boolean, default=True)
#     max_size_bytes = Column(Integer, nullable=True)
#     record_count = Column(Integer, nullable=True)
#     log_mode = Column(String, nullable=True)
    
#     # Relationships
#     host = relationship("Host")
#     winlogsource = relationship("WindowsLogSource")

class SigmaRule(Base):  
    __tablename__ = 'sigma_rule'

    id = Column(Integer, primary_key=True)
    rule_id = Column(String(100), unique=True)
    name = Column(String(255))
    log_source_category = Column(String(255))
    log_source_service = Column(String(255))
    log_source_product = Column(String(255))
    description = Column(Text)
    status = Column(String(50))
    level = Column(String(50))
    tags = Column(String(255))
    author = Column(String(255))
    date = Column(String(50))
    modified = Column(String(50))
    file_path = Column(String(255))
    
    # New fields from the Rule class
    rule_kibana_id = Column(String)  # Kibana rule ID
    rule_kibana_custom_id = Column(String)  # Custom rule ID
    enabled = Column(Boolean, default=False)  # Rules are disabled by default
    deleted = Column(Boolean, default=False)  # Rules are not deleted by default
    risk_score = Column(Float)
    severity = Column(String)
    
    # Relationships
    tactics = relationship('MitreTactic', secondary='mitre_tactic_sigma_rule', backref='sigma_rules')
    techniques = relationship('MitreTechnique', secondary='mitre_technique_sigma_rule', backref='sigma_rules')
    windows_log_sources = relationship('SigmaWindowsLogSource', secondary='sigma_rule_windows_log_map', back_populates='sigma_rules')

    def __repr__(self):
        return f"<SigmaRule(rule_id='{self.rule_id}', name='{self.name}', category='{self.log_source_category}', service='{self.log_source_service}', product='{self.log_source_product}')>"

class HostSigmaCompliance(Base):
    __tablename__ = 'host_sigma_compliance'
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('host.id'), nullable=False)
    host_config_review_id = Column(Integer, ForeignKey('host_config_review.id'), nullable=False)
    sigma_id = Column(Integer, ForeignKey('sigma_rule.id'), nullable=False)
    
    # Add unique constraint for host_config_review_id and sigma_id combination
    __table_args__ = (
        UniqueConstraint('host_config_review_id', 'sigma_id', name='uix_host_config_review_sigma'),
    )
    
    # Relationships
    host = relationship("Host")
    host_config_review = relationship("HostConfigReview")
    sigma_rule = relationship("SigmaRule")


class SigmaWindowsLogSource(Base):
    __tablename__ = 'sigma_windows_log_source'
    
    id = Column(Integer, primary_key=True)
    sigma_log_source = Column(String, nullable=False)
    windows_event_channel = Column(String, nullable=False)
    event_id = Column(Integer, nullable=True)
    
    # Relationships
    sigma_rules = relationship('SigmaRule', secondary='sigma_rule_windows_log_map', back_populates='windows_log_sources')

# Junction table for SigmaRules and WindowsLogSources (many-to-many)
sigma_rule_windows_log_map = Table(
    'sigma_rule_windows_log_map',
    Base.metadata,
    Column('sigma_rule_id', Integer, ForeignKey('sigma_rule.id')),
    Column('windows_log_source_id', Integer, ForeignKey('sigma_windows_log_source.id'))
)

class MitreTactic(Base):
    __tablename__ = 'mitre_tactic'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tactic_id = Column(String, unique=True)
    name = Column(String)
    reference = Column(String)
    
    
class MitreTechnique(Base):
    __tablename__ = 'mitre_technique'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String, unique=True)
    name = Column(String)
    reference = Column(String)
    
class MitreSubtechnique(Base):
    __tablename__ = 'mitre_subtechnique'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    subtechnique_id = Column(String, unique=True)
    technique_id = Column(Integer, ForeignKey('mitre_technique.id'), nullable=True)
    name = Column(String)
    reference = Column(String)
    
mitre_technique_tactic_map = Table(
    'mitre_technique_tactic_map',
    Base.metadata,
    Column('technique_id', Integer, ForeignKey('mitre_technique.id')),
    Column('tactic_id', Integer, ForeignKey('mitre_tactic.id'))
)
    
# Junction table for SigmaRules-Tactics (many-to-many)
rule_tactics_map = Table(
    'mitre_tactic_sigma_rule',
    Base.metadata,
    Column('sigma_rule_id', Integer, ForeignKey('sigma_rule.id')),
    Column('tactic_id', Integer, ForeignKey('mitre_tactic.id'))
)

# Junction table for SigmaRules-Techniques (many-to-many)
rule_techniques_map = Table(
    'mitre_technique_sigma_rule',
    Base.metadata,
    Column('sigma_rule_id', Integer, ForeignKey('sigma_rule.id')),
    Column('technique_id', Integer, ForeignKey('mitre_technique.id'))
)

rule_subtechniques_map = Table(
    'mitre_subtechnique_sigma_rule',
    Base.metadata,
    Column('sigma_rule_id', Integer, ForeignKey('sigma_rule.id')),
    Column('subtechnique_id', Integer, ForeignKey('mitre_subtechnique.id'))
)

# TheHive models
class TheHiveCase(Base):
    __tablename__ = 'thehive_case'
    
    id = Column(Integer, primary_key=True)
    hive_id = Column(String, unique=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String)  # SEV:LOW, SEV:MEDIUM, SEV:HIGH, SEV:CRITICAL
    start_date = Column(DateTime)
    owner = Column(String)
    flag = Column(Boolean, default=False)
    tlp = Column(String)  # TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED
    pap = Column(String)  # PAP:WHITE, PAP:GREEN, PAP:AMBER, PAP:RED
    tags = Column(String)  # Stored as JSON
    status = Column(String)
    resolution_status = Column(String)
    impact_status = Column(String)
    summary = Column(Text)
    end_date = Column(DateTime)

class TheHiveAlert(Base):
    __tablename__ = 'thehive_alert'
    
    id = Column(Integer, primary_key=True)
    hive_id = Column(String, unique=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    tlp = Column(String)  # TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED
    pap = Column(String)  # PAP:WHITE, PAP:GREEN, TLP:AMBER, TLP:RED
    severity = Column(String)  # SEV:LOW, SEV:MEDIUM, SEV:HIGH, SEV:CRITICAL
    date = Column(DateTime)
    tags = Column(String)  # Stored as JSON
    type = Column(String)
    source = Column(String)
    source_ref = Column(String)
    status = Column(String)
    case_id = Column(Integer, ForeignKey('thehive_case.id'), nullable=True)
    
    # Relationships
    artifacts = relationship('TheHiveArtifact', secondary='thehive_alert_artifact_map', back_populates='alerts')

class TheHiveArtifact(Base):
    __tablename__ = 'thehive_artifact'
    
    id = Column(Integer, primary_key=True)
    data_type = Column(String, nullable=False)
    message = Column(Text)
    data = Column(Text)
    
    # Relationships
    alerts = relationship('TheHiveAlert', secondary='thehive_alert_artifact_map', back_populates='artifacts')


# Junction table for Alerts and Artifacts (many-to-many)
alert_artifact_map = Table(
    'thehive_alert_artifact_map',
    Base.metadata,
    Column('alert_id', Integer, ForeignKey('thehive_alert.id')),
    Column('artifact_id', Integer, ForeignKey('thehive_artifact.id'))
)

