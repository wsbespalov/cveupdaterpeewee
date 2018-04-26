import peewee
from playhouse.postgres_ext import ArrayField
from datetime import datetime
import json

from configuration import POSTGRES

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

class VULNERABILITIES(peewee.Model):
    class Meta:
        database = database
        table_name = "vulnerabilities"
    id = peewee.PrimaryKeyField(
        null=False
    )
    component = peewee.TextField(
        default="",
        verbose_name="Component name"
    )
    version = peewee.TextField(
        default="",
        verbose_name="Component version"
    )

    # From CVEs Table

    published = peewee.DateTimeField(
        default=datetime.now,
        verbose_name="Component published date"
    )
    last_modified = peewee.DateTimeField(
        default=datetime.now,
        verbose_name="Component modified date"
    )
    data_format = peewee.TextField(
        default="",
        verbose_name="Component CVE Data Format"
    )
    data_type = peewee.TextField(
        default="",
        verbose_name="Component CVE Data Type"
    )
    data_version = peewee.TextField(
        default="",
        verbose_name="Component CVE Data Version"
    )
    description = peewee.TextField(
        default="",
        verbose_name="Component CVE description"
    )
    references = ArrayField(
        peewee.TextField,
        verbose_name="Component CVE References",
        default=[]
    )
    vendors = ArrayField(
        peewee.TextField,
        verbose_name='Component CVEs VENDORS Table',
        default=[]
    )
    cve = peewee.TextField(
        default="",
        verbose_name="Component CVE ID"
    )
    # cwe = peewee.TextField(
    #     default="",
    #     verbose_name='Component CVEs CWE ID',
    # )
    cwe = ArrayField(
        peewee.TextField,
        verbose_name='CVEs CWEs',
        default=[]
    )
    # capec = peewee.TextField(
    #     default="",
    #     verbose_name="Component CAPEC ID"
    # )
    capec = ArrayField(
        peewee.TextField,
        verbose_name='CVEs CWEs',
        default=[]
    )
    cpe22 = peewee.TextField(
        default="",
        verbose_name="Component CPE 2.2 string"
    )
    cvssv2_access_complexity = peewee.TextField(
        verbose_name="Component CVSS v.2 Access Complexity Metrics",
        default=""
    )
    cvssv2_access_vector = peewee.TextField(
        verbose_name="Component CVSS v.2 Access Vector Metrics",
        default=""
    )
    cvssv2_authentication = peewee.TextField(
        verbose_name="Component CVSS v.2 Authentication Metrics",
        default=""
    )
    cvssv2_availability_impact = peewee.TextField(
        verbose_name="Component CVSS v.2 Availability Impact Metrics",
        default=""
    )
    cvssv2_base_score = peewee.TextField(
        verbose_name="Component CVSS v.2 Base Score Metrics",
        default=""
    )
    cvssv2_confidentiality_impact = peewee.TextField(
        verbose_name="Component CVSS v.2 Confidentiality Impact Metrics",
        default=""
    )
    cvssv2_exploitability_score = peewee.TextField(
        verbose_name="Component CVSS v.2 Exploitability Score Metrics",
        default=""
    )
    cvssv2_impact_score = peewee.TextField(
        verbose_name="Component CVSS v.2 Impact Score Metrics",
        default=""
    )
    cvssv2_integrity_impact = peewee.TextField(
        verbose_name="Component CVSS v.2 Impact Score Metrics",
        default=""
    )
    cvssv2_obtain_all_privilege = peewee.TextField(
        verbose_name="Component CVSS v.2 Obtain All Privilege Metrics"
    )
    cvssv2_obtain_other_privilege = peewee.TextField(
        verbose_name="Component CVSS v.2 Obtain Other Privilege Metrics"
    )
    cvssv2_obtain_user_privilege = peewee.TextField(
        verbose_name="Component CVSS v.2 Obtain User Privilege Metrics"
    )
    cvssv2_severity = peewee.TextField(
        verbose_name="Component CVSS v.2 Severity Metrics",
        default=""
    )
    cvssv2_user_interaction_required = peewee.TextField(
        verbose_name="Component CVSS v.2 User Interaction Metrics"
    )
    cvssv2_vector_string = peewee.TextField(
        verbose_name="Component CVSS v.2 Vector String",
        default=""
    )
    cvssv2_version = peewee.TextField(
        verbose_name="Component CVSS v.2 Version",
        default=""
    )
    cvssv3_attack_complexity = peewee.TextField(
        verbose_name="Component CVSS v.3 Attack Complexity Metrics",
        default=""
    )
    cvssv3_attack_vector = peewee.TextField(
        verbose_name="Component CVSS v.3 Attack Vector Metrics",
        default=""
    )
    cvssv3_availability_impact = peewee.TextField(
        verbose_name="Component CVSS v.3 Availability Impact Metrics",
        default=""
    )
    cvssv3_base_score = peewee.TextField(
        verbose_name="Component CVSS v.3 Base Score Metrics",
        default=""
    )
    cvssv3_base_severity = peewee.TextField(
        verbose_name="Component CVSS v.3 Base Severity Metrics",
        default=""
    )
    cvssv3_confidentiality_impact = peewee.TextField(
        verbose_name="Component CVSS v.3 Confidentiality Impact Metrics",
        default=""
    )
    cvssv3_exploitability_score = peewee.TextField(
        verbose_name="Component CVSS v.3 Exploitability Score Metrics",
        default=""
    )
    cvssv3_impact_score = peewee.TextField(
        verbose_name="Component CVSS v.3 Impact Score Metrics",
        default=""
    )
    cvssv3_integrity_impact = peewee.TextField(
        verbose_name="Component CVSS v.3 Integrity Impact Metrics",
        default=""
    )
    cvssv3_privileges_required = peewee.TextField(
        verbose_name="Component CVSS v.3 Privileges Required Metrics",
        default=""
    )
    cvssv3_scope = peewee.TextField(
        verbose_name="Component CVSS v.3 Scope Metrics",
        default=""
    )
    cvssv3_user_interaction = peewee.TextField(
        verbose_name="Component CVSS v.3 User Interaction Metrics",
        default=""
    )
    cvssv3_vector_string = peewee.TextField(
        verbose_name="Component CVSS v.3 Vector String",
        default=""
    )
    cvssv3_version = peewee.TextField(
        verbose_name="Component CVSS v.3 Version",
        default=""
    )

    # # From CWE Table
    #
    # cwe_name = peewee.TextField(
    #     default="",
    #     verbose_name="Component CWE Name"
    # )
    # cwe_status = peewee.TextField(
    #     default="",
    #     verbose_name="Component CWE Status"
    # )
    # cwe_weaknessabs = peewee.TextField(
    #     default="",
    #     verbose_name="Component CWE Weaknessabs"
    # )
    # cwe_description_summary = peewee.TextField(
    #     default="",
    #     verbose_name="Component CWE Description Summary"
    # )

    # From CAPEC Table

    # capec_name = peewee.TextField(
    #     default="",
    #     verbose_name="Component CAPEC Name"
    # )
    # capec_summary = peewee.TextField(
    #     default="",
    #     verbose_name="Component CAPEC Summary"
    # )
    # capec_prerequisites = peewee.TextField(
    #     default="",
    #     verbose_name="Component CAPEC Prerequisities"
    # )
    # capec_solutions = peewee.TextField(
    #     default="",
    #     verbose_name="Component CAPEC Solutions"
    # )


    def __unicode__(self):
        return "VULNERABILITIES"

    def __str__(self):
        return self.cve

    @property
    def data(self):
        vulnerability_data = {}
        # From CVEs Table
        vulnerability_data["id"] = self.id
        vulnerability_data["cve"] = self.cve
        vulnerability_data["cwe"] = self.cwe
        vulnerability_data["capec"] = self.capec
        vulnerability_data["cpe22"] = self.cpe22
        vulnerability_data["references"] = self.references
        vulnerability_data["description"] = self.description
        vulnerability_data["modified"] = self.last_modified
        vulnerability_data["published"] = self.published
        vulnerability_data["version"] = self.version
        vulnerability_data["component"] = self.component
        vulnerability_data["cvssv2_access_complexity"] = self.cvssv2_access_complexity
        vulnerability_data["cvssv2_access_vector"] = self.cvssv2_access_vector
        vulnerability_data["cvssv2_authentication"] = self.cvssv2_authentication
        vulnerability_data["cvssv2_availability_impact"] = self.cvssv2_availability_impact
        vulnerability_data["cvssv2_base_score"] = self.cvssv2_base_score
        vulnerability_data["cvssv2_confidentiality_impact"] = self.cvssv2_confidentiality_impact
        vulnerability_data["cvssv2_exploitability_score"] = self.cvssv2_exploitability_score
        vulnerability_data["cvssv2_impact_score"] = self.cvssv2_impact_score
        vulnerability_data["cvssv2_integrity_impact"] = self.cvssv2_integrity_impact
        vulnerability_data["cvssv2_obtain_all_privilege"] = self.cvssv2_obtain_all_privilege
        vulnerability_data["cvssv2_obtain_other_privilege"] = self.cvssv2_obtain_other_privilege
        vulnerability_data["cvssv2_obtain_user_privilege"] = self.cvssv2_obtain_user_privilege
        vulnerability_data["cvssv2_severity"] = self.cvssv2_severity
        vulnerability_data["cvssv2_user_interaction_required"] = self.cvssv2_user_interaction_required
        vulnerability_data["cvssv2_vector_string"] = self.cvssv2_vector_string
        vulnerability_data["cvssv2_version"] = self.cvssv2_version
        vulnerability_data["cvssv3_attack_complexity"] = self.cvssv3_attack_complexity
        vulnerability_data["cvssv3_attack_vector"] = self.cvssv3_attack_vector
        vulnerability_data["cvssv3_availability_impact"] = self.cvssv3_availability_impact
        vulnerability_data["cvssv3_base_score"] = self.cvssv3_base_score
        vulnerability_data["cvssv3_base_severity"] = self.cvssv3_base_severity
        vulnerability_data["cvssv3_confidentiality_impact"] = self.cvssv3_confidentiality_impact
        vulnerability_data["cvssv3_exploitability_score"] = self.cvssv3_exploitability_score
        vulnerability_data["cvssv3_impact_score"] = self.cvssv3_impact_score
        vulnerability_data["cvssv3_integrity_impact"] = self.cvssv3_integrity_impact
        vulnerability_data["cvssv3_privileges_required"] = self.cvssv3_privileges_required
        vulnerability_data["cvssv3_scope"] = self.cvssv3_scope
        vulnerability_data["cvssv3_user_interaction"] = self.cvssv3_user_interaction
        vulnerability_data["cvssv3_vector_string"] = self.cvssv3_vector_string
        vulnerability_data["cvssv3_version"] = self.cvssv3_version
        # From CWE Table
        # vulnerability_data["cwe_name"] = self.cwe_name
        # vulnerability_data["cwe_status"] = self.cwe_status
        # vulnerability_data["cwe_weaknessabs"] = self.cwe_weaknessabs
        # vulnerability_data["cwe_description_summary"] = self.cwe_description_summary
        # From CAPEC Table
        # vulnerability_data["capec_name"] = self.capec_name
        # vulnerability_data["capec_summary"] = self.capec_summary
        # vulnerability_data["capec_prerequisites"] = self.capec_prerequisites
        # vulnerability_data["capec_solutions"] = self.capec_solutions

        return vulnerability_data

    @staticmethod
    def convert_list_data_from_json(data):
        if isinstance(data, list):
            deserialized = []
            for element in data:
                deserialized.append(json.loads(element))
            return deserialized
        else:
            return []

VULNERABILITIES.add_index(VULNERABILITIES.component)