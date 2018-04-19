import peewee
from playhouse.postgres_ext import ArrayField

import json

from configuration import POSTGRES

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


class CVE_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "cve_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        unique=True,
        default="",
        verbose_name="CVE ID"
    )
    data_format = peewee.TextField(
        default="",
        verbose_name="CVE Data Format"
    )
    data_type = peewee.TextField(
        default="",
        verbose_name="CVE Data Type"
    )
    data_version = peewee.TextField(
        default="",
        verbose_name="CVE Data Version"
    )
    description = peewee.TextField(
        default="",
        verbose_name="CVE Description"
    )
    last_modified = peewee.DateTimeField(
        verbose_name='CVE last modified time from server'
    )
    published = peewee.DateTimeField(
        verbose_name="CVE Published time"
    )
    references = ArrayField(
        peewee.TextField,
        verbose_name="CVE References",
        default=[]
    )
    vendors = ArrayField(
        peewee.TextField,
        verbose_name='CVEs VENDORS Table',
        default=[]
    )
    cpe22 = ArrayField(
        peewee.TextField,
        verbose_name='CVE CPE 2.2 Array',
        default=[]
    )
    cpe23 = ArrayField(
        peewee.TextField,
        verbose_name='CVE CPE 2.3 Array',
        default=[]
    )
    cwe = ArrayField(
        peewee.TextField,
        verbose_name='CVEs CWE ID',
        default=[]
    )
    cvssv2_access_complexity = peewee.TextField(
        verbose_name="CVSS v.2 Access Complexity Metrics",
        default=""
    )
    cvssv2_access_vector = peewee.TextField(
        verbose_name="CVSS v.2 Access Vector Metrics",
        default=""
    )
    cvssv2_authentication = peewee.TextField(
        verbose_name="CVSS v.2 Authentication Metrics",
        default=""
    )
    cvssv2_availability_impact = peewee.TextField(
        verbose_name="CVSS v.2 Availability Impact Metrics",
        default=""
    )
    cvssv2_base_score = peewee.TextField(
        verbose_name="CVSS v.2 Base Score Metrics",
        default=""
    )
    cvssv2_confidentiality_impact = peewee.TextField(
        verbose_name="CVSS v.2 Confidentiality Impact Metrics",
        default=""
    )
    cvssv2_exploitability_score = peewee.TextField(
        verbose_name="CVSS v.2 Exploitability Score Metrics",
        default=""
    )
    cvssv2_impact_score = peewee.TextField(
        verbose_name="CVSS v.2 Impact Score Metrics",
        default=""
    )
    cvssv2_integrity_impact = peewee.TextField(
        verbose_name="CVSS v.2 Impact Score Metrics",
        default=""
    )
    cvssv2_obtain_all_privilege = peewee.BooleanField(
        verbose_name="CVSS v.2 Obtain All Privilege Metrics"
    )
    cvssv2_obtain_other_privilege = peewee.BooleanField(
        verbose_name="CVSS v.2 Obtain Other Privilege Metrics"
    )
    cvssv2_obtain_user_privilege = peewee.BooleanField(
        verbose_name="CVSS v.2 Obtain User Privilege Metrics"
    )
    cvssv2_severity = peewee.TextField(
        verbose_name="CVSS v.2 Severity Metrics",
        default=""
    )
    cvssv2_user_interaction_required = peewee.BooleanField(
        verbose_name="CVSS v.2 User Interaction Metrics"
    )
    cvssv2_vector_string = peewee.TextField(
        verbose_name="CVSS v.2 Vector String",
        default=""
    )
    cvssv2_version = peewee.TextField(
        verbose_name="CVSS v.2 Version",
        default=""
    )
    cvssv3_attack_complexity = peewee.TextField(
        verbose_name="CVSS v.3 Attack Complexity Metrics",
        default=""
    )
    cvssv3_attack_vector = peewee.TextField(
        verbose_name="CVSS v.3 Attack Vector Metrics",
        default=""
    )
    cvssv3_availability_impact = peewee.TextField(
        verbose_name="CVSS v.3 Availability Impact Metrics",
        default=""
    )
    cvssv3_base_score = peewee.TextField(
        verbose_name="CVSS v.3 Base Score Metrics",
        default=""
    )
    cvssv3_base_severity = peewee.TextField(
        verbose_name="CVSS v.3 Base Severity Metrics",
        default=""
    )
    cvssv3_confidentiality_impact = peewee.TextField(
        verbose_name="CVSS v.3 Confidentiality Impact Metrics",
        default=""
    )
    cvssv3_exploitability_score = peewee.TextField(
        verbose_name="CVSS v.3 Exploitability Score Metrics",
        default=""
    )
    cvssv3_impact_score = peewee.TextField(
        verbose_name="CVSS v.3 Impact Score Metrics",
        default=""
    )
    cvssv3_integrity_impact = peewee.TextField(
        verbose_name="CVSS v.3 Integrity Impact Metrics",
        default=""
    )
    cvssv3_privileges_required = peewee.TextField(
        verbose_name="CVSS v.3 Privileges Required Metrics",
        default=""
    )
    cvssv3_scope = peewee.TextField(
        verbose_name="CVSS v.3 Scope Metrics",
        default=""
    )
    cvssv3_user_interaction = peewee.TextField(
        verbose_name="CVSS v.3 User Interaction Metrics",
        default=""
    )
    cvssv3_vector_string = peewee.TextField(
        verbose_name="CVSS v.3 Vector String",
        default=""
    )
    cvssv3_version = peewee.TextField(
        verbose_name="CVSS v.3 Version",
        default=""
    )

    def __unicode__(self):
        return "CVES"

    def __str__(self):
        return self.item

    @property
    def data(self):
        cves_data = {}
        cves_data["id"] = self.id
        cves_data["cve"] = self.item
        cves_data["data_type"] = self.data_type
        cves_data["data_format"] = self.data_format
        cves_data["data_version"] = self.data_version
        cves_data["references"] = self.references
        cves_data["published"] = self.published
        cves_data["last_modified"] = self.last_modified
        cves_data["cpe22"] = self.cpe22
        cves_data["cpe23"] = self.cpe23
        cves_data["cwe"] = self.cwe
        cves_data["vendors"] = self.convert_list_data_from_json(self.vendors)
        return cves_data

    @staticmethod
    def convert_list_data_from_json(data):
        if isinstance(data, list):
            deserialized = []
            for element in data:
                deserialized.append(json.loads(element))
            return deserialized
        else:
            return []


CVE_VULNERS.add_index(CVE_VULNERS.item)
