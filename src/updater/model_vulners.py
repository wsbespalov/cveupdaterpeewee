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
    published = peewee.DateTimeField(
        verbose_name="Component published date"
    )
    modified = peewee.DateTimeField(
        verbose_name="Component modified date"
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
    cve = peewee.TextField(
        default="",
        verbose_name="Component CVE ID"
    )
    cwe = ArrayField(
        peewee.TextField,
        verbose_name='Component CVEs CWE ID',
        default=[]
    )
    cpe22 = peewee.TextField(
        default="",
        verbose_name="Component CPE 2.2 string"
    )

    def __unicode__(self):
        return "VULNERABILITIES"

    def __str__(self):
        return self.cve

    @property
    def data(self):
        vulnerability_data = {}
        vulnerability_data["id"] = self.id
        vulnerability_data["cve"] = self.cve
        vulnerability_data["cwe"] = self.cwe
        vulnerability_data["cpe22"] = self.cpe22
        vulnerability_data["references"] = self.references
        vulnerability_data["description"] = self.description
        vulnerability_data["modified"] = self.modified
        vulnerability_data["published"] = self.published
        vulnerability_data["version"] = self.version
        vulnerability_data["component"] = self.component

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