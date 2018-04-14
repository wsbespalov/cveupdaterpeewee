import peewee
from playhouse.postgres_ext import ArrayField

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
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
    data_type = peewee.TextField(
        default="",
        verbose_name="CVE Data Type"
    )
    data_format = peewee.TextField(
        default="",
        verbose_name="CVE Data Format"
    )
    data_version = peewee.TextField(
        default="",
        verbose_name="CVE Data Version"
    )
    assigner = peewee.TextField(
        default="",
        verbose_name="CVE ASSIGNER"
    )
    references = ArrayField(
        peewee.TextField,
        verbose_name="CVE References"
    )
    summary = peewee.TextField(
        default="",
        verbose_name='CVE Summary'
    )
    cvss = peewee.TextField(
        default="0.0",
        verbose_name='CVE Score'
    )
    published = peewee.DateTimeField(
        verbose_name="CVE Published time"
    )
    modified = peewee.DateTimeField(
        verbose_name='CVE Modified time'
    )
    last_modified = peewee.DateTimeField(
        verbose_name='CVE last modified time from server'
    )
    cvss_time = peewee.DateTimeField(
        verbose_name='CVE Score time'
    )
    cpe22 = ArrayField(
        peewee.TextField,
        verbose_name='CVE CPE 2.2 Array'
    )
    cpe23 = ArrayField(
        peewee.TextField,
        verbose_name='CVE CPE 2.3 Array'
    )
    cwe = ArrayField(
        peewee.TextField,
        verbose_name='CVEs CWE ID'
    )
    access = ArrayField(
        peewee.TextField,
        verbose_name='CVEs ACCESS Table'
    )
    impact = ArrayField(
        peewee.TextField,
        verbose_name='CVEs IMPACT Table'
    )
    vendors = ArrayField(
        peewee.TextField,
        verbose_name='CVEs VENDORS Table'
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
        cves_data["assigner"] = self.assigner
        cves_data["references"] = self.references
        cves_data["summary"] = self.summary
        cves_data["cvss"] = self.cvss
        cves_data["published"] = self.published
        cves_data["modified"] = self.modified
        cves_data["last_modified"] = self.last_modified
        cves_data["cvss_time"] = self.cvss_time
        cves_data["cpe22"] = self.cpe22
        cves_data["cpe23"] = self.cpe23
        cves_data["cwe"] = self.cwe
        cves_data["access"] = self.access
        cves_data["impact"] = self.impact
        cves_data["vendors"] = self.vendors
        return cves_data
CVE_VULNERS.add_index(CVE_VULNERS.item)