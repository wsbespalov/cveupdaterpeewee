import peewee
from playhouse.postgres_ext import ArrayField

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
)

class CPE_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "cpe_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        default="",
        verbose_name="CPE ID"
    )
    title = peewee.TextField(
        default="",
        verbose_name="CPE Title"
    )
    refs = ArrayField(
        peewee.TextField,
    )
    cpe22 = peewee.TextField(
        default="",
        verbose_name="CPE 2.2 Metrics"
    )
    cpe23 = peewee.TextField(
        default="",
        verbose_name="CPE 2.3 Metrics"
    )
    def __unicode__(self):
        return "CPE"
    def __str__(self):
        return self.item
    @property
    def data(self):
        cpe_data = {}
        cpe_data["id"] = self.id
        cpe_data["item"] = self.item
        cpe_data["title"] = self.title
        cpe_data["references"] = self.refs
        cpe_data["cpe22"] = self.cpe22
        cpe_data["cpe23"] = self.cpe23
        return cpe_data
CPE_VULNERS.add_index(CPE_VULNERS.item)