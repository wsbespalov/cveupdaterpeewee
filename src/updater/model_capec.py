import peewee
from playhouse.postgres_ext import ArrayField

from configuration import POSTGRES

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)
class CAPEC_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "capec_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        unique=True,
        default="",
        verbose_name="CAPEC ID"
    )
    name = peewee.TextField(
        default="",
        verbose_name="CAPEC Name"
    )
    summary = peewee.TextField(
        default="",
        verbose_name="CAPEC Summary"
    )
    prerequisites = peewee.TextField(
        default="",
        verbose_name="CAPEC Prerequisites"
    )
    solutions = peewee.TextField(
        default="",
        verbose_name="CAPEC Solutions"
    )
    related_weakness = ArrayField(
        peewee.TextField,
        default=[],
        verbose_name="CAPEC Related Weakness"
    )
    def __unicode__(self):
        return "CAPEC"
    def __str__(self):
        return self.item
    @property
    def data(self):
        capec_data = {}
        capec_data["id"] = self.id
        capec_data["capec"] = self.item
        capec_data["name"] = self.name
        capec_data["summary"] = self.summary
        capec_data["prerequisites"] = self.prerequisites
        capec_data["solutions"] = self.solutions
        capec_data["related_weakness"] = self.related_weakness
        return capec_data
    def save(self, *args, **kwargs):
        self.item = ''.join(filter(lambda x: x.isdigit(), self.item))
        self.item = "CAPEC-" + self.item
        super(CAPEC_VULNERS, self).save(*args, **kwargs)
CAPEC_VULNERS.add_index(CAPEC_VULNERS.item)