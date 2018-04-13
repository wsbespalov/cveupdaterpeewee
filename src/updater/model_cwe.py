import peewee

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
)

class CWE_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "cwe_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        unique=True,
        verbose_name="CWE ID"
    )
    name = peewee.TextField(
        default="",
        verbose_name="CWE Name"
    )
    status = peewee.TextField(
        default="",
        verbose_name="CWE Status"
    )
    weaknessabs = peewee.TextField(
        default="",
        verbose_name="CWE Weakness"
    )
    description_summary = peewee.TextField(
        default="",
        verbose_name="CWE Description"
    )
    def __unicode__(self):
        return "CWE"
    def __str__(self):
        return self.item
    @property
    def data(self):
        cwe_data = {}
        cwe_data["id"] = self.id
        cwe_data["item"] = self.item
        cwe_data["name"] = self.name
        cwe_data["status"] = self.status
        cwe_data["weaknessabs"] = self.weaknessabs
        cwe_data["description_summary"] = self.description_summary
        return cwe_data
    def save(self, *args, **kwargs):
        self.item = ''.join(filter(lambda x: x.isdigit(), self.item))
        self.item = "CWE-" + self.item
        super(CWE_VULNERS, self).save(*args, **kwargs)
CWE_VULNERS.add_index(CWE_VULNERS.item)