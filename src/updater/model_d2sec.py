import peewee

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
)


class D2SEC_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "d2sec_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        default="",
        verbose_name="D2SEC ID"
    )
    name = peewee.TextField(
        default="",
        verbose_name="D2SEC Name"
    )
    url = peewee.TextField(
        default="",
        verbose_name="D2SEC Url"
    )
    def __unicode__(self):
        return "D2SEC"
    def __str__(self):
        return self.item
    @property
    def data(self):
        d2sec_data = {}
        d2sec_data["id"] = self.id
        d2sec_data["item"] = self.item
        d2sec_data["name"] = self.name
        d2sec_data["url"] = self.url
        return d2sec_data
D2SEC_VULNERS.add_index(D2SEC_VULNERS.item)