import peewee

import configuration as config

# database = peewee.SqliteDatabase(config.DB.get("name", "db.sqlite"))

from configuration import POSTGRES

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

class INFO(peewee.Model):
    class Meta:
        database = database
        table_name = "info"

    name = peewee.TextField(
        default="",
        verbose_name="Collection name"
    )
    last_modified = peewee.TextField(
        default="",
        verbose_name="Last modified time"
    )
    def __unicode__(self):
        return "INFO"
    @property
    def data(self):
        info_data = {}
        info_data["id"] = self.id
        info_data["name"] = self.name
        info_data["last_modified"] = self.last_modified
        return info_data
    def save(self, *args, **kwargs):
        super(INFO, self).save(*args, **kwargs)