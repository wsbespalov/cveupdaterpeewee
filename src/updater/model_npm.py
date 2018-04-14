import peewee
from playhouse.postgres_ext import ArrayField

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
)

class NPM_VULNERS(peewee.Model):
    class Meta:
        database = database
        table_name = "npm_vulners"
    id = peewee.PrimaryKeyField(
        null=False
    )
    item = peewee.TextField(
        unique=True,
        default="",
        verbose_name="NPM ID"
    )
    title = peewee.TextField(
        default="",
        verbose_name="NPM Title"
    )
    created_at = peewee.TextField(
        default="",
        verbose_name="NPM Created At"
    )
    updated_at = peewee.TextField(
        default="",
        verbose_name="NPM Updated At"
    )
    publish_date = peewee.TextField(
        default="",
        verbose_name="NPM Publish Date"
    )
    author = peewee.TextField(
        default="",
        verbose_name="NPM Vulner Author"
    )
    module_name = peewee.TextField(
        default="",
        verbose_name="NPM Module Name"
    )
    cves = ArrayField(
        peewee.TextField,
        default=[]
    )
    vulnerable_versions = peewee.TextField(
        default="",
        verbose_name="NPM Vulnerable Versions"
    )
    patched_versions = peewee.TextField(
        default="",
        verbose_name="NPM Patched Versions"
    )
    slug = peewee.TextField(
        default="",
        verbose_name="NPM Slug"
    )
    overview = peewee.TextField(
        default="",
        verbose_name="NPM Overview"
    )
    recomendation = peewee.TextField(
        default="",
        verbose_name="NPM Recomendation"
    )
    references = peewee.TextField(
        default="",
        verbose_name="NPM References"
    )
    legacy_slug = peewee.TextField(
        default="",
        verbose_name="NPM Legacy Slug"
    )
    allowed_scopes = ArrayField(
        peewee.TextField,
        default=[],
    )
    cvss_vector = peewee.TextField(
        default="",
        verbose_name="NPM CVSS Vector"
    )
    cvss_score = peewee.TextField(
        default="",
        verbose_name="NPM CVSS Score"
    )
    cwe = peewee.TextField(
        default="",
        verbose_name="NPM CWE Reference"
    )
    def __unicode__(self):
        return "NPM"
    def __str__(self):
        return self.item
    @property
    def data(self):
        npm_data = {}
        npm_data["id"] = self.id
        npm_data["item"] = self.item
        npm_data["title"] = self.title
        npm_data["created_at"] = self.created_at
        npm_data["updated_at"] = self.updated_at
        npm_data["publish_date"] = self.publish_date
        npm_data["author"] = self.author
        npm_data["module_name"] = self.module_name
        npm_data["cves"] = self.cves
        npm_data["vulnerable_versions"] = self.vulnerable_versions
        npm_data["patched_versions"] = self.patched_versions
        npm_data["slug"] = self.slug
        npm_data["overview"] = self.overview
        npm_data["recomendation"] = self.recomendation
        npm_data["references"] = self.references
        npm_data["legacy_slug"] = self.legacy_slug
        npm_data["allowed_scopes"] = self.allowed_scopes
        npm_data["cvss_vector"] = self.cvss_vector
        npm_data["cvss_score"] = self.cvss_score
        npm_data["cwe"] = self.cwe
        return npm_data
    def save(self, *args, **kwargs):
        self.item = ''.join(filter(lambda x: x.isdigit(), self.item))
        self.item = "NPM-" + self.item
        super(NPM_VULNERS, self).save(*args, **kwargs)
NPM_VULNERS.add_index(NPM_VULNERS.item)
