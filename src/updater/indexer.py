import sys
import time
import peewee
import redis
import json
import cpe

from configuration import POSTGRES
from model_cpe import CPE_VULNERS

# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------

postgres_database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

REDIS = {
    "host": "localhost",
    "port": 6379,
    "database": 1,
    "collections": {
        "npm": {
            "item": "indexer:npm:item",
            "module": "indexer:npm:module"
        },
        "cpe": {
            "index": "indexer::cpe::",
        }
    }
}

# ----------------------------------------------------------------------------
# Cache
# ----------------------------------------------------------------------------

indexer_database = redis.StrictRedis(
    host=REDIS["host"],
    port=REDIS["port"],
    db=REDIS["database"]
)


class Indexer(object):

    def __init__(self):
        self.cache = indexer_database
        self.collection = REDIS["collections"]["cpe"]["index"]

    def make_index_for_cpe(self):
        items = CPE_VULNERS.select()
        print("All CPE Items selected")
        prefix = "Process {} elements".format(len(items))


        for item in progressbar(it=items, prefix=prefix):
            item_info = filter_cpe_2_3_string(item.data)
            if item_info["component"] is not None and \
                    item_info["version"] is not None and \
                    item_info["id"] != 0:

                new_collection_name = ''.join([
                    self.collection,
                    item_info["component"],
                    "::",
                    item_info['version']
                ])

                self.cache.set(
                    new_collection_name,
                    item_info["id"]
                )

                pass

        pass

    def find_component_directly(self, component_name=None, component_version=None):
        result = []
        query = self.collection
        if component_name is not None:
            query += component_name
            if component_version is not None:
                query += "::"
                query += component_version
            else:
                query += '*'
            keys = self.cache.keys(query)
            if len(keys) > 0:
                for k in keys:
                    result.append(self.cache.get(k))
        return result

# ----------------------------------------------------------------------------
# Filtering
# ----------------------------------------------------------------------------

def filter_cpe_2_3_string(element):
    result = {
        "id": 0,
        "component": None,
        "version": None
    }

    item = element.get("cpe22", None)
    result["id"] = element.get("id", 0)

    if item is not None:
        try:
            c22 = cpe.CPE(item, cpe.CPE.VERSION_2_2)
        except ValueError as value_error:
            try:
                c22 = cpe.CPE(item, cpe.CPE.VERSION_UNDEFINED)
            except NotImplementedError as not_implemented_error:
                c22 = None

        c22_product = c22.get_product() if c22 is not None else []
        c22_version = c22.get_version() if c22 is not None else []
        result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
        result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None

    return result

# ----------------------------------------------------------------------------
# Progressbar
# ----------------------------------------------------------------------------

def progressbar(it, prefix="Processing ", size=50):
    count = len(it)
    def _show(_i):
        if count != 0 and sys.stdout.isatty():
            x = int(size * _i / count)
            sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, " " * (size - x), _i, count))
            sys.stdout.flush()
    _show(0)
    for i, item in enumerate(it):
        yield item
        _show(i + 1)
    sys.stdout.write("\n")
    sys.stdout.flush()


def main():

    indexer = Indexer()
    # indexer.make_index_for_cpe()

    # component = 'zulip_server'
    # version = '1.3.3'
    component = 'tomcat'
    # version = '8.0'
    version = None

    start_time = time.time()
    print(indexer.find_component_directly(component_name=component, component_version=version))
    print('Job time: {}'.format(time.time() - start_time))

    return 0

if __name__ == '__main__':
    sys.exit(main())