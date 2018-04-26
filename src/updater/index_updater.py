import time
import redis
import peewee

from configuration import REDIS
from configuration import POSTGRES

from utils import progressbar

from model_vulners import VULNERABILITIES


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

cache = redis.StrictRedis(
    host=REDIS["host"],
    port=REDIS["port"],
    db=REDIS["database"]
)

cache_indexer_collection_mask = REDIS["collections"]["vulnerabilities"]


def action_make_index_for_vulnerabilities_table():
    start_time = time.time()
    result = dict(
        time_delta=0,
        items=0,
        message="Start"
    )
    database.connect()
    count = 0

    # Clear cache

    for key in cache.keys(cache_indexer_collection_mask):
        cache.delete(key)
    print("Cache clear")

    # Get All rows from VULNER Table
    all_vulnerabilities = VULNERABILITIES.select()
    print("All VULNERABILITIES selected")

    for one_vulner in progressbar(all_vulnerabilities):
        one_vulner_data = one_vulner.data
        component = one_vulner_data["component"]
        version = one_vulner_data["version"]

        new_collection_name = ''.join([
            cache_indexer_collection_mask,
            component,
            "::",
            version
        ])

        dictionary = dict(
            component=component,
            version=version,
            vuln_id=one_vulner_data["id"]
        )

        cache.hmset(
            new_collection_name,
            dictionary
        )


    result["time_delta"] = time.time() - start_time
    result["items"] = count
    result["message"] = "Complete"

    database.close()
    return result


def find_component_in_cache_index(component, version=None):
    result = None
    query = cache_indexer_collection_mask
    if component is not None:
        query += component
        query += "::"
        if version is not None:
            query += version
        else:
            query += "*"
        record = cache.hgetall(
            query
        )
        result = dict(
            component=record
        )
    return result
