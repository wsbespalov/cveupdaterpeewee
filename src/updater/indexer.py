import sys
import time
import peewee

import redis

from configuration import POSTGRES

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

from model_npm import NPM_VULNERS


REDIS = {
    "host": "localhost",
    "port": 6379,
    "collections": {
        "npm": {
            "item": "indexer:npm:item",
            "module": "indexer:npm:module"
        }
    }
}

def make_index_for_item():
    index_collection = REDIS["collections"]["npm"]["item"]
    result = {
        "items": 0,
        "time_delta": 0,
        "message": "Complete indexing by ~item~"
    }
    start_time = time.time()



    result["time_delta"] = time.time() - start_time
    return result

def make_index_for_module_name():
    index_collection = REDIS["collections"]["npm"]["module"]
    result = {
        "items": 0,
        "time_delta": 0,
        "message": "Complete indexing by ~module~"
    }
    start_time = time.time()

    



    result["time_delta"] = time.time() - start_time
    return result

def index_it():
    database.connect()

    result = make_index_for_module_name()

    print('Indexed!!!')
    database.close()

if __name__ == "__main__":
    sys.exit(index_it())