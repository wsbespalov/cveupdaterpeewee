import os
import time
import json
import peewee
import requests
from xml.sax import make_parser

from datetime import datetime

from configuration import POSTGRES
from configuration import SOURCES

from utils import progressbar

from model_info import INFO
from model_npm import NPM_VULNERS

from capec_updater import CapecHandler


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

advisories_url = SOURCES["npm"]


def download_npm_file(api_data):
    # type: (dict) -> bool
    """
    Download file from server,
    """
    url = api_data['url']
    local_file_name = url.split('/')[-1] + '.json'
    try:
        upload_result = requests.get(url, allow_redirects=True)
        with open(local_file_name, 'wb') as f:
            for chunk in upload_result.iter_content(chunk_size=1024):
                f.write(chunk)
        api_data['local_file_name'] = local_file_name
        return True
    except Exception as common_exception:
        print('Get an exception {0}'.format(common_exception))
        api_data['local_file_name'] = None
        return False


def is_downloadable_as_file(api_data):
    # type: (dict) -> bool
    """
    Check if file is downloadable from URL.
    """
    url = api_data['url']
    h = requests.head(url, allow_redirects=True)
    header = h.headers
    content_type = header.get('content-type')
    api_data['content_type'] = content_type
    content_length = header.get('content-length', None)
    api_data['content_length'] = content_length
    if 'text' in content_type.lower():
        return False
    if 'html' in content_type.lower():
        return False
    return True


def get_nodesecurity_advisories_json_from_server(api_data):
    # type: (dict) -> bool
    """
    Upload json from nodesecurity.io
    """
    api_data['url'] = advisories_url
    if is_downloadable_as_file(api_data):
        result = download_npm_file(api_data)
        local_file = api_data['local_file_name']
        if result:
            if local_file is not None:
                with open(local_file, 'r') as fp:
                    try:
                        content = json.load(fp)
                        api_data['source'] = content
                        return True
                    except Exception as common_exception:
                        print('JSON parsing exception: {0}'.format(common_exception))
                        api_data['source'] = None
                        return False
                    finally:
                        if os.path.isfile(local_file):
                            os.remove(local_file)
    api_data['source'] = None
    return False


def action_update_npm():
    database.connect()

    INFO.create_table()

    NPM_VULNERS.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    ch = CapecHandler()
    parser.setContentHandler(ch)

    data = {}
    data['source'] = None
    if get_nodesecurity_advisories_json_from_server(data):
        if data['source'] is not None:
            if 'results' in data['source']:
                parsed_items = data['source']['results']

        info, created = INFO.get_or_create(name="npm")

        now = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

        info.last_modified = now
        info.save()

        for item in progressbar(parsed_items, prefix="Update Database NPM: "):
            item_id = "NPM-" + str(item["id"])
            item_created_at = item.get("created_at", now) if item.get("created_at", now) is not None else ""
            item_updated_at = item.get("updated_at", now) if item.get("updated_at", now) is not None else ""
            item_title = item.get("title", "") if item.get("title", "") is not None else ""
            item_author = item.get("author", "") if item.get("author", "") is not None else ""
            item_module_name = item.get("module_name", "") if item.get("module_name", "") is not None else ""
            item_publish_date = item.get("publish_date", "") if item.get("publish_date", "") is not None else ""
            item_cves = item.get("cves", []) if item.get("cves", []) is not None else []
            item_vulnerable_versions = item.get("item_vulnerable_versions", "") if item.get("item_vulnerable_versions",
                                                                                            "") is not None else ""
            item_patched_versions = item.get("patched_versions", "") if item.get("patched_versions",
                                                                                 "") is not None else ""
            item_slug = item.get("slug", "") if item.get("slug", "") is not None else ""
            item_overview = item.get("overview", "") if item.get("overview", "") is not None else ""
            item_recommendation = item.get("recommendation", "") if item.get("recommendation", "") is not None else ""
            item_references = item.get("references", "") if item.get("references", "") is not None else ""
            item_legacy_slug = item.get("legacy_slug", "") if item.get("legacy_slug", "") is not None else ""
            item_allowed_scopes = item.get("allowed_scopes", []) if item.get("allowed_scopes", []) is not None else []
            item_cvss_vector = item.get("cvss_vector", "") if item.get("cvss_vector", "") is not None else ""
            item_cvss_score = item.get("cvss_score", "") if item.get("cvss_score", "") is not None else ""
            item_cwe = item.get("cwe", "") if item.get("cwe", "") is not None else ""
            item_cwe = ''.join(filter(lambda x: x.isdigit(), item_cwe))
            item_cwe = "CWE-" + item_cwe

            npm_selected = NPM_VULNERS.get_or_none(NPM_VULNERS.item == item_id)

            if npm_selected is None:
                capec_created = NPM_VULNERS(
                    item=item_id,
                    created_at=item_created_at,
                    updated_at=item_updated_at,
                    title=item_title,
                    author=item_author,
                    module_name=item_module_name,
                    publish_date=item_publish_date,
                    cves=item_cves,
                    vulnerable_versions=item_vulnerable_versions,
                    patched_versions=item_patched_versions,
                    slug=item_slug,
                    overview=item_overview,
                    recomendation=item_recommendation,
                    references=item_references,
                    legacy_slug=item_legacy_slug,
                    allowed_scopes=item_allowed_scopes,
                    cvss_vector=item_cvss_vector,
                    cvss_score=item_cvss_score,
                    cwe=item_cwe
                )
                capec_created.save()

            else:
                if npm_selected.created_at == item_created_at and \
                        npm_selected.updated_at == item_updated_at and \
                        npm_selected.title == item_title and \
                        npm_selected.author == item_author and \
                        npm_selected.module_name == item_module_name and \
                        npm_selected.publish_date == item_publish_date and \
                        npm_selected.cves == item_cves and \
                        npm_selected.vulnerable_versions == item_vulnerable_versions and \
                        npm_selected.patched_versions == item_patched_versions and \
                        npm_selected.slug == item_slug and \
                        npm_selected.overview == item_overview and \
                        npm_selected.recomendation == item_recommendation and \
                        npm_selected.references == item_references and \
                        npm_selected.legacy_slug == item_legacy_slug and \
                        npm_selected.allowed_scopes == item_allowed_scopes and \
                        npm_selected.cvss_vector == item_cvss_vector and \
                        npm_selected.cvss_score == item_cvss_score and \
                        npm_selected.cwe == item_cwe:
                    pass
                else:
                    npm_selected.created_at = item_created_at
                    npm_selected.updated_at = item_updated_at
                    npm_selected.title = item_title
                    npm_selected.author = item_author
                    npm_selected.module_name = item_module_name
                    npm_selected.publish_date = item_publish_date
                    npm_selected.cves = item_cves
                    npm_selected.vulnerable_versions = item_vulnerable_versions
                    npm_selected.patched_versions = item_patched_versions
                    npm_selected.slug = item_slug
                    npm_selected.overview = item_overview
                    npm_selected.recomendation = item_recommendation
                    npm_selected.references = item_references
                    npm_selected.legacy_slug = item_legacy_slug
                    npm_selected.allowed_scopes = item_allowed_scopes
                    npm_selected.cvss_vector = item_cvss_vector
                    npm_selected.cvss_score = item_cvss_score
                    npm_selected.cwe = item_cwe
                    npm_selected.save()

        stop_time = time.time()

        database.close()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database NPM: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database NPM: Unable to get advisories from server"
    )
