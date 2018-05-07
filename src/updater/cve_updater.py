import time
import json
import pika
import peewee

from datetime import datetime
from dateutil.parser import parse as parse_datetime

from configuration import POSTGRES
from configuration import SOURCES, START_YEAR


from get_files import get_file
from item import Item
from utils import progressbar, convert_list_data_to_json

from model_info import INFO
from model_cve import CVE_VULNERS


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


def download_cve_file(source):
    file_stream, response_info = get_file(source)
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"], response_info
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_file(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(Item(item).to_json())
    return parsed_items


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt)

    if isinstance(dt, datetime):
        return parse_datetime(str(dt))


def unify_bool(param):
    if isinstance(param, bool):
        if param is False:
            return 'false'
        elif param is True:
            return 'true'
    elif isinstance(param, str):
        if param == 'False':
            return 'false'
        elif param == 'True':
            return 'true'
        elif param == '':
            return 'false'
    elif isinstance(param, type(None)):
        return 'false'


def cve_loop(parsed_item, action='Update', db_name='CVE'):
    count = 0
    now = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

    for item in progressbar(parsed_item, prefix="{} Database {}: ".format(action, db_name)):
        count += 1

        item = json.loads(item)

        item_id = item["id"]
        item_data_format = item.get("data_format", "")
        item_data_type = item.get("data_type", "")
        item_data_version = item.get("data_version", "")
        item_description = item.get("description", "")
        item_last_modified_date = item.get("lastModifiedDate", now)
        item_published_date = item.get("publishedDate", now)

        item_references = item.get("references", [])
        item_references_json = {"data": item_references}

        item_vendor_data = item.get("vendor_data", [])
        item_vendor_data_json = {"data": item_vendor_data}

        item_cpe22 = item.get("cpe22", [])
        item_cpe22_json = {"data": item_cpe22}

        item_cpe23 = item.get("cpe23", [])
        item_cpe23_json = {"data": item_cpe23}

        item_cwe = item.get("cwe", [])
        item_cwe_json = {"data": item_cwe}

        item_cvssv2_access_complexity = item.get("cvssv2", {}).get("accessComplexity", "")
        item_cvssv2_access_vector = item.get("cvssv2", {}).get("accessVector", "")
        item_cvssv2_authentication = item.get("cvssv2", {}).get("authentication", "")
        item_cvssv2_availability_impact = item.get("cvssv2", {}).get("availabilityImpact", "")
        item_cvssv2_base_score = item.get("cvssv2", {}).get("baseScore", "")
        item_cvssv2_confidentiality_impact = item.get("cvssv2", {}).get("confidentialityImpact", "")
        item_cvssv2_exploitability_score = item.get("cvssv2", {}).get("exploitabilityScore", "")
        item_cvssv2_impact_score = item.get("cvssv2", {}).get("impactScore", "")
        item_cvssv2_integrity_impact = item.get("cvssv2", {}).get("integrityImpact", "")
        item_cvssv2_obtain_all_privilege = item.get("cvssv2", {}).get("obtainAllPrivilege", "false")
        item_cvssv2_obtain_other_privilege = item.get("cvssv2", {}).get("obtainOtherPrivilege", 'false')
        item_cvssv2_obtain_user_privilege = item.get("cvssv2", {}).get("obtainUserPrivilege", 'false')
        item_cvssv2_severity = item.get("cvssv2", {}).get("severity", "")
        item_cvssv2_user_interaction_required = item.get("cvssv2", {}).get("userInteractionRequired", 'false')
        item_cvssv2_vector_string = item.get("cvssv2", {}).get("vectorString", "")
        item_cvssv2_version = item.get("cvssv2", {}).get("version", "")

        item_cvssv3_attack_complexity = item.get("cvssv3", {}).get("attackComplexity", "")
        item_cvssv3_attack_vector = item.get("cvssv3", {}).get("attackVector", "")
        item_cvssv3_availability_impact = item.get("cvssv3", {}).get("availabilityImpact", "")
        item_cvssv3_base_score = item.get("cvssv3", {}).get("baseScore", "")
        item_cvssv3_base_severity = item.get("cvssv3", {}).get("baseSeverity", "")
        item_cvssv3_confidentiality_impact = item.get("cvssv3", {}).get("confidentialityImpact", "")
        item_cvssv3_exploitability_score = item.get("cvssv3", {}).get("exploitabilityScore", "")
        item_cvssv3_impact_score = item.get("cvssv3", {}).get("impactScore", "")
        item_cvssv3_integrity_impact = item.get("cvssv3", {}).get("integrityImpact", "")
        item_cvssv3_privileges_required = item.get("cvssv3", {}).get("privilegesRequired", "")
        item_cvssv3_scope = item.get("cvssv3", {}).get("scope", "")
        item_cvssv3_user_interaction = item.get("cvssv3", {}).get("userInteraction", "")
        item_cvssv3_vector_string = item.get("cvssv3", {}).get("vectorString", "")
        item_cvssv3_version = item.get("cvssv3", {}).get("version", "")

        selected_item = CVE_VULNERS.get_or_none(CVE_VULNERS.item == item_id)

        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        chanel = connection.channel()

        if selected_item is None:
            selected_item = CVE_VULNERS(
                item=item_id,
                data_format=item_data_format,
                data_type=item_data_type,
                data_version=item_data_version,
                description=item_description,
                last_modified=item_last_modified_date,
                published=item_published_date,
                references=json.dumps(item_references_json),
                vendors=json.dumps(item_vendor_data_json),
                cpe22=json.dumps(item_cpe22_json),
                cpe23=json.dumps(item_cpe23_json),
                cwe=json.dumps(item_cwe_json),
                cvssv2_access_complexity=item_cvssv2_access_complexity,
                cvssv2_access_vector=item_cvssv2_access_vector,
                cvssv2_authentication=item_cvssv2_authentication,
                cvssv2_availability_impact=item_cvssv2_availability_impact,
                cvssv2_base_score=item_cvssv2_base_score,
                cvssv2_confidentiality_impact=item_cvssv2_confidentiality_impact,
                cvssv2_exploitability_score=item_cvssv2_exploitability_score,
                cvssv2_impact_score=item_cvssv2_impact_score,
                cvssv2_integrity_impact=item_cvssv2_integrity_impact,
                cvssv2_obtain_all_privilege=item_cvssv2_obtain_all_privilege,
                cvssv2_obtain_other_privilege=item_cvssv2_obtain_other_privilege,
                cvssv2_obtain_user_privilege=item_cvssv2_obtain_user_privilege,
                cvssv2_severity=item_cvssv2_severity,
                cvssv2_user_interaction_required=item_cvssv2_user_interaction_required,
                cvssv2_vector_string=item_cvssv2_vector_string,
                cvssv2_version=item_cvssv2_version,
                cvssv3_attack_complexity=item_cvssv3_attack_complexity,
                cvssv3_attack_vector=item_cvssv3_attack_vector,
                cvssv3_availability_impact=item_cvssv3_availability_impact,
                cvssv3_base_score=item_cvssv3_base_score,
                cvssv3_base_severity=item_cvssv3_base_severity,
                cvssv3_confidentiality_impact=item_cvssv3_confidentiality_impact,
                cvssv3_exploitability_score=item_cvssv3_exploitability_score,
                cvssv3_impact_score=item_cvssv3_impact_score,
                cvssv3_integrity_impact=item_cvssv3_integrity_impact,
                cvssv3_privileges_required=item_cvssv3_privileges_required,
                cvssv3_scope=item_cvssv3_scope,
                cvssv3_user_interaction=item_cvssv3_user_interaction,
                cvssv3_vector_string=item_cvssv3_vector_string,
                cvssv3_version=item_cvssv3_version
            )
            selected_item.save()

            chanel.queue_declare(queue='create')
            chanel.basic_publish(exchange='', routing_key='create', body=json.dumps(item))
        else:
            if selected_item.data["data_format"] == item_data_format and \
                    selected_item.data["data_type"] == item_data_type and \
                    selected_item.data["data_version"] == item_data_version and \
                    selected_item.data["description"] == item_description and \
                    unify_time(selected_item.data["last_modified"]) == unify_time(item_last_modified_date) and \
                    unify_time(selected_item.data["published"]) == unify_time(item_published_date) and \
                    selected_item.data["references"] == item_references and \
                    selected_item.data["vendors"] == item_vendor_data and \
                    selected_item.data["cpe22"] == item_cpe22 and \
                    selected_item.data["cpe23"] == item_cpe23 and \
                    selected_item.data["cwe"] == item_cwe and \
                    selected_item.data["cvssv2_access_complexity"] == item_cvssv2_access_complexity and \
                    selected_item.data["cvssv2_access_vector"] == item_cvssv2_access_vector and \
                    selected_item.data["cvssv2_authentication"] == item_cvssv2_authentication and \
                    selected_item.data["cvssv2_availability_impact"] == item_cvssv2_availability_impact and \
                    selected_item.data["cvssv2_base_score"] == str(item_cvssv2_base_score) and \
                    selected_item.data["cvssv2_confidentiality_impact"] == item_cvssv2_confidentiality_impact and \
                    selected_item.data["cvssv2_exploitability_score"] == str(item_cvssv2_exploitability_score) and \
                    selected_item.data["cvssv2_impact_score"] == str(item_cvssv2_impact_score) and \
                    selected_item.data["cvssv2_integrity_impact"] == item_cvssv2_integrity_impact and \
                    unify_bool(selected_item.data["cvssv2_obtain_all_privilege"]) == unify_bool(
                item_cvssv2_obtain_all_privilege) and \
                    unify_bool(selected_item.data["cvssv2_obtain_other_privilege"]) == unify_bool(
                item_cvssv2_obtain_other_privilege) and \
                    unify_bool(selected_item.data["cvssv2_obtain_user_privilege"]) == unify_bool(
                item_cvssv2_obtain_user_privilege) and \
                    selected_item.data["cvssv2_severity"] == item_cvssv2_severity and \
                    unify_bool(selected_item.data["cvssv2_user_interaction_required"]) == unify_bool(
                item_cvssv2_user_interaction_required) and \
                    selected_item.data["cvssv2_vector_string"] == item_cvssv2_vector_string and \
                    selected_item.data["cvssv2_version"] == item_cvssv2_version and \
                    selected_item.data["cvssv3_attack_complexity"] == item_cvssv3_attack_complexity and \
                    selected_item.data["cvssv3_attack_vector"] == item_cvssv3_attack_vector and \
                    selected_item.data["cvssv3_availability_impact"] == item_cvssv3_availability_impact and \
                    selected_item.data["cvssv3_base_score"] == str(item_cvssv3_base_score) and \
                    selected_item.data["cvssv3_base_severity"] == item_cvssv3_base_severity and \
                    selected_item.data["cvssv3_confidentiality_impact"] == item_cvssv3_confidentiality_impact and \
                    selected_item.data["cvssv3_exploitability_score"] == str(item_cvssv3_exploitability_score) and \
                    selected_item.data["cvssv3_impact_score"] == str(item_cvssv3_impact_score) and \
                    selected_item.data["cvssv3_integrity_impact"] == item_cvssv3_integrity_impact and \
                    selected_item.data["cvssv3_privileges_required"] == item_cvssv3_privileges_required and \
                    selected_item.data["cvssv3_scope"] == item_cvssv3_scope and \
                    selected_item.data["cvssv3_user_interaction"] == item_cvssv3_user_interaction and \
                    selected_item.data["cvssv3_vector_string"] == item_cvssv3_vector_string and \
                    selected_item.data["cvssv3_version"] == item_cvssv3_version:
                pass
            else:
                selected_item.data_format = item_data_format
                selected_item.data_type = item_data_type
                selected_item.data_version = item_data_version
                selected_item.description = item_description
                selected_item.last_modified = unify_time(item_last_modified_date)
                selected_item.published = unify_time(item_published_date)
                selected_item.references = item_references
                selected_item.vendors = convert_list_data_to_json(item_vendor_data)
                selected_item.cpe22 = item_cpe22
                selected_item.cpe23 = item_cpe23
                selected_item.cwe = item_cwe
                selected_item.cvssv2_access_complexity = item_cvssv2_access_complexity
                selected_item.cvssv2_access_vector = item_cvssv2_access_vector
                selected_item.cvssv2_authentication = item_cvssv2_authentication
                selected_item.cvssv2_availability_impact = item_cvssv2_availability_impact
                selected_item.cvssv2_base_score = item_cvssv2_base_score
                selected_item.cvssv2_confidentiality_impact = item_cvssv2_confidentiality_impact
                selected_item.cvssv2_exploitability_score = item_cvssv2_exploitability_score
                selected_item.cvssv2_impact_score = item_cvssv2_impact_score
                selected_item.cvssv2_integrity_impact = item_cvssv2_integrity_impact
                selected_item.cvssv2_obtain_all_privilege = unify_bool(item_cvssv2_obtain_all_privilege)
                selected_item.cvssv2_obtain_other_privilege = unify_bool(item_cvssv2_obtain_other_privilege)
                selected_item.cvssv2_obtain_user_privilege = unify_bool(item_cvssv2_obtain_user_privilege)
                selected_item.cvssv2_severity = item_cvssv2_severity
                selected_item.cvssv2_user_interaction_required = unify_bool(item_cvssv2_user_interaction_required)
                selected_item.cvssv2_vector_string = item_cvssv2_vector_string
                selected_item.cvssv2_version = item_cvssv2_version
                selected_item.cvssv3_attack_complexity = item_cvssv3_attack_complexity
                selected_item.cvssv3_attack_vector = item_cvssv3_attack_vector
                selected_item.cvssv3_availability_impact = item_cvssv3_availability_impact
                selected_item.cvssv3_base_score = item_cvssv3_base_score
                selected_item.cvssv3_base_severity = item_cvssv3_base_severity
                selected_item.cvssv3_confidentiality_impact = item_cvssv3_confidentiality_impact
                selected_item.cvssv3_exploitability_score = item_cvssv3_exploitability_score
                selected_item.cvssv3_impact_score = item_cvssv3_impact_score
                selected_item.cvssv3_integrity_impact = item_cvssv3_integrity_impact
                selected_item.cvssv3_privileges_required = item_cvssv3_privileges_required
                selected_item.cvssv3_scope = item_cvssv3_scope
                selected_item.cvssv3_user_interaction = item_cvssv3_user_interaction
                selected_item.cvssv3_vector_string = item_cvssv3_vector_string
                selected_item.cvssv3_version = item_cvssv3_version
                selected_item.save()

                chanel.queue_declare(queue='update')
                chanel.basic_publish(exchange='', routing_key='update', body=json.dumps(item))

        chanel.close()
    return count


def action_update_cve():
    database.connect()

    INFO.create_table()

    CVE_VULNERS.create_table()

    start_time = time.time()

    count = 0

    modified_items, response = download_cve_file(SOURCES["cve_modified"])
    modified_parsed = parse_cve_file(modified_items)

    last_modified = parse_datetime(response.headers["last-modified"], ignoretz=True)

    info, created = INFO.get_or_create(name="cve-modified")
    if not created:
        if info.last_modified != "":
            info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
    else:
        info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

    if info_last_modified != last_modified:
        info.last_modified = last_modified
        info.save()

        count += cve_loop(modified_parsed, db_name="MODIFIED")

    recent_items, response = download_cve_file(SOURCES["cve_recent"])
    recent_parsed = parse_cve_file(recent_items)

    last_modified = parse_datetime(response.headers["last-modified"], ignoretz=True)

    info, created = INFO.get_or_create(name="cve-recent")
    if not created:
        if info.last_modified != "":
            info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
    else:
        info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

    if info_last_modified != last_modified:
        info.last_modified = last_modified
        info.save()

        count += cve_loop(recent_parsed, db_name="RECENT")

        stop_time = time.time()

        database.close()

        return dict(
            items=count,
            time_delta=stop_time - start_time,
            message="Update Database CVE: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CVE: Not modified"
    )


def action_populate_cve():
    database.connect()

    INFO.create_table()

    CVE_VULNERS.create_table()

    start_time = time.time()

    count = 0

    current_year = datetime.now().year

    for year in range(START_YEAR, current_year+1):

        print("Populate CVE-{}".format(year))

        source = SOURCES["cve_base"] + str(year) + SOURCES["cve_base_postfix"]
        cve_item, response = download_cve_file(source)

        if response.code != 200:
            print("Populate CVE-{}: Failed download".format(year))

        parsed_cve_item = parse_cve_file(cve_item)

        last_modified = parse_datetime(response.headers["last-modified"], ignoretz=True)

        info, created = INFO.get_or_create(name="cve-{}".format(year))
        if not created:
            if info.last_modified != "":
                info_last_modified = datetime.strptime(info.last_modified, '%Y-%m-%d %H:%M:%S')
            else:
                info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
        else:
            info_last_modified = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

        if info_last_modified != last_modified:
            info.last_modified = last_modified
            info.save()

            count += cve_loop(parsed_cve_item, action="Populate", db_name="CVE-{}".format(year))

    stop_time = time.time()

    database.close()

    return dict(
        items=count,
        time_delta=stop_time - start_time,
        message="Populate Database CVE: Complete."
    )
