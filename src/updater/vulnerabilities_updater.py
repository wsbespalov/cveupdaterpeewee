import time
import json
import peewee
import cpe as cpe_module

from configuration import POSTGRES

from utils import progressbar, convert_list_data_to_json

from model_vulners import VULNERABILITIES
from model_cve import CVE_VULNERS
from model_cwe import CWE_VULNERS
from model_capec import CAPEC_VULNERS


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


def action_make_vulnerabilities_table():
    def filter_cpe_string(element):
        result = {
            "component": None,
            "version": None
        }

        try:
            c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_2)
        except ValueError as value_error:
            try:
                c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_2_3)
            except ValueError as another_value_error:
                try:
                    c22 = cpe_module.CPE(element, cpe_module.CPE.VERSION_UNDEFINED)
                except NotImplementedError as not_implemented_error:
                    c22 = None

        c22_product = c22.get_product() if c22 is not None else []
        c22_version = c22.get_version() if c22 is not None else []
        result["component"] = c22_product[0] if isinstance(c22_product, list) and len(c22_product) > 0 else None
        result["version"] = c22_version[0] if isinstance(c22_version, list) and len(c22_version) > 0 else None

        return result

    def search_by_component_and_version(component, version):
        return list(VULNERABILITIES.select().where(
            (VULNERABILITIES.component==component) &
            (VULNERABILITIES.version==version)
        ))

    def check_version_of_component(element):
        if str(element["component"]).__eq__(""):
            return None
        if element["version"] is not None:
            if str(element["version"]).__eq__(""):
                return None
            if str(element["version"]).__eq__("*"):
                return None
            return element
        else:
            return None

    ###

    result = dict(
        items=0,
        time_delta=0,
        message=""
    )

    database.connect()

    VULNERABILITIES.create_table()

    start_time = time.time()
    count = 0

    # Get all CVEs from table - make index table for its

    all_cves = CVE_VULNERS.select()

    # Drop VULNERABILITIES Table??? - oh, no! just update it!!!

    # For all cves
    for cve_element_in_all_cves in all_cves:
        # Get Table raw as JSON object
        cve_object_data_in_json = cve_element_in_all_cves.data

        # Get cpe 2.2 string
        cpes22_strings = cve_object_data_in_json["cpe22"]

        # Search for cpe elements in all CVEs in cpe 2.2 string
        for cpe_element_in_cpes22_string in cpes22_strings:
            # Parse this cpe string
            cpe_parsed_element = filter_cpe_string(cpe_element_in_cpes22_string)
            # Just a count of elements
            count += 1

            # find one of many cpes
            if cpe_parsed_element["component"] is not None and \
                    cpe_parsed_element["version"] is not None:

                # check, if this component:version already exists in VULNERABILITIES Table
                # method return <list>
                cpe_selected = search_by_component_and_version(
                    cpe_parsed_element["component"],
                    cpe_parsed_element["version"]
                )

                if len(cpe_selected) != 0:
                    VULNERABILITIES.delete().where(
                        (VULNERABILITIES.component == cpe_parsed_element["component"]) &
                        (VULNERABILITIES.version == cpe_parsed_element["version"])
                    )
                else:
                    pass

                # check version by filter
                if check_version_of_component(cpe_parsed_element) is None:
                    break

                # Get information from CWE

                cwe_list = list(cve_object_data_in_json["cwe"])

                # Create list of cwes from Table

                cwe_list_items = []

                # If exists
                if len(cwe_list) > 0:
                    # Get one item (Just CWE name) from cwes list
                    for cwe_i in cwe_list:
                        # Get element or None from CWE Table by CWE Name
                        cwe_selected = CWE_VULNERS.get_or_none(
                            CWE_VULNERS.item==cwe_i
                        )
                        if cwe_selected is not None:
                            cwe_list_items.append(
                                json.dumps(
                                    dict(
                                        cwe_id=cwe_i,
                                        cwe_selected_name=cwe_selected.data["name"] if cwe_selected is not None else "",
                                        cwe_selected_status=cwe_selected.data["status"] if cwe_selected is not None else "",
                                        cwe_selected_weaknessabs=cwe_selected.data["weaknessabs"] if cwe_selected is not None else "",
                                        cwe_selected_description_summary = cwe_selected.data["description_summary"] if cwe_selected is not None else "",
                                    )
                                )
                            )
                        else:
                            # Nothing to append
                            pass
                # If empty CWE List - just add one empty element
                else:
                    cwe_list_items.append(
                        json.dumps(
                            dict(
                                cwe_id="",
                                cwe_selected_name="",
                                cwe_selected_status = "",
                                cwe_selected_weaknessabs = "",
                                cwe_selected_description_summary = "",
                            )
                        )
                    )

                # Get information from CAPEC

                # Create list of CAPEC Elements
                capec_list_items = []

                # Get CAPEC ids by CWE Names
                for cwe_i in cwe_list_items:

                    id = json.loads(cwe_i).get("cwe_id", None)
                    if id is not None:
                        capec_selected = CAPEC_VULNERS.get_or_none(
                            id in CAPEC_VULNERS.related_weakness
                        )
                        if capec_selected is not None:
                            capec_list_items.append(
                                json.dumps(
                                    dict(
                                        capec_id=capec_selected.data["capec"] if capec_selected is not None else "",
                                        capec_selected_name=capec_selected.data["name"] if capec_selected is not None else "",
                                        capec_selected_summary=capec_selected.data["summary"] if capec_selected is not None else "",
                                        capec_selected_prerequisites=capec_selected.data["prerequisites"] if capec_selected is not None else "",
                                        capec_selected_solutions=capec_selected.data["solutions"] if capec_selected is not None else "",
                                    )
                                )
                            )
                        else:
                            # Noting to append
                            pass
                    else:
                        # Append empty list
                        capec_list_items.append(
                            json.dumps(
                                dict(
                                    capec_id="",
                                    capec_selected_name="",
                                    capec_selected_summary="",
                                    capec_selected_prerequisites="",
                                    capec_selected_solutions="",
                                )
                            )
                        )

                # Create if not exists

                cpe_created = VULNERABILITIES(
                    component=cpe_parsed_element["component"],
                    version=cpe_parsed_element["version"],
                    published=cve_object_data_in_json["published"],
                    modified=cve_object_data_in_json["last_modified"],
                    description=cve_object_data_in_json["description"],
                    references=cve_object_data_in_json["references"],
                    data_type=cve_object_data_in_json["data_type"],
                    data_format=cve_object_data_in_json["data_format"],
                    data_version=cve_object_data_in_json["data_version"],
                    vendors=convert_list_data_to_json(cve_object_data_in_json["vendors"]),
                    cve=cve_object_data_in_json["cve"],
                    cpe22=cpe_element_in_cpes22_string,
                    cvssv2_access_complexity=cve_object_data_in_json["cvssv2_access_complexity"],
                    cvssv2_access_vector=cve_object_data_in_json["cvssv2_access_vector"],
                    cvssv2_authentication=cve_object_data_in_json["cvssv2_authentication"],
                    cvssv2_availability_impact=cve_object_data_in_json["cvssv2_availability_impact"],
                    cvssv2_base_score=cve_object_data_in_json["cvssv2_base_score"],
                    cvssv2_confidentiality_impact=cve_object_data_in_json["cvssv2_confidentiality_impact"],
                    cvssv2_exploitability_score=cve_object_data_in_json["cvssv2_exploitability_score"],
                    cvssv2_impact_score=cve_object_data_in_json["cvssv2_impact_score"],
                    cvssv2_integrity_impact=cve_object_data_in_json["cvssv2_integrity_impact"],
                    cvssv2_obtain_all_privilege=cve_object_data_in_json["cvssv2_obtain_all_privilege"],
                    cvssv2_obtain_other_privilege=cve_object_data_in_json["cvssv2_obtain_other_privilege"],
                    cvssv2_obtain_user_privilege=cve_object_data_in_json["cvssv2_obtain_user_privilege"],
                    cvssv2_severity=cve_object_data_in_json["cvssv2_severity"],
                    cvssv2_user_interaction_required=cve_object_data_in_json["cvssv2_user_interaction_required"],
                    cvssv2_vector_string=cve_object_data_in_json["cvssv2_vector_string"],
                    cvssv2_version=cve_object_data_in_json["cvssv2_version"],
                    cvssv3_attack_complexity=cve_object_data_in_json["cvssv3_attack_complexity"],
                    cvssv3_attack_vector=cve_object_data_in_json["cvssv3_attack_vector"],
                    cvssv3_availability_impact=cve_object_data_in_json["cvssv3_availability_impact"],
                    cvssv3_base_score=cve_object_data_in_json["cvssv3_base_score"],
                    cvssv3_base_severity=cve_object_data_in_json["cvssv3_base_severity"],
                    cvssv3_confidentiality_impact=cve_object_data_in_json["cvssv3_confidentiality_impact"],
                    cvssv3_exploitability_score=cve_object_data_in_json["cvssv3_exploitability_score"],
                    cvssv3_impact_score=cve_object_data_in_json["cvssv3_impact_score"],
                    cvssv3_integrity_impact=cve_object_data_in_json["cvssv3_integrity_impact"],
                    cvssv3_privileges_required=cve_object_data_in_json["cvssv3_privileges_required"],
                    cvssv3_scope=cve_object_data_in_json["cvssv3_scope"],
                    cvssv3_user_interaction=cve_object_data_in_json["cvssv3_user_interaction"],
                    cvssv3_vector_string=cve_object_data_in_json["cvssv3_vector_string"],
                    cvssv3_version=cve_object_data_in_json["cvssv3_version"],

                    cwe=cwe_list_items,

                    capec=capec_list_items,

                )
                cpe_created.save()

            pass
        pass

    result["time_delta"] = time.time() - start_time
    result["items"] = count
    result["message"] = "Complete"

    database.close()

    return result
