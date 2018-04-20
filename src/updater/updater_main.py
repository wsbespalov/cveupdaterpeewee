import os
import sys
import json
import time
import peewee
import requests
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from dateutil.parser import parse as parse_datetime

from configuration import POSTGRES
from configuration import SOURCES

from datetime import datetime

from get_files import get_file

database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)

from model_info import INFO
from model_cwe import CWE_VULNERS
from model_npm import NPM_VULNERS
from model_cpe import CPE_VULNERS
from model_cve import CVE_VULNERS
from model_d2sec import D2SEC_VULNERS
from model_capec import CAPEC_VULNERS

advisories_url = SOURCES["npm"]


# ----------------------------------------------------------------------------
# CWE Handler
# ----------------------------------------------------------------------------

class CWEHandler(ContentHandler):
    def __init__(self):
        self.cwe = []
        self.description_summary_tag = False
        self.weakness_tag = False

    def startElement(self, name, attrs):
        if name == 'Weakness':
            self.weakness_tag = True
            self.statement = ""
            self.weaknessabs = attrs.get('Weakness_Abstraction')
            self.name = attrs.get('Name')
            self.idname = attrs.get('ID')
            self.status = attrs.get('Status')
            self.cwe.append({
                'name': self.name,
                'id': self.idname,
                'status': self.status,
                'weaknessabs': self.weaknessabs})
        elif name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = True
            self.description_summary = ""

    def characters(self, ch):
        if self.description_summary_tag:
            self.description_summary += ch.replace("       ", "")

    def endElement(self, name):
        if name == 'Description_Summary' and self.weakness_tag:
            self.description_summary_tag = False
            self.description_summary = self.description_summary + \
                                       self.description_summary
            self.cwe[-1]['description_summary'] = \
                self.description_summary.replace("\n", "")
        elif name == 'Weakness':
            self.weakness_tag = False


class CPEHandler(ContentHandler):
    """Class for CPEHandler redefinition"""

    def __init__(self):
        self.name = ""
        self.title = ""
        self.href = None
        self.cpe = []
        self.titletag = False
        self.referencetitle = ""
        self.referencestag = False
        self.referencetag = False

    def startElement(self, name, attrs):
        if name == 'cpe-item':
            self.name = ""
            self.title = ""
            self.referencetitle = ""
            self.name = attrs.get('name')
            self.cpe.append({'name': attrs.get('name'), 'title': [], 'references': []})
        elif name == 'title':
            if attrs.get('xml:lang') == 'en-US':
                self.titletag = True
        elif name == 'references':
            self.referencestag = True
        elif name == 'reference':
            self.referencetag = True
            self.href = attrs.get('href')
            self.cpe[-1]['references'].append(self.href)

    def characters(self, ch):
        if self.titletag:
            self.title += ch

    def endElement(self, name):
        if name == 'title':
            self.titletag = False
            self.cpe[-1]['title'].append(self.title.rstrip())
        elif name == 'references':
            self.referencestag = False
        elif name == 'reference':
            self.referencetag = False
            self.href = None


class ExploitHandler(ContentHandler):
    def __init__(self):
        self.d2sec = []
        self.exploittag = False
        self.elliottag = False
        self.nametag = False
        self.urltag = False
        self.reltag = False
        self.refcvetag = False
        self.tag = False
        self.refl = []

    def startElement(self, name, attrs):
        if name == 'elliot':
            self.elliottag = True
        if name == 'exploit' and self.elliottag:
            self.exploittag = True

        if self.exploittag:
            self.tag = name
            if self.tag == 'name':
                self.nametag = True
                self.name = ""
            elif self.tag == 'url':
                self.urltag = True
                self.url = ""
            elif self.tag == 'ref':
                self.reftag = True
                self.reftype = attrs.getValue('type')
                if self.reftype == 'CVE':
                    self.refcvetag = True
                    self.cveref = ""
                elif self.reftype != 'CVE':
                    self.refcvetag = False
                    self.cveref = False

    def characters(self, ch):
        if self.nametag:
            self.name += ch
        elif self.urltag:
            self.url += ch
        elif self.refcvetag:
            self.cveref += ch

    def endElement(self, name):
        if name == 'ref':
            if self.cveref != "" and self.cveref:
                self.refl.append(self.cveref.rstrip())
            self.reftag = False
        if name == 'name':
            self.nametag = False
        if name == 'url':
            self.urltag = False
        if name == 'ref':
            self.reftag = False
        if name == 'exploit':
            for refl in self.refl:
                self.d2sec.append({
                    'name': self.name,
                    'url': self.url,
                    'id': refl})
            self.exploittag = False
            self.refl = []
        if name == 'elliot':
            self.elliottag = False


class CapecHandler(ContentHandler):

    def __init__(self):
        self.capec = []
        self.Attack_Pattern_Catalog_tag = False
        self.Attack_Patterns_tag = False
        self.Attack_Pattern_tag = False
        self.Description_tag = False
        self.Summary_tag = False
        self.Text_tag = False
        self.Attack_Prerequisites_tag = False
        self.Attack_Prerequisite_tag = False
        self.Solutions_and_Mitigations_tag = False
        self.Solution_or_Mitigation_tag = False
        self.Related_Weaknesses_tag = False
        self.Related_Weakness_tag = False
        self.CWE_ID_tag = False

        self.tag = False

        self.id = ""
        self.name = ""

        self.Summary_ch = ""
        self.Attack_Prerequisite_ch = ""
        self.Solution_or_Mitigation_ch = ""
        self.CWE_ID_ch = ""

        self.Summary = []
        self.Attack_Prerequisite = []
        self.Solution_or_Mitigation = []
        self.Related_Weakness = []

    def startElement(self, name, attrs):

        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = True
        if name == 'capec:Attack_Patterns' and self.Attack_Pattern_Catalog_tag:
            self.Attack_Patterns_tag = True
        if name == 'capec:Attack_Pattern' and self.Attack_Patterns_tag:
            self.Attack_Pattern_tag = True

        if self.Attack_Pattern_tag:
            self.tag = name
            if self.tag == 'capec:Attack_Pattern':
                self.id = attrs.getValue('ID')
                self.name = attrs.getValue('Name')

            if self.tag == 'capec:Description':
                self.Description_tag = True
            if name == 'capec:Summary' and self.Description_tag:
                self.Summary_tag = True
            if name == 'capec:Text' and self.Summary_tag:
                self.Text_tag = True
                self.Summary_ch = ""

            if self.tag == 'capec:Attack_Prerequisites':
                self.Attack_Prerequisites_tag = True
            if name == 'capec:Attack_Prerequisite' and \
                    self.Attack_Prerequisites_tag:
                self.Attack_Prerequisite_tag = True
            if name == 'capec:Text' and self.Attack_Prerequisite_tag:
                self.Text_tag = True
                self.Attack_Prerequisite_ch = ""

            if self.tag == 'capec:Solutions_and_Mitigations':
                self.Solutions_and_Mitigations_tag = True
            if name == 'capec:Solution_or_Mitigation' and \
                    self.Solutions_and_Mitigations_tag:
                self.Solution_or_Mitigation_tag = True
            if name == 'capec:Text' and self.Solution_or_Mitigation_tag:
                self.Text_tag = True
                self.Solution_or_Mitigation_ch = ""

            if self.tag == 'capec:Related_Weaknesses':
                self.Related_Weaknesses_tag = True
            if name == 'capec:Related_Weakness' and \
                    self.Related_Weaknesses_tag:
                self.Related_Weakness_tag = True
            if name == 'capec:CWE_ID' and self.Related_Weakness_tag:
                self.CWE_ID_tag = True
                self.CWE_ID_ch = ""

    def characters(self, ch):
        if self.Text_tag:
            if self.Summary_tag:
                self.Summary_ch += ch
            elif self.Attack_Prerequisite_tag:
                self.Attack_Prerequisite_ch += ch
            elif self.Solution_or_Mitigation_tag:
                self.Solution_or_Mitigation_ch += ch
        elif self.CWE_ID_tag:
            self.CWE_ID_ch += ch

    def endElement(self, name):
        if name == 'capec:Summary':
            if self.Summary_ch != "":
                self.Summary_ch = ""
            self.Summary_tag = False
        if name == 'capec:Attack_Prerequisite':
            if self.Attack_Prerequisite_ch != "":
                self.Attack_Prerequisite.append(
                    self.Attack_Prerequisite_ch.rstrip())
            self.Attack_Prerequisite_tag = False
        if name == 'capec:Solution_or_Mitigation':
            if self.Solution_or_Mitigation_ch != "":
                self.Solution_or_Mitigation.append(
                    self.Solution_or_Mitigation_ch.rstrip())
            self.Solution_or_Mitigation_tag = False
        if name == 'capec:Related_Weakness':
            if self.CWE_ID_ch != "":
                self.Related_Weakness.append(self.CWE_ID_ch.rstrip())
            self.Related_Weakness_tag = False

        if name == 'capec:Description':
            self.Description_tag = False
        if name == 'capec:Attack_Prerequisites':
            self.Attack_Prerequisites_tag = False
        if name == 'capec:Solutions_and_Mitigations':
            self.Solutions_and_Mitigations_tag = False
        if name == 'capec:Related_Weaknesses':
            self.Related_Weaknesses_tag = False

        if name == 'capec:Text':
            if self.Summary_tag:
                self.Summary.append(self.Summary_ch.rstrip())
            self.Text_tag = False
        if name == 'capec:CWE_ID':
            self.CWE_ID_tag = False
        if name == 'capec:Attack_Pattern':
            self.capec.append({
                'name': self.name,
                'id': self.id,
                'summary': '\n'.join(self.Summary),
                'prerequisites': '\n'.join(self.Attack_Prerequisite),
                'solutions': '\n'.join(self.Solution_or_Mitigation),
                'related_weakness': self.Related_Weakness})
            self.Summary = []
            self.Attack_Prerequisite = []
            self.Solution_or_Mitigation = []
            self.Related_Weakness = []

            self.Attack_Pattern_tag = False
        if name == 'capec:Attack_Patterns':
            self.Attack_Patterns_tag = False
        if name == 'capec:Attack_Pattern_Catalog':
            self.Attack_Pattern_Catalog_tag = False


class Item(object):

    def __init__(self, data):
        """
        Parse JSON data structure for ONE item
        :param data: (dict) - Item to parse
        """
        cve = data.get("cve", {})
        self.data_type = cve.get("data_type", None)  # Data type CVE
        self.data_format = cve.get("data_format", None)  # Data format MITRE
        self.data_version = cve.get("data_version", None)  # Data version like 4.0
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.id = CVE_data_meta.get("ID", None)  # ID like CVE-2002-2446
        affects = cve.get("affects", {})
        vendor = affects.get("vendor", {})

        # GET Related VENDORs

        self.vendor_data = []  # VENDOR data (different TABLE)

        vdata = vendor.get("vendor_data", [])

        for vd in vdata:
            vendor_name = vd.get("vendor_name", None)  # vendor name - one value - VENDOR
            product = vd.get("product", {})
            product_data = product.get("product_data", [])

            for pd in product_data:
                product_name = pd.get("product_name", None)  # product name - list of products for VENDOR
                version = pd.get("version", {})
                version_data = version.get("version_data", [])

                for vd in version_data:
                    version_value = vd.get("version_value", None)  # version value list of versions for PRODUCT

                    # create json set

                    if version_value is not None and product_name is not None and vendor_name is not None:
                        jtemplate = dict(
                            vendor=vendor_name,
                            product=product_name,
                            version=version_value
                        )
                        self.vendor_data.append(jtemplate)
                        del jtemplate

        # GET CWEs

        self.cwe = []  # CWE data (different TABLE)

        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])

        for pd in problemtype_data:
            description = pd.get("description", [])

            for d in description:
                value = d.get("value", None)
                if value is not None:
                    self.cwe.append(value)

        # GET RREFERENCEs

        self.references = []  # REFERENCES

        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])

        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                self.references.append(url)

        # GET DESCRIPTION

        self.description = ""

        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])

        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value

        # GET CPEs                                                  # CPES (different TABLE)

        self.cpe22 = []
        self.cpe23 = []

        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])

        for n in nodes:
            cpe = n.get("cpe", [])

            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                c23 = c.get("cpe23Uri", None)

                self.cpe22.append(c22)
                self.cpe23.append(c23)

        impact = data.get("impact", {})

        # GET CVSSV2                                                # CVSSV2 (different TABLE ???)

        self.cvssv2 = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.cvssv2["version"] = cvssV2.get("version", "")
        self.cvssv2["vectorString"] = cvssV2.get("vectorString", "")
        self.cvssv2["accessVector"] = cvssV2.get("accessVector", "")
        self.cvssv2["accessComplexity"] = cvssV2.get("accessComplexity", "")
        self.cvssv2["authentication"] = cvssV2.get("authentication", "")
        self.cvssv2["confidentialityImpact"] = cvssV2.get("confidentialityImpact", "")
        self.cvssv2["integrityImpact"] = cvssV2.get("integrityImpact", "")
        self.cvssv2["availabilityImpact"] = cvssV2.get("availabilityImpact", "")
        self.cvssv2["baseScore"] = cvssV2.get("baseScore", "")
        self.cvssv2["severity"] = baseMetricV2.get("severity", "")
        self.cvssv2["exploitabilityScore"] = baseMetricV2.get("exploitabilityScore", "")
        self.cvssv2["impactScore"] = baseMetricV2.get("impactScore", "")
        self.cvssv2["obtainAllPrivilege"] = baseMetricV2.get("obtainAllPrivilege", "")
        self.cvssv2["obtainUserPrivilege"] = baseMetricV2.get("obtainUserPrivilege", "")
        self.cvssv2["obtainOtherPrivilege"] = baseMetricV2.get("obtainOtherPrivilege", "")
        self.cvssv2["userInteractionRequired"] = baseMetricV2.get("userInteractionRequired", "")

        # GET CVSSV3                                                # CVSSV3 (different TABLE ???)

        self.cvssv3 = {}
        baseMetricV3 = impact.get("baseMetricV3", {})
        cvssV3 = baseMetricV3.get("cvssV3", {})
        self.cvssv3["version"] = cvssV3.get("version", "")
        self.cvssv3["vectorString"] = cvssV3.get("vectorString", "")
        self.cvssv3["attackVector"] = cvssV3.get("attackVector", "")
        self.cvssv3["attackComplexity"] = cvssV3.get("attackComplexity", "")
        self.cvssv3["privilegesRequired"] = cvssV3.get("privilegesRequired", "")
        self.cvssv3["userInteraction"] = cvssV3.get("userInteraction", "")
        self.cvssv3["scope"] = cvssV3.get("scope", "")
        self.cvssv3["confidentialityImpact"] = cvssV3.get("confidentialityImpact", "")
        self.cvssv3["integrityImpact"] = cvssV3.get("integrityImpact", "")
        self.cvssv3["availabilityImpact"] = cvssV3.get("availabilityImpact", "")
        self.cvssv3["baseScore"] = cvssV3.get("baseScore", "")
        self.cvssv3["baseSeverity"] = cvssV3.get("baseSeverity", "")
        self.cvssv3["exploitabilityScore"] = baseMetricV3.get("exploitabilityScore", "")
        self.cvssv3["impactScore"] = baseMetricV3.get("impactScore", "")

        # GET Dates

        self.publishedDate = data.get("publishedDate", datetime.utcnow())
        self.lastModifiedDate = data.get("lastModifiedDate", datetime.utcnow())

    def to_json(self):
        return json.dumps(self,
                          default=lambda o: o.__dict__,
                          sort_keys=True)


def to_string_formatted_cpe(cpe, autofill=False):
    """Convert CPE to formatted string"""
    cpe = cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'):
            return False
        cpe = cpe.replace('cpe:/', 'cpe:2.3:')
        cpe = cpe.replace('::', ':-:')
        cpe = cpe.replace('~-', '~')
        cpe = cpe.replace('~', ':-:')
        cpe = cpe.replace('::', ':')
        cpe = cpe.strip(':-')
    if autofill:
        element = cpe.split(':')
        for _ in range(0, 13 - len(element)):
            cpe += ':-'
    return cpe


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


def download_cve_modified_file():
    file_stream, response_info = get_file(SOURCES["cve_modified"])
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"]
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_modified_file(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(Item(item).to_json())
    return parsed_items


def download_cve_recent_file():
    file_stream, response_info = get_file(SOURCES["cve_recent"])
    try:
        result = json.load(file_stream)
        if "CVE_Items" in result:
            return result["CVE_Items"]
        return None
    except json.JSONDecodeError as json_error:
        print('Get an JSON decode error: {}'.format(json_error))
        return None


def parse_cve_recent_file(items=None):
    if items is None:
        items = []
    parsed_items = []
    for item in items:
        parsed_items.append(Item(item).to_json())
    return parsed_items


def convert_list_data_to_json(data):
    if isinstance(data, list):
        serialized = []
        for element in data:
            serialized.append(json.dumps(element))
        return serialized
    else:
        return []


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

# ----------------------------------------------------------------------------
# ACTION: UPDATE CWE Database
# ----------------------------------------------------------------------------


def action_update_cwe():
    database.connect()

    INFO.create_table()

    CWE_VULNERS.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    cwe_handler = CWEHandler()
    parser.setContentHandler(cwe_handler)

    source = SOURCES["cwe"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database CWE: Cant download file: {}'.format(source))
        database.close()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CWE: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="cwe")
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

        parser.parse(data)

        for cwe in cwe_handler.cwe:
            cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
            parsed_items.append(cwe)

        for item in progressbar(parsed_items, prefix="Update Database CWE: "):
            item_id = "CWE-" + item["id"]

            item_name = item.get("name", "")
            item_status = item.get("status", "")
            item_weaknessabs = item.get("weaknessabs", "")
            item_description_summary = item.get("description_summary", "")

            cwe_selected = CWE_VULNERS.get_or_none(CWE_VULNERS.item == item_id)

            if cwe_selected is None:
                cwe_created = CWE_VULNERS(
                    item=item_id,
                    name=item_name,
                    status=item_status,
                    weaknessabs=item_weaknessabs,
                    description_summary=item_description_summary
                )
                cwe_created.save()

            else:
                if cwe_selected.name == item_name and \
                        cwe_selected.status == item_status and \
                        cwe_selected.weaknessabs == item_weaknessabs and \
                        cwe_selected.description_summary == item_description_summary:
                    pass
                else:
                    cwe_selected.name = item_name
                    cwe_selected.status = item_status
                    cwe_selected.weaknessabs = item_weaknessabs
                    cwe_selected.description_summary = item_description_summary
                    cwe_selected.save()

        stop_time = time.time()

        database.close()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CWE: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CWE: Not modified"
    )


# ----------------------------------------------------------------------------
# ACTION: UPDATE CPE Database
# ----------------------------------------------------------------------------

def action_update_cpe():
    database.connect()

    INFO.create_table()

    CPE_VULNERS.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    cpe_handler = CPEHandler()
    parser.setContentHandler(cpe_handler)

    source = SOURCES["cpe22"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database CPE: Cant download file: {}'.format(source))
        database.close()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CPE: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="cpe")
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

        parser.parse(data)

        for cpe in cpe_handler.cpe:
            cpe["id"] = to_string_formatted_cpe(cpe["name"])
            cpe['title'] = cpe['title'][0]
            cpe['cpe_2_2'] = cpe.pop('name')
            if not cpe['references']:
                cpe.pop('references')
            parsed_items.append(cpe)

        for item in progressbar(parsed_items, prefix="Update Database CPE: "):
            item_id = item["id"]
            item_title = item.get("title", "")
            item_refs = item.get("references", [])
            item_cpe22 = item.get("cpe_2_2", "")
            item_cpe23 = item_id

            cpe_selected = CPE_VULNERS.get_or_none(CPE_VULNERS.item == item_id)

            if cpe_selected is None:
                cpe_created = CPE_VULNERS(
                    item=item_id,
                    title=item_title,
                    refs=item_refs,
                    cpe22=item_cpe22,
                    cpe23=item_cpe23
                )
                cpe_created.save()

            else:
                if cpe_selected.title == item_title and \
                        cpe_selected.refs == item_refs and \
                        cpe_selected.cpe22 == item_cpe22 and \
                        cpe_selected.cpe23 == item_cpe23:
                    pass

                else:
                    cpe_selected.title = item_title,
                    cpe_selected.refs = item_refs,
                    cpe_selected.cpe22 = item_cpe22,
                    cpe_selected.cpe23 = item_cpe23
                    cpe_selected.save()

        stop_time = time.time()

        database.close()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CPE: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CPE: Not modified"
    )


# ----------------------------------------------------------------------------
# ACTION: UPDATE D2SEC Database
# ----------------------------------------------------------------------------

def action_update_d2sec():
    database.connect()

    INFO.create_table()

    D2SEC_VULNERS.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    ch = ExploitHandler()
    parser.setContentHandler(ch)

    source = SOURCES["d2sec"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database D2SEC: Cant download file: {}'.format(source))
        database.close()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database D2SEC: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="d2sec")
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

        parser.parse(data)

        for item in progressbar(ch.d2sec, prefix="Update Database D2SEC: "):
            parsed_items.append(item)
            item_id = item["id"]
            item_name = item.get("name", "")
            item_url = item.get("url", "")

            d2sec_selected = D2SEC_VULNERS.get_or_none(D2SEC_VULNERS.item == item_id)

            if d2sec_selected is None:
                d2sec_created = D2SEC_VULNERS(
                    item=item_id,
                    name=item_name,
                    url=item_url
                )
                d2sec_created.save()
            else:
                if d2sec_selected.name == item_name and \
                        d2sec_selected.url == item_url:
                    pass
                else:
                    d2sec_selected.name = item_name
                    d2sec_selected.url = item_url
                    d2sec_selected.save()

        stop_time = time.time()

        database.close()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database D2SEC: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database D2SEC: Not modified"
    )


# ----------------------------------------------------------------------------
# ACTION: UPDATE CAPEC Database
# ----------------------------------------------------------------------------

def action_update_capec():
    database.connect()

    INFO.create_table()

    CAPEC_VULNERS.create_table()

    start_time = time.time()
    parsed_items = []

    parser = make_parser()
    ch = CapecHandler()
    parser.setContentHandler(ch)

    source = SOURCES["capec"]

    try:
        data, response = get_file(getfile=source)
    except:
        print('Update Database CAPEC: Cant download file: {}'.format(source))
        database.close()
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CAPEC: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="capec")
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

        parser.parse(data)

        for item in progressbar(ch.capec, prefix="Update Database CAPEC: "):
            parsed_items.append(item)
            item_id = "CAPEC-" + item["id"]
            item_name = item.get("name", "")
            item_summary = item.get("summary", "")
            item_prerequisites = item.get("prerequisites", "")
            item_solutions = item.get("solutions", "")
            item_related_weakness = item.get("related_weakness", [])

            for i in range(0, len(item_related_weakness)):
                item_related_weakness[i] = ''.join(filter(lambda x: x.isdigit(), item_related_weakness[i]))
                item_related_weakness[i] = 'CWE-' + item_related_weakness[i]

            capec_selected = CAPEC_VULNERS.get_or_none(CAPEC_VULNERS.item == item_id)

            if capec_selected is None:
                capec_created = CAPEC_VULNERS(
                    item=item_id,
                    name=item_name,
                    summary=item_summary,
                    prerequisites=item_prerequisites,
                    solutions=item_solutions,
                    related_weakness=item_related_weakness
                )
                capec_created.save()

            else:
                if capec_selected.name == item_name and \
                        capec_selected.summary == item_summary and \
                        capec_selected.prerequisites == item_prerequisites and \
                        capec_selected.solutions == item_solutions and \
                        capec_selected.related_weakness == item_related_weakness:
                    pass
                else:
                    capec_selected.name = item_name
                    capec_selected.summary = item_summary
                    capec_selected.prerequisites = item_prerequisites
                    capec_selected.solutions = item_solutions
                    capec_selected.related_weakness = item_related_weakness
                    capec_selected.save()

        stop_time = time.time()

        database.close()

        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CAPEC: Complete."
        )

    database.close()

    return dict(
        items=0,
        time_delta=0,
        message="Update Database CAPEC: Not modified"
    )

# ----------------------------------------------------------------------------
# ACTION: UPDATE NPM Database
# ----------------------------------------------------------------------------


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


# ----------------------------------------------------------------------------
# ACTION: UPDATE CVE Database
# ----------------------------------------------------------------------------


def action_update_cve():
    database.connect()

    INFO.create_table()

    CVE_VULNERS.create_table()

    start_time = time.time()
    now = datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

    count = 0

    modified_items = download_cve_modified_file()
    modified_parsed = parse_cve_modified_file(modified_items)

    recent_items = download_cve_recent_file()
    recent_parsed = parse_cve_recent_file(recent_items)

    for item in progressbar(modified_parsed, prefix="Update Database MODIFIED: "):
        count += 1

        item = json.loads(item)

        item_id = "MODIFIED-" + item["id"]
        item_data_format = item.get("data_format", "")
        item_data_type = item.get("data_type", "")
        item_data_version = item.get("data_version", "")
        item_description = item.get("description", "")
        item_last_modified_date = item.get("lastModifiedDate", now)
        item_published_date = item.get("publishedDate", now)
        item_references = item.get("references", [])
        item_vendor_data = item.get("vendor_data", [])
        item_cpe22 = item.get("cpe22", [])
        item_cpe23 = item.get("cpe23", [])
        item_cwe = item.get("cwe", [])

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

        modified_selected = CVE_VULNERS.get_or_none(CVE_VULNERS.item == item_id)

        if modified_selected is None:
            modified_created = CVE_VULNERS(
                item=item_id,
                data_format=item_data_format,
                data_type=item_data_type,
                data_version=item_data_version,
                description=item_description,
                last_modified=item_last_modified_date,
                published=item_published_date,
                references=item_references,
                vendors=convert_list_data_to_json(item_vendor_data),
                cpe22=item_cpe22,
                cpe23=item_cpe23,
                cwe=item_cwe,
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
            modified_created.save()
        else:
            if modified_selected.data["data_format"] == item_data_format and \
                    modified_selected.data["data_type"] == item_data_type and \
                    modified_selected.data["data_version"] == item_data_version and \
                    modified_selected.data["description"] == item_description and \
                    unify_time(modified_selected.data["last_modified"]) == unify_time(item_last_modified_date) and \
                    unify_time(modified_selected.data["published"]) == unify_time(item_published_date) and \
                    modified_selected.data["references"] == item_references and \
                    modified_selected.data["vendors"] == item_vendor_data and \
                    modified_selected.data["cpe22"] == item_cpe22 and \
                    modified_selected.data["cpe23"] == item_cpe23 and \
                    modified_selected.data["cwe"] == item_cwe and \
                    modified_selected.data["cvssv2_access_complexity"] == item_cvssv2_access_complexity and \
                    modified_selected.data["cvssv2_access_vector"] == item_cvssv2_access_vector and \
                    modified_selected.data["cvssv2_authentication"] == item_cvssv2_authentication and \
                    modified_selected.data["cvssv2_availability_impact"] == item_cvssv2_availability_impact and \
                    modified_selected.data["cvssv2_base_score"] == str(item_cvssv2_base_score) and \
                    modified_selected.data["cvssv2_confidentiality_impact"] == item_cvssv2_confidentiality_impact and \
                    modified_selected.data["cvssv2_exploitability_score"] == str(item_cvssv2_exploitability_score) and \
                    modified_selected.data["cvssv2_impact_score"] == str(item_cvssv2_impact_score) and \
                    modified_selected.data["cvssv2_integrity_impact"] == item_cvssv2_integrity_impact and \
                    unify_bool(modified_selected.data["cvssv2_obtain_all_privilege"]) == unify_bool(item_cvssv2_obtain_all_privilege) and \
                    unify_bool(modified_selected.data["cvssv2_obtain_other_privilege"]) == unify_bool(item_cvssv2_obtain_other_privilege) and \
                    unify_bool(modified_selected.data["cvssv2_obtain_user_privilege"]) == unify_bool(item_cvssv2_obtain_user_privilege) and \
                    modified_selected.data["cvssv2_severity"] == item_cvssv2_severity and \
                    unify_bool(modified_selected.data["cvssv2_user_interaction_required"]) == unify_bool(item_cvssv2_user_interaction_required) and \
                    modified_selected.data["cvssv2_vector_string"] == item_cvssv2_vector_string and \
                    modified_selected.data["cvssv2_version"] == item_cvssv2_version and \
                    modified_selected.data["cvssv3_attack_complexity"] == item_cvssv3_attack_complexity and \
                    modified_selected.data["cvssv3_attack_vector"] == item_cvssv3_attack_vector and \
                    modified_selected.data["cvssv3_availability_impact"] == item_cvssv3_availability_impact and \
                    modified_selected.data["cvssv3_base_score"] == str(item_cvssv3_base_score) and \
                    modified_selected.data["cvssv3_base_severity"] == item_cvssv3_base_severity and \
                    modified_selected.data["cvssv3_confidentiality_impact"] == item_cvssv3_confidentiality_impact and \
                    modified_selected.data["cvssv3_exploitability_score"] == str(item_cvssv3_exploitability_score) and \
                    modified_selected.data["cvssv3_impact_score"] == str(item_cvssv3_impact_score) and \
                    modified_selected.data["cvssv3_integrity_impact"] == item_cvssv3_integrity_impact and \
                    modified_selected.data["cvssv3_privileges_required"] == item_cvssv3_privileges_required and \
                    modified_selected.data["cvssv3_scope"] == item_cvssv3_scope and \
                    modified_selected.data["cvssv3_user_interaction"] == item_cvssv3_user_interaction and \
                    modified_selected.data["cvssv3_vector_string"] == item_cvssv3_vector_string and \
                    modified_selected.data["cvssv3_version"] == item_cvssv3_version:
                pass
            else:
                modified_selected.data_format = item_data_format
                modified_selected.data_type = item_data_type
                modified_selected.data_version = item_data_version
                modified_selected.description = item_description
                modified_selected.last_modified = unify_time(item_last_modified_date)
                modified_selected.published = unify_time(item_published_date)
                modified_selected.references = item_references
                modified_selected.vendors = convert_list_data_to_json(item_vendor_data)
                modified_selected.cpe22 = item_cpe22
                modified_selected.cpe23 = item_cpe23
                modified_selected.cwe = item_cwe
                modified_selected.cvssv2_access_complexity = item_cvssv2_access_complexity
                modified_selected.cvssv2_access_vector = item_cvssv2_access_vector
                modified_selected.cvssv2_authentication = item_cvssv2_authentication
                modified_selected.cvssv2_availability_impact = item_cvssv2_availability_impact
                modified_selected.cvssv2_base_score = item_cvssv2_base_score
                modified_selected.cvssv2_confidentiality_impact = item_cvssv2_confidentiality_impact
                modified_selected.cvssv2_exploitability_score = item_cvssv2_exploitability_score
                modified_selected.cvssv2_impact_score = item_cvssv2_impact_score
                modified_selected.cvssv2_integrity_impact = item_cvssv2_integrity_impact
                modified_selected.cvssv2_obtain_all_privilege = unify_bool(item_cvssv2_obtain_all_privilege)
                modified_selected.cvssv2_obtain_other_privilege = unify_bool(item_cvssv2_obtain_other_privilege)
                modified_selected.cvssv2_obtain_user_privilege = unify_bool(item_cvssv2_obtain_user_privilege)
                modified_selected.cvssv2_severity = item_cvssv2_severity
                modified_selected.cvssv2_user_interaction_required = unify_bool(item_cvssv2_user_interaction_required)
                modified_selected.cvssv2_vector_string = item_cvssv2_vector_string
                modified_selected.cvssv2_version = item_cvssv2_version
                modified_selected.cvssv3_attack_complexity = item_cvssv3_attack_complexity
                modified_selected.cvssv3_attack_vector = item_cvssv3_attack_vector
                modified_selected.cvssv3_availability_impact = item_cvssv3_availability_impact
                modified_selected.cvssv3_base_score = item_cvssv3_base_score
                modified_selected.cvssv3_base_severity = item_cvssv3_base_severity
                modified_selected.cvssv3_confidentiality_impact = item_cvssv3_confidentiality_impact
                modified_selected.cvssv3_exploitability_score = item_cvssv3_exploitability_score
                modified_selected.cvssv3_impact_score = item_cvssv3_impact_score
                modified_selected.cvssv3_integrity_impact = item_cvssv3_integrity_impact
                modified_selected.cvssv3_privileges_required = item_cvssv3_privileges_required
                modified_selected.cvssv3_scope = item_cvssv3_scope
                modified_selected.cvssv3_user_interaction = item_cvssv3_user_interaction
                modified_selected.cvssv3_vector_string = item_cvssv3_vector_string
                modified_selected.cvssv3_version = item_cvssv3_version
                modified_selected.save()
                pass

    for item in progressbar(recent_parsed, prefix="Update Database RECENT: "):
        count += 1

        item = json.loads(item)

        item_id = "RECENT-" + item["id"]
        item_data_format = item.get("data_format", "")
        item_data_type = item.get("data_type", "")
        item_data_version = item.get("data_version", "")
        item_description = item.get("description", "")
        item_last_modified_date = item.get("lastModifiedDate", now)
        item_published_date = item.get("publishedDate", now)
        item_references = item.get("references", [])
        item_vendor_data = item.get("vendor_data", [])
        item_cpe22 = item.get("cpe22", [])
        item_cpe23 = item.get("cpe23", [])
        item_cwe = item.get("cwe", [])

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

        recent_selected = CVE_VULNERS.get_or_none(CVE_VULNERS.item == item_id)

        if recent_selected is None:
            recent_selected = CVE_VULNERS(
                item=item_id,
                data_format=item_data_format,
                data_type=item_data_type,
                data_version=item_data_version,
                description=item_description,
                last_modified=item_last_modified_date,
                published=item_published_date,
                references=item_references,
                vendors=convert_list_data_to_json(item_vendor_data),
                cpe22=item_cpe22,
                cpe23=item_cpe23,
                cwe=item_cwe,
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
            recent_selected.save()
        else:
            if recent_selected.data["data_format"] == item_data_format and \
                    recent_selected.data["data_type"] == item_data_type and \
                    recent_selected.data["data_version"] == item_data_version and \
                    recent_selected.data["description"] == item_description and \
                    unify_time(recent_selected.data["last_modified"]) == unify_time(item_last_modified_date) and \
                    unify_time(recent_selected.data["published"]) == unify_time(item_published_date) and \
                    recent_selected.data["references"] == item_references and \
                    recent_selected.data["vendors"] == item_vendor_data and \
                    recent_selected.data["cpe22"] == item_cpe22 and \
                    recent_selected.data["cpe23"] == item_cpe23 and \
                    recent_selected.data["cwe"] == item_cwe and \
                    recent_selected.data["cvssv2_access_complexity"] == item_cvssv2_access_complexity and \
                    recent_selected.data["cvssv2_access_vector"] == item_cvssv2_access_vector and \
                    recent_selected.data["cvssv2_authentication"] == item_cvssv2_authentication and \
                    recent_selected.data["cvssv2_availability_impact"] == item_cvssv2_availability_impact and \
                    recent_selected.data["cvssv2_base_score"] == str(item_cvssv2_base_score) and \
                    recent_selected.data["cvssv2_confidentiality_impact"] == item_cvssv2_confidentiality_impact and \
                    recent_selected.data["cvssv2_exploitability_score"] == str(item_cvssv2_exploitability_score) and \
                    recent_selected.data["cvssv2_impact_score"] == str(item_cvssv2_impact_score) and \
                    recent_selected.data["cvssv2_integrity_impact"] == item_cvssv2_integrity_impact and \
                    unify_bool(recent_selected.data["cvssv2_obtain_all_privilege"]) == unify_bool(item_cvssv2_obtain_all_privilege) and \
                    unify_bool(recent_selected.data["cvssv2_obtain_other_privilege"]) == unify_bool(item_cvssv2_obtain_other_privilege) and \
                    unify_bool(recent_selected.data["cvssv2_obtain_user_privilege"]) == unify_bool(item_cvssv2_obtain_user_privilege) and \
                    recent_selected.data["cvssv2_severity"] == item_cvssv2_severity and \
                    unify_bool(recent_selected.data["cvssv2_user_interaction_required"]) == unify_bool(item_cvssv2_user_interaction_required) and \
                    recent_selected.data["cvssv2_vector_string"] == item_cvssv2_vector_string and \
                    recent_selected.data["cvssv2_version"] == item_cvssv2_version and \
                    recent_selected.data["cvssv3_attack_complexity"] == item_cvssv3_attack_complexity and \
                    recent_selected.data["cvssv3_attack_vector"] == item_cvssv3_attack_vector and \
                    recent_selected.data["cvssv3_availability_impact"] == item_cvssv3_availability_impact and \
                    recent_selected.data["cvssv3_base_score"] == str(item_cvssv3_base_score) and \
                    recent_selected.data["cvssv3_base_severity"] == item_cvssv3_base_severity and \
                    recent_selected.data["cvssv3_confidentiality_impact"] == item_cvssv3_confidentiality_impact and \
                    recent_selected.data["cvssv3_exploitability_score"] == str(item_cvssv3_exploitability_score) and \
                    recent_selected.data["cvssv3_impact_score"] == str(item_cvssv3_impact_score) and \
                    recent_selected.data["cvssv3_integrity_impact"] == item_cvssv3_integrity_impact and \
                    recent_selected.data["cvssv3_privileges_required"] == item_cvssv3_privileges_required and \
                    recent_selected.data["cvssv3_scope"] == item_cvssv3_scope and \
                    recent_selected.data["cvssv3_user_interaction"] == item_cvssv3_user_interaction and \
                    recent_selected.data["cvssv3_vector_string"] == item_cvssv3_vector_string and \
                    recent_selected.data["cvssv3_version"] == item_cvssv3_version:
                pass
            else:
                recent_selected.data_format = item_data_format
                recent_selected.data_type = item_data_type
                recent_selected.data_version = item_data_version
                recent_selected.description = item_description
                recent_selected.last_modified = unify_time(item_last_modified_date)
                recent_selected.published = unify_time(item_published_date)
                recent_selected.references = item_references
                recent_selected.vendors = convert_list_data_to_json(item_vendor_data)
                recent_selected.cpe22 = item_cpe22
                recent_selected.cpe23 = item_cpe23
                recent_selected.cwe = item_cwe
                recent_selected.cvssv2_access_complexity = item_cvssv2_access_complexity
                recent_selected.cvssv2_access_vector = item_cvssv2_access_vector
                recent_selected.cvssv2_authentication = item_cvssv2_authentication
                recent_selected.cvssv2_availability_impact = item_cvssv2_availability_impact
                recent_selected.cvssv2_base_score = item_cvssv2_base_score
                recent_selected.cvssv2_confidentiality_impact = item_cvssv2_confidentiality_impact
                recent_selected.cvssv2_exploitability_score = item_cvssv2_exploitability_score
                recent_selected.cvssv2_impact_score = item_cvssv2_impact_score
                recent_selected.cvssv2_integrity_impact = item_cvssv2_integrity_impact
                recent_selected.cvssv2_obtain_all_privilege = unify_bool(item_cvssv2_obtain_all_privilege)
                recent_selected.cvssv2_obtain_other_privilege = unify_bool(item_cvssv2_obtain_other_privilege)
                recent_selected.cvssv2_obtain_user_privilege = unify_bool(item_cvssv2_obtain_user_privilege)
                recent_selected.cvssv2_severity = item_cvssv2_severity
                recent_selected.cvssv2_user_interaction_required = unify_bool(item_cvssv2_user_interaction_required)
                recent_selected.cvssv2_vector_string = item_cvssv2_vector_string
                recent_selected.cvssv2_version = item_cvssv2_version
                recent_selected.cvssv3_attack_complexity = item_cvssv3_attack_complexity
                recent_selected.cvssv3_attack_vector = item_cvssv3_attack_vector
                recent_selected.cvssv3_availability_impact = item_cvssv3_availability_impact
                recent_selected.cvssv3_base_score = item_cvssv3_base_score
                recent_selected.cvssv3_base_severity = item_cvssv3_base_severity
                recent_selected.cvssv3_confidentiality_impact = item_cvssv3_confidentiality_impact
                recent_selected.cvssv3_exploitability_score = item_cvssv3_exploitability_score
                recent_selected.cvssv3_impact_score = item_cvssv3_impact_score
                recent_selected.cvssv3_integrity_impact = item_cvssv3_integrity_impact
                recent_selected.cvssv3_privileges_required = item_cvssv3_privileges_required
                recent_selected.cvssv3_scope = item_cvssv3_scope
                recent_selected.cvssv3_user_interaction = item_cvssv3_user_interaction
                recent_selected.cvssv3_vector_string = item_cvssv3_vector_string
                recent_selected.cvssv3_version = item_cvssv3_version
                recent_selected.save()
                pass

    stop_time = time.time()

    database.close()

    return dict(
        items=count,
        time_delta=stop_time - start_time,
        message="Update Database CVE: Complete."
    )


if __name__ == '__main__':
    # print(action_update_cwe())
    # print(action_update_d2sec())
    # print(action_update_cpe())

    # capec -> related_weakness -> array ID of CWE
    # capec -> related_weakness -> links

    # print(action_update_capec())

    # print(action_update_npm())
    print((action_update_cve()))

    pass
