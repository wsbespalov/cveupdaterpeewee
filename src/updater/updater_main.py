import sys
import time
import peewee
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from dateutil.parser import parse as parse_datetime

from configuration import DB
from configuration import SOURCES

from datetime import datetime

from get_files import get_file

database = peewee.PostgresqlDatabase(
    'updater_db',
    user='postgres',
    password='password',
    host='localhost',
    port='5432'
)

from model_cwe import CWE_VULNERS
from model_info import INFO
from model_cpe import CPE_VULNERS
from model_d2sec import D2SEC_VULNERS
from model_capec import CAPEC_VULNERS

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
                    cwe_selected.status=item_status
                    cwe_selected.weaknessabs=item_weaknessabs
                    cwe_selected.description_summary=item_description_summary
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
                item_related_weakness[i] = 'CWE-'+item_related_weakness[i]

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

if __name__ == '__main__':
    # print(action_update_cwe())
    # print(action_update_d2sec())
    # print(action_update_cpe())


    # capec -> related_weakness -> array ID of CWE
    # capec -> related_weakness -> links

    print(action_update_capec())

    pass