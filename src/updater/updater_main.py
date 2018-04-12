import sys
import time
import peewee
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from dateutil.parser import parse as parse_datetime

from configuration import DB
from configuration import SOURCES


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
    try:
        INFO.create_table()
    except peewee.OperationalError as operation_error:
        print('INFO Table already exists')

    try:
        CWE_VULNERS.create_table()
    except peewee.OperationalError as operation_error:
        print('CWE Table already exists')

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
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CWE: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="cwe")
    info_last_modified = info.last_modified

    if info_last_modified != last_modified:
        info.last_modified = last_modified
        info.save()

        parser.parse(data)

        for cwe in cwe_handler.cwe:
            cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
            parsed_items.append(cwe)

        for item in progressbar(parsed_items, prefix="Update Database CWE: "):
            id = "CWE-" + item["id"]
            print(id)
            cwe, created = CWE_VULNERS.get_or_create(item=id)
            cwe.item = id
            cwe.name = item["name"]
            cwe.status=item["status"]
            cwe.weaknessabs=item["weaknessabs"]
            cwe.description_summary=item["description_summary"]
            cwe.save()
        stop_time = time.time()
        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CWE: Complete."
        )
    return dict(
        items=0,
        time_delta=0,
        message="Update Database CWE: Not modified"
    )

def action_update_cpe():
    database.connect()
    try:
        INFO.create_table()
    except peewee.OperationalError as operation_error:
        print('INFO Table already exists')

    try:
        CPE_VULNERS.create_table()
    except peewee.OperationalError as operation_error:
        print('CPE Table already exists')

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
        return dict(
            items=0,
            time_delta=0,
            message='Update Database CPE: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="cpe")
    info_last_modified = info.last_modified

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
            id = item["id"]
            print(id)
            cpe = CPE_VULNERS.get_or_none(CPE_VULNERS.item == id)
            if cpe is None:
                cpe = CPE_VULNERS.insert(
                    item=str(id),
                    title=item["title"],
                    refs=item.get("references", []),
                    cpe22=item["cpe_2_2"],
                    cpe23=str(id)
                ).execute()
            else:
                cpe = CPE_VULNERS.update(
                    item=str(id),
                    title=item["title"],
                    refs=item.get("references", []),
                    cpe22=item["cpe_2_2"],
                    cpe23=str(id)
                ).execute()
                pass
        stop_time = time.time()
        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database CWE: Complete."
        )
    return dict(
        items=0,
        time_delta=0,
        message="Update Database CPE: Not modified"
    )

def action_update_d2sec():
    database.connect()
    try:
        INFO.create_table()
    except peewee.OperationalError as operation_error:
        print('INFO Table already exists')

    try:
        D2SEC_VULNERS.create_table()

    except peewee.OperationalError as operation_error:
        print('D2SEC Table already exists')

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
        return dict(
            items=0,
            time_delta=0,
            message='Update Database D2SEC: Cant download file: {}'.format(source)
        )

    last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

    info, created = INFO.get_or_create(name="d2sec")
    info_last_modified = info.last_modified

    if info_last_modified != last_modified:
        info.last_modified = last_modified
        info.save()

        parser.parse(data)

        for item in progressbar(ch.d2sec, prefix="Update Database D2SEC: "):
            parsed_items.append(item)
            id = item["id"]
            print(id)
            d2sec, created = D2SEC_VULNERS.get_or_create(item=id)
            d2sec.item = str(id)
            d2sec.name = str(item["name"])
            d2sec.url = str(item["url"])
            d2sec.save()
            # d2sec = D2SEC_VULNERS.get_or_none(D2SEC_VULNERS.item == id)
            # if d2sec is None:
            #     print('+')
            #     d2sec = D2SEC_VULNERS.insert(
            #         item=str(id),
            #         name=item["name"],
            #         url=item.get("url", ""),
            #     ).execute()
            # else:
            #     print('-')
            #     d2sec = D2SEC_VULNERS.update(
            #         item=str(id),
            #         name=item["name"],
            #         url=item.get("url", ""),
            #     ).execute()
        stop_time = time.time()
        return dict(
            items=len(parsed_items),
            time_delta=stop_time - start_time,
            message="Update Database D2SEC: Complete."
        )
    return dict(
        items=0,
        time_delta=0,
        message="Update Database D2SEC: Not modified"
    )


if __name__ == '__main__':
    # print(action_update_cwe())
    print(action_update_d2sec())
    # print(action_update_cpe())
    # print(CPE_VULNERS.get_or_none(item='123'))


    pass