import time
import peewee
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from datetime import datetime
from dateutil.parser import parse as parse_datetime

from configuration import POSTGRES
from configuration import SOURCES

from get_files import get_file
from utils import progressbar, to_string_formatted_cpe

from model_info import INFO
from model_cpe import CPE_VULNERS


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


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
