import time
import peewee
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

from datetime import datetime
from dateutil.parser import parse as parse_datetime

from configuration import POSTGRES
from configuration import SOURCES

from get_files import get_file
from utils import progressbar

from model_info import INFO
from model_d2sec import D2SEC_VULNERS


database = peewee.PostgresqlDatabase(
    POSTGRES.get("database", "updater_db"),
    user=POSTGRES.get("user", "postgres"),
    password=POSTGRES.get("password", "password"),
    host=POSTGRES.get("host", "localhost"),
    port=int(POSTGRES.get("port", 5432))
)


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
