SOURCES = {
    "cve_modified": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz",
    "cve_recent": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz",
    "cve_base": "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-",
    "cve_base_postfix": ".json.gz",
    "cpe22": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip",
    "cpe23": "https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip",
    "cwe": "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip",
    "capec": "http://capec.mitre.org/data/xml/capec_v2.6.xml",
    "ms": "http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx",
    "d2sec": "http://www.d2sec.com/exploits/elliot.xml",
    "npm": "https://api.nodesecurity.io/advisories",
}

START_YEAR = 2018

POSTGRES = {
    "user": 'admin',
    "password": '123',
    "database": "updater_db",
    "host": "localhost",
    "port": "5432"
}

