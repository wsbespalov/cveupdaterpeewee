import time

from cwe_updater import action_update_cwe
from d2sec_updater import action_update_d2sec
from cpe_updater import action_update_cpe
from capec_updater import action_update_capec
from npm_updater import action_update_npm
from cve_updater import action_update_cve, action_populate_cve
from vulnerabilities_updater import action_make_vulnerabilities_table
from index_updater import action_make_index_for_vulnerabilities_table, find_component_in_cache_index


if __name__ == '__main__':
    # print(action_update_cwe())
    # print(action_update_d2sec())
    # print(action_update_cpe())

    # capec -> related_weakness -> array ID of CWE
    # capec -> related_weakness -> links

    # print(action_update_capec())

    # print(action_update_npm())
    # print(action_update_cve())
    # print(action_populate_cve())

    print(action_make_vulnerabilities_table())
    print(action_make_index_for_vulnerabilities_table())

    start_time = time.time()

    print(find_component_in_cache_index(component="solaris", version="2.6"))

    print('Job time: {}'.format(time.time() - start_time))

    pass
