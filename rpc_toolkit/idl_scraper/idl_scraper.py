# Akamai RPC Toolkit
# Copyright 2022 Akamai Technologies, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in
# compliance with the License.  You may obtain a copy
# of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing
# permissions and limitations under the License.

import argparse
import json
import logging
import os
import re
import requests
from tqdm import tqdm
from bs4 import BeautifulSoup
from posixpath import join as path_urljoin

##################### GLOBALS #####################

WINDOWS_PROTOCOLS_URL = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols'
TECHNICAL_DOCS_URL = 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winprotlp/e36c976a-6263-42a8-b119-7a3cc41ddd2a'
DEFAULT = 'DEFAULT'


def get_protocol_names():
    """
    Fetch the list of protocol names from Microsoft's technical documents page.
    """
    html = requests.get(TECHNICAL_DOCS_URL).content
    soup = BeautifulSoup(html, 'html.parser')
    table_rows = soup.find('table').find("tbody").find_all("tr")
    idl_names = []
    for row in table_rows:
        left_cell = row.find('td')
        a = left_cell.find('a')
        assert(a['data-linktype'] == 'relative-path')
        relative_url = left_cell.find('a')['href']
        name, uuid = relative_url.split('/')[1:]
        idl_names.append(name)
    return idl_names


def get_toc_items_from_protocol_name(protocol_name):
    """
    Fetch the table of contents JSON file for a specific protocol, and return its "items" list.
    This is the first step towards getting the URLs for all relvant IDL files.
    """
    toc_url = path_urljoin(WINDOWS_PROTOCOLS_URL, protocol_name, 'toc.json')
    toc_page = requests.get(toc_url).content
    return json.loads(toc_page).get('items', None)


def get_dicts_rec(array):
    """
    Recursively yields all dicationary objects from the table of content JSON.
    This is a helper function for get_idl_page_uuids_from_toc_items().
    """
    for element in array:
        yield(element)
        if 'children' in element:
            for child in get_dicts_rec(element['children']):
                yield(child)


def get_idl_page_uuids_from_toc_items(items):
    """
    Fetch the UUIDs of the pages where IDL files are documented.
    These are *not* the UUIDs of the interfaces! :) Just pages identifiers.
    """
    idl_page_uuids = {}
    for item in get_dicts_rec(items):
        toc_title = item.get('toc_title', '')
        if 'Full IDL' in toc_title and 'children' not in item:
            # This is the case when only a single IDL is present for the protocol.
            # Mark this IDL page as DEFAULT.
            idl_page_uuids[DEFAULT] = item.get('href', '')
        elif toc_title.endswith('.idl'):
            # This is the case where multiple IDL files are present for the protocol.
            try:
                idl_name = re.search('(\w+).idl', toc_title).group(1)
                idl_page_uuids[idl_name] = item.get('href', '')
            except AttributeError:
                logging.error(f'could not fetch IDL name from TOC. toc_title = {toc_title}')
    return idl_page_uuids


def generate_urls_from_uuids(protocol_name, idl_uuids):
    result = {}
    for name, uuid in idl_uuids.items():
        result[name] = path_urljoin(WINDOWS_PROTOCOLS_URL, protocol_name, uuid)
    return result


def get_idl_urls(protocol_name):
    toc_items = get_toc_items_from_protocol_name(protocol_name)
    if not toc_items:
        logging.error(f'could not find TOC items for protocol {protocol_name}')
        return
    idl_page_uuids = get_idl_page_uuids_from_toc_items(toc_items)
    if not idl_page_uuids:
        logging.info(f'no IDL UUIDs in the ToC for protocol {protocol_name}')
        return
    return generate_urls_from_uuids(protocol_name, idl_page_uuids)


def get_idl_from_url(idl_url):
    idl_page = requests.get(idl_url).content
    idl_soup = BeautifulSoup(idl_page, 'html.parser')
    dds = idl_soup.find_all('dd')
    if len(dds) > 0:  # Found an IDL code blob
        idl_text = '\n'.join(dd.find('pre').get_text() for dd in dds)  # Sometimes the code appears across multiple frames :(
        return idl_text.replace('\xa0', ' ')  # There's this stupid character which is in fact single-space


def download_protocol_idls(protocol_name, output):
    num_files_saved = 0
    idl_urls = get_idl_urls(protocol_name)
    if not idl_urls:
        return num_files_saved
    for idl_name, idl_url in idl_urls.items():
        file_name = protocol_name if idl_name == DEFAULT else idl_name
        idl_file = get_idl_from_url(idl_url)
        if not idl_file:
            logging.error(f'could not fetch an IDL from {idl_url}')
            return num_files_saved
        with open(path_urljoin(output, f'{file_name}.idl'), 'w') as f:
            try:
                f.write(idl_file)
                num_files_saved +=1 
            except (TypeError, AttributeError) as e:
                logging.error(f'failed to write a file for protocol {protocol_name}, IDL URL = {idl_url}, error = {e}')
    return num_files_saved


def download_all_protocols_idls(output):
    protocols = get_protocol_names()
    status = {}
    logging.info(f'{len(protocols)} protocols to go!')
    for protocol_name in tqdm(protocols):
        status[protocol_name] = download_protocol_idls(protocol_name, output)
    logging.info(f'Protocols\' Status: {status}')


def get_args():
    parser = argparse.ArgumentParser(description='Download all IDL files available in Microsoft\'s technical documents')
    parser.add_argument('-o', '--output', help='path to output folder for all IDL files', default='IDLFiles')
    parser.add_argument('-p', '--protocol', help='name of protocol whose IDL to download, e.g. "ms-tsch"')
    return parser.parse_args()


def set_logging():
    logger = logging.getLogger()
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler('msdn_idl_scraper.log')
    formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s %(message)s')
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.WARNING)


if __name__ == '__main__':
    set_logging()
    args = get_args()
    protocol = args.protocol
    output = args.output
    if output and not os.path.exists(output):
        os.makedirs(output)
    if protocol:
        download_protocol_idls(protocol, output)
    else:
        download_all_protocols_idls(output)
