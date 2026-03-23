#!python3
import os
import sys
import re
import requests
import argparse
from evtx import PyEvtxParser  # https://github.com/omerbenamram/evtx/
from urllib.parse import urlparse


def evtx_to_xml(evtx_file_path):

    xml_records = []

    parser = PyEvtxParser(evtx_file_path, number_of_threads=0)
    for record in parser.records():
        cleaned_data = re.sub(r'<\?xml version="1.0" encoding="utf-8"\?>\n?', '', record['data'])
        xml_records.append(cleaned_data)


    final_xml = f'<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>\n'
    final_xml += '\n'.join(xml_records)
    final_xml += '\n</Events>'

    print(final_xml)


def check_url(url):
    try:
        response = requests.head(url)
        valid: bool = 2 <= response.status_code // 100 <= 3
        if not valid:
            print(f"Response code: {response.status_code}")
        return valid
    except Exception as e:
        print(f"Error: {e}")
        return False


def download_file(url, local_filename):
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except requests.RequestException as e:
        print(f"Error: {e}")
        # Delete the downloaded file
        if os.path.exists(local_filename):
            os.remove(local_filename)
        sys.exit(1)

    return local_filename


def main():

    parser = argparse.ArgumentParser(description='Converts EVTX files to XML.')
    parser.add_argument('evtx_file_path_or_url', help='Path to the EVTX file or URL to download it from.')

    args = parser.parse_args()

    evtx_file_path_or_url = args.evtx_file_path_or_url

    # Check if the evtx_file_path_or_url is a URL
    parsed_url = urlparse(evtx_file_path_or_url)
    isUrl = parsed_url.scheme in ['http', 'https']
    if isUrl:
        if not check_url(evtx_file_path_or_url):
            print(f"Error: URL {evtx_file_path_or_url} is not valid.")
            sys.exit(1)
        evtx_file_path_or_url = download_file(evtx_file_path_or_url, 'tmp_downloaded.evtx')
    else:
        if not os.path.exists(evtx_file_path_or_url):
            print(f"Error: File {evtx_file_path_or_url} does not exist.")
            sys.exit(1)

    try:
        evtx_to_xml(evtx_file_path_or_url)
    except Exception as e:
        print(f"Error: {e}")
        if isUrl:
            os.remove(evtx_file_path_or_url)
        sys.exit(1)

    # Delete the downloaded file
    if isUrl:
        os.remove(evtx_file_path_or_url)


if __name__ == "__main__":
    main()
