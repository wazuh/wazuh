#! python3
import os
import sys
import re
import requests
from evtx import PyEvtxParser # https://github.com/omerbenamram/evtx/
from urllib.parse import urlparse

def evtx_to_xml(evtx_file_path, xml_output_path=None):
    parser = PyEvtxParser(evtx_file_path, number_of_threads=0)
    xml_records = []
    try:
        for record in parser.records():
            cleaned_data = re.sub(r'<\?xml version="1.0" encoding="utf-8"\?>\n?', '', record['data'])
            xml_records.append(cleaned_data)
    except RuntimeError as e:
        print(f'Error: {e}')
        exit(0)

    final_xml = f'<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>\n'
    final_xml += '\n'.join(xml_records)
    final_xml += '\n</Events>'

    if xml_output_path:
        with open(xml_output_path, "w") as xml_output:
            xml_output.write(final_xml)
    else:
        print(final_xml)

def check_url(url):
    try:
        response = requests.head(url)
        return response.status_code // 100 == 2
    except requests.RequestException as e:
        print(f"Error: {e}")
        return False

def download_file(url, local_filename):
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename


def main():
    if len(sys.argv) < 2:
        print("Usage: python evtx_to_xml.py <evtx_file_path_or_url> [xml_output_path]")
        sys.exit(1)

    evtx_file_path_or_url = sys.argv[1]
    xml_output_path = sys.argv[2] if len(sys.argv) == 3 else None

    # Check if the evtx_file_path_or_url is a URL
    parsed_url = urlparse(evtx_file_path_or_url)
    isUrl = parsed_url.scheme in ['http', 'https']
    if isUrl:
        if not check_url(evtx_file_path_or_url):
            print(f"Error: URL {evtx_file_path_or_url} is not accessible.")
            sys.exit(1)
        evtx_file_path_or_url = download_file(evtx_file_path_or_url, 'tmp_downloaded.evtx')
    else:
        if not os.path.exists(evtx_file_path_or_url):
            print(f"Error: File {evtx_file_path_or_url} does not exist.")
            sys.exit(1)

    evtx_to_xml(evtx_file_path_or_url, xml_output_path)

    # Delete the downloaded file
    if isUrl:
        os.remove(evtx_file_path_or_url)


if __name__ == "__main__":
    main()
