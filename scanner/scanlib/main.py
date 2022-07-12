import config
import requests
import json
import os
import hashlib

from colorama import Fore, Back, Style
from datetime import datetime

from typing import Optional, Union

class Logger:
    def __init__(self) -> None:
        return None
    
    def __call__(self, message: str) -> bool:
        return
        
class APIRequest:
    def __init__(self, config: type) -> None:
        self.config = config
        self.master_dir = config.master_dir
        self.headers = {
            "Accept": "application/json",
            "x-apikey": self.config.api_key
        }
        return

    def __call__(self, route: str, method: str, add_headers: dict = None) -> Optional[requests.models.Response]:
        url = f'{self.config.endpoint}/{route}'
        headers = self.headers
        
        if add_headers is not None:
            headers.update(add_headers)

        if(method == 'post'):
            print('error1')
            return None

        elif(method == 'get'):
            response = requests.get(url, headers=headers)


        if not response.ok:
            print('error1', response.text)
            return None 
        
        return json.loads(response.text)


class Scanner:
    def __init__(self, path: str) -> None:
        self.master_dir = os.path.dirname(os.path.realpath(__file__))
        self.APIRequest = APIRequest(config.Config(self.master_dir))
        self.Log = Logger()
        if os.path.exists(path):
            hash = self.get_file_hash(path)
            self.scan_file_by_hash(hash)
        else:
            print('doesnt exist')
        return

    def get_file_hash(self, path: str):
        with open(path, "rb") as f:
            f_byte= f.read()
            result = hashlib.sha256(f_byte)
            return result.hexdigest()

    def row(self, title: str, data: Union[str, int], flag: bool = False) -> None:
        padding = 18
        title += ':'
        if flag:
            data = Fore.RED + data
        print(Fore.GREEN, title.rjust(padding), Style.RESET_ALL, data, Style.RESET_ALL)


    def format_timestamp(self, timestamp: int) -> str:
        format = datetime.fromtimestamp(timestamp)
        return(f"{format.strftime('%c')}")


    def display_result(self, response: dict) -> None:

        scan_id = response['data']['id']
        attr = response['data']['attributes']
        times_submitted = attr['times_submitted']
        total_votes = attr['total_votes']
        last_submission_date = attr['last_submission_date']
        first_submission_date = attr['first_submission_date']
        last_analysis_stats = attr['last_analysis_stats']
        
        print()
        print()
        print(Back.WHITE, Fore.BLACK, 'SCAN COMPLETE', Style.RESET_ALL)
        print()
        print(Fore.BLUE, f'  https://www.virustotal.com/gui/file/{scan_id}', Style.RESET_ALL)
        print()
        self.row('submissions', times_submitted)
        self.row('votes', f"{total_votes['harmless']} 👍  / {total_votes['malicious']} 👎")
        self.row('analysis', f"{last_analysis_stats['malicious']} / {last_analysis_stats['undetected'] + last_analysis_stats['malicious']}", flag=(last_analysis_stats['malicious'] > 0))
        self.row('first seen', self.format_timestamp(first_submission_date))
        self.row('last seen', self.format_timestamp(last_submission_date))
        print()
        print()

        return


    def scan_file_by_hash(self, hash: str) -> None:
        response = self.APIRequest(f'files/{hash}', 'get') # SHA-256, SHA-1 or MD5

        if not response:
            self.Log('An error occurred.')
            return

        self.display_result(response)

        """
            times_submitted
            total_votes
            last_submission_date
            first_submission_date
            "last_analysis_stats": {
                "harmless": 0,
                "type-unsupported": 3,
                "suspicious": 0,
                "confirmed-timeout": 0,
                "timeout": 0,
                "failure": 0,
                "malicious": 55,
                "undetected": 14
            },
            "id"
        """