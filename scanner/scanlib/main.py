import config
import requests
import json
from typing import Optional, Union
from colorama import Fore, Back, Style
# import colorama

class Logger:
    def __init__(self) -> None:
        return None
    
    def __call__(self, message: str) -> bool:
        print('LOG', message)
        return
        
class APIRequest:
    def __init__(self, config: type) -> None:
        self.config = config
        self.headers = {
            "Accept": "application/json",
            "x-apikey": self.config.api_key
        }
        return

    def __call__(self, route: str, method: str, add_headers: dict = None) -> Optional[requests.models.Response]:
        # url = f'{self.config.endpoint}/{route}'
        # headers = self.headers
        # if add_headers is not None:
        #     headers.update(add_headers)

        # if(method == 'post'):
        #     return None
        # elif(method == 'get'):
        #     # print(url, headers)
        #     response = requests.get(url, headers=headers)
        #     # print('response->', response)
        
        # with open('res.txt', 'w') as f:
        #     f.write(response.text)

        # if not response.ok:
        #     return None 

        with open('res.txt', 'r') as f:
            response = f.read()

        response = json.loads(response)
        
        return response


class Scanner:
    def __init__(self) -> None:
        self.APIRequest = APIRequest(config.Config())
        self.Log = Logger()
        return

    def row(self, title: str, data: Union[str, int], flag: bool = False) -> None:
        padding = 18
        title += ':'
        if flag:
            data = Fore.RED + data
        print(Fore.GREEN, title.rjust(padding), Style.RESET_ALL, data, Style.RESET_ALL)

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
        print(Fore.BLUE, f'https://www.virustotal.com/gui/file/{scan_id}', Style.RESET_ALL)
        print()
        self.row('submissions', times_submitted)
        self.row('votes', f"{total_votes['harmless']} 👍  / {total_votes['malicious']} 👎")
        self.row('last submission', last_submission_date)
        self.row('first submission', first_submission_date)
        self.row('analysis', f"{last_analysis_stats['malicious']} / {last_analysis_stats['undetected'] + last_analysis_stats['malicious']}", flag=(last_analysis_stats['malicious'] > 0))

        print()
        print()

        return

    def scan_file_by_hash(self, hash: str) -> None:
        hash = '5c81cf8262f9a8b0e100d2a220f7119e54edfc10c4fb906ab7848a015cd12d90'
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