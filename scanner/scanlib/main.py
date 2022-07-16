from optparse import Option
import requests
import json
import os
import hashlib

from config import options as __options__
from colorama import Fore, Back, Style
from datetime import datetime

from typing import List
from typing import Optional
from typing import Union
from typing import Any 
from typing import Type
from typing import Dict

class Logger:
    def __init__(self) -> None:
        return None
    
    def __call__(self, msg: str, tag: Optional[str] = None, end: Optional[str] = None) -> None:
        print('  ', end='')

        tags: Dict[str, str] = {
            'error' : Back.RED,
            'info' : Back.BLUE,
            'question' : Back.MAGENTA,
        }

        if(tag in tags):
            print(tags[tag], Fore.WHITE, tag, ' ', end=Style.RESET_ALL)

        if end is None:
            print(' ', msg)
        else:
            print(' ', msg, end=end)

        return
        
class APIRequest:
    def __init__(self, config: Dict[str, str]) -> None:
        self.Log: Type[Logger] = Logger()
        self.config: Dict[str, str] = config 
        self.headers: Dict[str, str] = {
            "Accept": "application/json",
            "x-apikey": self.config['api_key'] 
        }
        return

    def __call__(
        self, 
        route: str, 
        method: str, 
        add_headers: Dict[str, str] = None,
        files: Optional[Dict[str, any]] = None
    ) -> requests.models.Response:

        url: str = f"{self.config['endpoint']}/{route}"
        headers: Dict[str, str] = self.headers
        
        if add_headers is not None:
            headers.update(add_headers)

        if(method == 'post'):
            #self.Log('Invalid request', tag='error')
            if files is not None:
                response = requests.post(url, files=files, headers=headers)


        elif(method == 'get'):
            response = requests.get(url, headers=headers)

        return response



class Scanner:
    def __init__(self, __target: str, which: str) -> None:

        self.master_dir: str = os.path.dirname(os.path.realpath(__file__))

        with open(f'{self.master_dir}/API_KEY', 'r') as f:
            self.api_key = f.readline() 

        self.config: Dict[str, str] = __options__ 
        self.config['api_key'] = self.api_key

        self.APIRequest: Type[APIRequest] = APIRequest(self.config)
        self.Log: Type[Logger] = Logger()

        path: Optional[str] = None
        hash: Optional[str] = None
        
        if(which == 'file'):
            path = __target
            if not os.path.exists(path):
                return self.Log(f'File does not exist ({path})', tag='error')
            if os.path.getsize(path) > self.config['size_limit']:
                return self.Log(f'File size is too large', tag='error')
            hash = self.get_file_hash(path)

        elif(which == 'hash'):
            hash = __target

        self.scan_file_by_hash(hash, path)

    def RaiseError(self,  error_message: Optional[str], flag: Optional[int] = False) -> bool:
        self.Log(error_message, tag='error')
        return flag

    def get_file_hash(self, path: str):
        with open(path, "rb") as f:
            f_byte: bytes = f.read()
            result: hashlib._Hash = hashlib.sha256(f_byte)
            return result.hexdigest()

    def row(self, title: str, data: Union[str, int], flag: bool = False) -> None:
        padding: int = 18
        title += ':'
        if flag:
            data = Fore.RED + data
        print(Fore.GREEN, title.rjust(padding), Style.RESET_ALL, data, Style.RESET_ALL)


    def format_timestamp(self, timestamp: int) -> str:
        format: datetime = datetime.fromtimestamp(timestamp)
        return(f"{format.strftime('%c')}")


    def display_result(self, response: Dict[str, str]) -> None:

        scan_id: str = response['data']['id']
        attr: str = response['data']['attributes']

        names: List[str] = attr['names'][0:6]
        type: str = attr['type_description']

        times_submitted: int = attr['times_submitted']
        total_votes: Dict[str, int] = attr['total_votes']

        last_submission_date: int = attr['last_submission_date']
        first_submission_date: int = attr['first_submission_date']

        last_analysis_stats: Dict[str, int] = attr['last_analysis_stats']
        sha256: str = attr['sha256']

        format_names: str = (', '.join(names) + ', ...') if (len(names) > 0) else ('...')
        
        print('\n')
        print(Back.WHITE, Fore.BLACK, 'SCAN COMPLETE', Style.RESET_ALL)
        print()
        print(Fore.BLUE, f'  https://www.virustotal.com/gui/file/{scan_id}', Style.RESET_ALL)
        print()
        self.row('type', type)
        self.row('names', f'{format_names}')
        self.row('sha256', sha256)
        self.row('submissions', times_submitted)
        self.row('votes', f"{total_votes['harmless']} 👍  / {total_votes['malicious']} 👎")
        self.row('detections', f"{last_analysis_stats['malicious']} / {last_analysis_stats['undetected'] + last_analysis_stats['malicious']} {'❌' if (last_analysis_stats['malicious'] > 0) else '✅'}", flag=(last_analysis_stats['malicious'] > 0))
        self.row('first seen', self.format_timestamp(first_submission_date))
        self.row('last seen', self.format_timestamp(last_submission_date))
        print('\n')

        return

    def force_upload_and_scan(self, path: str) -> None:

        # Assume file already exists (checked in __init__)

        file_handle = open(path, 'rb')
        response: requests.models.Response = self.APIRequest(f'files', 'post', files={
            'file' : file_handle
        })

        if not response.ok:
            return self.RaiseError('Invalid API response')

        response = json.loads(response.text)

        if 'data' in response and 'id' in response['data']:
            id = response['data']['id']
            response: requests.models.Response = self.APIRequest(f'analyses/{id}', 'get') 
            response = json.loads(response.text)
            hash = response['meta']['file_info']['sha256']
            self.scan_file_by_hash(hash)

        return

    def scan_file_by_hash(self, hash: str, file_path: Optional[str] = None) -> None:
        
        response: requests.models.Response = self.APIRequest(f'files/{hash}', 'get') 

        if not response.ok:
            if len(response.text) > 0:
                response_object: Dict[str, Dict[str, str]] = {}

                try:
                    response_object = json.loads(response.text)
                except ValueError as e:
                    return self.RaiseError('Could not unpackage response. Corrupted?')

                if ('error' in response_object) and (response_object['error']['code'] == 'NotFoundError'):

                    self.Log(f'A hash could not be found in the VirusTotal database for "{file_path}"', tag='info')
                    self.Log(f'Would you like to upload the file to VirusTotal? (Y/n): ', tag='question', end='')
                    user_res: str = input()
                    if(user_res.upper() == 'Y'):
                        return self.force_upload_and_scan(file_path)
                    
                    return self.RaiseError('Unable to scan designated file.', flag='upload')
            
            return self.RaiseError('Invalid API response')
        
        response = json.loads(response.text)
        self.display_result(response)

        return