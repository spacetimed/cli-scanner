class Config:
    def __init__(self) -> None:

        with open('API_KEY', 'r') as f:
            self.api_key = f.readline()
        
        self.endpoint = 'https://www.virustotal.com/api/v3'
        self.device_name = 'test'

        return