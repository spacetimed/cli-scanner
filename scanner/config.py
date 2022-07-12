class Config:
    def __init__(self, master_dir: str) -> None:

        with open(f'{master_dir}/API_KEY', 'r') as f:
            self.api_key = f.readline()
        
        self.master_dir = master_dir
        self.endpoint = 'https://www.virustotal.com/api/v3'
        self.device_name = 'test'
        self.size_limit = 12000

        return