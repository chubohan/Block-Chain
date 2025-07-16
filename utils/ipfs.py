import requests
import os
from dotenv import load_dotenv

load_dotenv()

PINATA_API_KEY = '329fea7713104ba6ed38'
PINATA_SECRET_API_KEY = 'b5ec32891265eea2c5d433235719baa7e8320934e3986566ab57836bbdcc8899'

def upload_to_pinata(file_path, file_name):
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }
    with open(file_path, 'rb') as file:
        files = {'file': (file_name, file)}
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            return response.json()['IpfsHash']
        else:
            raise Exception(f"上傳 Pinata 失敗: {response.text}")