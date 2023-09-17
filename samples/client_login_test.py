
import os
from sfosapi import Client
from sfosapi import Request

def print_input_debug():
    print(
f'''
$env:SFOS_TEST_API_USERNAME={client.username}
$env:SFOS_TEST_API_PASSWORD={client.password}
$env:SFOS_TEST_API_ADDRESS={client.address}
$env:SFOS_TEST_API_WEBADMIN_PORT={client.port}
$env:SFOS_TEST_API_ALLOW_INSECURE_CERTIFICATES='{client.insecure_certificates}
'''
    )

debug:bool = os.getenv("SFOS_TEST_API_DEBUG_ON")=="True"
client = Client()
client.username = os.getenv("SFOS_TEST_API_USERNAME")
client.password = os.getenv("SFOS_TEST_API_PASSWORD")
client.address = os.getenv("SFOS_TEST_API_ADDRESS")
client.port = os.getenv("SFOS_TEST_API_WEBADMIN_PORT")
client.insecure_certificates = os.getenv("SFOS_TEST_API_ALLOW_INSECURE_CERTIFICATES")=="True"
    
if debug: print_input_debug()
login=client.test_login()
print(login)