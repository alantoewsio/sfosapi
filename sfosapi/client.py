from __future__ import annotations

import os
import ssl
import urllib.parse
import warnings
from getpass import getpass
from urllib.error import URLError, HTTPError
from urllib.request import urlopen 
from xml.etree.ElementTree import Element

import dotenv
from defusedxml import ElementTree as ET  # type: ignore

from .api_factory import _create_element
from .request import Request
from .response import Response


class Client:
    """
    Interfaces with the Sophos XG API server.
    """

    def __init__(
        self,
        *,
        username: str | None = None,
        password: str | None = None,
        address: str | None = None,
        port: int = 4444,
        apiversion: str = None,
        insecure_certificates: bool | None = None,
    ) -> None:

        self.username = username
        self.password = password
        self.address = address
        self.port = port
        self.apiversion = apiversion
        self.insecure_certificates = insecure_certificates

        dotenv.load_dotenv()

        if self.username is None:  # not provided by user
            self.username = os.getenv("SOPHOS_API_USERNAME")

            if self.username is None:  # not found in .env
                self.username = input("Enter Sophos API username: ")

        if self.password is None:  # not provided by user
            self.password = os.getenv("SOPHOS_API_PASSWORD_ENCRYPTED")
            self.is_encrypted = True

            if self.password is None:  # not found in .env
                self.password = getpass("Enter Sophos API password: ")
                self.is_encrypted = False

        if self.address is None:  # not provided by user
            self.address = os.getenv("SOPHOS_API_FIREWALL_IP")

            if self.address is None:  # not found in .env
                self.address = input("Enter Sophos Firewall IP address: ")

        if self.insecure_certificates is None:
                self.insecure_certificates = os.getenv("SOPHOS_API_ALLOW_INSECURE_CERTS")

        if self.insecure_certificates:
            warnings.warn(  # type: ignore
                "Insecure Certificate Mode Selected - Certificate validity will not be checked before connecting.",
                stacklevel=2,
            )

    def send(self, request: Request) -> list[Response]:
        response_element = self._make_api_call(request)
        responses = self._parse_response(response_element)
        return responses

    def _make_api_call(self, request: Request) -> Element:
        request.set_login(self.get_login_tag())
        req_str = urllib.parse.quote(str(request))
                
        context = ssl.create_default_context
        if (self.insecure_certificates):             
            context = ssl._create_unverified_context()       
        
        try:          
            response_http = urlopen(
                f"https://{self.address}:{self.port}/webconsole/APIController?reqxml={req_str}", 
                context=context  # noqa: E501
            )
            raw_response = response_http.read()            
            response_element = ET.fromstring(raw_response)          
            
        except URLError as ue:            
            response_element = ET.fromstring("<response><login><status>URL Error</status></login><response>")
            
        except AttributeError as ae:            
            response_element = ET.fromstring("<response><login><status>Attribute Error</status></login><response>")
            
        except:
            response_element = ET.fromstring("<response><login><status>Unknown Error Type</status></login><response>")
            
        finally:
            return response_element
        
    def _parse_response(self, response_element: Element) -> list[Response]:
        responses = [Response(e) for e in response_element]
        print(f'responses:{responses}')
        # don't need to store the Successful Authentication response:
        login_response = next(
            (
                r
                for r in responses                
                if r.data["message"] == "Authentication Successful"
            ),
            None,
        )
        if login_response is not None:
            responses.remove(login_response)

        # TODO
        # for each response:
        #     find corresponding request using transactionid
        #     set a reference to the request in the response
        return responses

    def get_login_tag(self) -> Element:
        login = _create_element("Login")
        login_username = _create_element("Username", text=self.username)
        login_password = _create_element("Password", text=self.password)
       

        login.append(login_username)
        login.append(login_password)

        return login

    def test_login(self) -> dict:
        """Run a login-only request to test client-server access and
        authentication.

        Returns the Sophos API status code and message
        Read-only issues will be seen with transaction responses, not at login
        """

        request = Request(apiversion=self.apiversion)
        response_element = self._make_api_call(request)

        status_code = -1
        message = "No response"
        if len(response_element) == 1:

            response = Response(response_element[0])
            status_code = response.status_code
            message = response.data["message"]  # type: ignore

        return {
            "status_code": status_code,
            "message": message,
        }

    # PROXIES FOR REQUEST
    def _request_proxy_call(
        self, fn_name: str, *args, **kwargs
    ) -> list[Response]:
        """Proxy to run one-off Request methods.

        Call Request.fn_name(*args, **kwargs)
        """
        request = Request(apiversion=self.apiversion)
        getattr(request, fn_name)(*args, **kwargs)

        responses = self.send(request)
        return responses

    # GENERIC METHODS
    def get(self, *args, **kwargs) -> list[Response]:
        return self._request_proxy_call("get", *args, **kwargs)

    def get_filter(self, *args, **kwargs) -> list[Response]:
        return self._request_proxy_call("get_filter", *args, **kwargs)

    def set(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("set", *args, **kwargs)[0]

    def add(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("add", *args, **kwargs)[0]

    def update(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("update", *args, **kwargs)[0]

    def remove(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("remove", *args, **kwargs)[0]

    # ZONES
    def get_zones(self, *args, **kwargs) -> list[Response]:
        return self._request_proxy_call("get_zones", *args, **kwargs)

    def get_zone(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("get_zone", *args, **kwargs)[0]

    def get_zones_like(self, *args, **kwargs) -> list[Response]:
        return self._request_proxy_call("get_zones_like", *args, **kwargs)

    def get_zones_except(self, *args, **kwargs) -> list[Response]:
        return self._request_proxy_call("get_zones_except", *args, **kwargs)

    def set_zone(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("set_zone", *args, **kwargs)[0]

    def add_zone(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("add_zone", *args, **kwargs)[0]

    def update_zone(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("update_zone", *args, **kwargs)[0]

    def remove_zone(self, *args, **kwargs) -> Response:
        return self._request_proxy_call("remove_zone", *args, **kwargs)[0]
