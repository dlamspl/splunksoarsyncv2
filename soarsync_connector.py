# File: soarsync_connector.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import ast
import bz2
import datetime
import gzip
import json
import os
import random
import shutil
import socket
import string
import tarfile
import time
import zipfile
import re
import hashlib
import magic
import requests

from pathlib import Path
from urllib.parse import quote
from markdownify import markdownify
from bs4 import BeautifulSoup
from requests.exceptions import SSLError, Timeout

import phantom.app as phantom # type: ignore
import phantom.rules as ph_rules # type: ignore
import phantom.utils as ph_utils # type: ignore
from phantom.action_result import ActionResult # type: ignore
from phantom.base_connector import BaseConnector # type: ignore
from phantom.cef import CEF_JSON, CEF_NAME_MAPPING # type: ignore
from phantom.utils import CONTAINS_VALIDATORS # type: ignore
from phantom.vault import Vault # type: ignore
import phantom.api.data_access.api_get_assets as more_api # type: ignore

# Constants imports
from soarsync_consts import *

# print(f"##### DEBUG ##### {vars(phantom)}")
try:
    from urllib.parse import quote
except Exception:
    from urllib import quote


# A list of files that MS OOXML archives will contain.
# OOXML documents are zip files with metadata, assets and data as various
# archive entries. We do not want to the deflate action to extract these.
OOXML_FILES = frozenset(['[Content_Types].xml', '_rels/.rels'])


def determine_contains(value):
    valid_contains = list()
    for c, f in list(CONTAINS_VALIDATORS.items()):
        try:
            if f(value):
                valid_contains.append(c)
        except Exception:
            continue

    return valid_contains


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


## New class with ph-auth-token support
class splunksoarupload:

    def __init__(self, baseurl=None, username=None, password=None, ph_auth_token=None, verify_certificate=True):
        if not baseurl:
            raise Exception("Base URL must be provided.")

        self.baseurl = baseurl
        self.username = username
        self.password = password
        self.ph_auth_token = ph_auth_token
        self.verify_certificate = verify_certificate
        self.s = requests.Session()
        self.s.verify = verify_certificate

        # Disable TLS warnings only if verify_certificate is False
        if not verify_certificate:
            requests.packages.urllib3.disable_warnings()

        # Basic validation
        if not ((username and password) or ph_auth_token):
            raise Exception("Either username/password or ph_auth_token must be provided.")

    def login(self):
        # print("####################### DEBUG #######################")
        # print(f"Logging in to {self.baseurl} with username: {self.username} and ph_auth_token: {self.ph_auth_token}")
        # print(f"Verify Certificate: {self.verify_certificate}")
        # print("Session Verify Headers: ", self.s.verify)
        # print("#####################################################")
        authenticated = False
        message = None
        csrf = None

        url = f"{self.baseurl}/login?next=/"
        page = self.s.get(url,verify=self.s.verify)

        if page.status_code != 200:
            raise Exception(f"Splunk SOAR returned HTTP/{page.status_code} during pre-login stage. Details: {page.content}")

        csrftoken = page.cookies.get('csrftoken', None)
        if not csrftoken:
            raise Exception("CSRF token not found in initial response.")

        self.s.headers.update({'Referer': url})

        # Login with username/password
        if self.username and self.password:
            login_data = {
                'csrfmiddlewaretoken': csrftoken,
                'username': self.username,
                'password': self.password
            }

            logged = self.s.post(f"{self.baseurl}/login", data=login_data,verify=self.verify_certificate)

            if logged.status_code == 200 and logged.json().get('authenticated', False):
                authenticated = True
                csrf = logged.cookies.get('csrftoken', None)
            else:
                message = logged.json().get('message', 'Login failed')

        # Login with ph-auth-token
        elif self.ph_auth_token:
            self.s.headers.update({'ph-auth-token': self.ph_auth_token})
            auth_check = self.s.get(f"{self.baseurl}/rest/container",verify=self.verify_certificate)

            if auth_check.status_code == 200:
                authenticated = True
                # Get CSRF for future POSTs
                page2 = self.s.get(url,verify=self.s.verify)
                csrf = page2.cookies.get('csrftoken', None)
                if csrf:
                    self.s.cookies.set('csrftoken', csrf)
            else:
                message = f"ph-auth-token authentication failed with HTTP {auth_check.status_code}"

        return authenticated, message, csrf

    def upload_chunked(self,csrftoken=None,file=None):

        success = False
        message = None
        
        # if not os.path.isfile(file) and os.path.getsize(file) < 100:
        if not os.path.isfile(file):
            raise Exception('Container to upload must be a valid file')

        with open(file,'rb') as f:
            # The following can read large files without issues - Read and update hash string value in blocks of 4K
            fbytes = hashlib.sha256()
            for byte_block in iter(lambda: f.read(4096),b""):
                fbytes.update(byte_block)
            file_hash = fbytes.hexdigest()

            post_data = {
                'csrfmiddlewaretoken':csrftoken,
                'import_container': True,       
            }
            
            # pointing at the beginning of the file
            f.seek(0)
            
            files = {'filename': os.path.basename(file),'file': f}
            
            url = f"{self.baseurl}/upload_chunked"
            chunk_posted = self.s.post(url, data=post_data,files=files,verify=False)

            if chunk_posted.status_code == 200:

                newurl = f"{self.baseurl}/upload_chunked_complete"
                post_data = {
                    'csrfmiddlewaretoken':csrftoken,
                    'upload_id':chunk_posted.json()['upload_id'],
                    'sha256': file_hash
                    }
                chunk_posted_complete = self.s.post(newurl, data=post_data, verify=False)
                if chunk_posted_complete.status_code == 200:
                    success = True
                    message = chunk_posted_complete.json().get('message', None)
                else:
                    success = False
                    data = chunk_posted_complete.json().get('data', None)
                    if data:
                        message = data.get('message',None)
            else:
                raise Exception(f"Splunk SOAR returned HTTP/{chunk_posted.status_code} during upload_chunked stage. Details: {chunk_posted.content}")
    
        return success, message

    ### Function for downloading file attachments
    def get_file_attachment(self,csrftoken=None,attachment_id=None,container_id=None):

        success = False
        message = None
        url = f"{self.baseurl}/download?id={attachment_id}&container_id={container_id}"
        # print(self.baseurl)
        # print(url)
        response = self.s.get(url, verify=False)

        if response.status_code == 200:
            success = True
            # print(response.text)
            message = "Success"
            
        else:
            raise Exception(f"Something went worng")
    
        return success, message, response


    def upload_chunked_to_vault(self,csrftoken=None,file=None, filename=None,container_id=None):

        success = False
        message = None
        
        if not container_id:
            raise Exception('Need a valid container id')
        
        if not os.path.isfile(file): #type: ignore
            raise Exception('File to upload must be a valid file')

        with open(file,'rb') as f: #type: ignore
            # getting hash256 of TGZ to upload
            fbytes = f.read() 
            file_hash = hashlib.sha256(fbytes).hexdigest()
            post_data = {
                'csrfmiddlewaretoken':csrftoken,
                'container_id': container_id,
                'name':'file',
                'filename': str(filename)
            }
            
            # print(f"Uploading file {filename} to container {container_id} with hash {file_hash}")
            # pointing at the beginning of the file
            f.seek(0)
            
            # files = {'filename': filename,'file': f} #type: ignore
            files = {'file': (filename, f)} #type: ignore
            
            url = f"{self.baseurl}/upload_chunked"
            chunk_posted = self.s.post(url, data=post_data, files=files,verify=False)

            if chunk_posted.status_code == 200:

                newurl = f"{self.baseurl}/upload_chunked_complete"
                post_data = {
                    'csrfmiddlewaretoken':csrftoken,
                    'upload_id':chunk_posted.json()['upload_id'],
                    'sha256': file_hash
                }
                chunk_posted_complete = self.s.post(newurl, data=post_data,verify=False)
                if chunk_posted_complete.status_code == 200:
                    success = True
                    message = chunk_posted_complete.json().get('message', None)
                else:
                    success = False
                    data = chunk_posted_complete.json().get('data', None)
                    if data:
                        message = data.get('message',None)
            else:
                raise Exception(f"Splunk SOAR returned HTTP/{chunk_posted.status_code} during upload_chunked stage. Details: {chunk_posted.content}")
    
        return success, message



class PhantomConnector(BaseConnector):
    
    def get_container_attachments(self,param):
        container = param.get('container_id')
        success = False
        message = None
        attachments = []
        export_url = None

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = f"/rest/container/{container}/attachments?sortKey=create_time&sortOrder=desc&pretty=true&page_size=0"

        ret_val, response, resp_data = self._make_rest_call(endpoint,action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Action Failed")
            return action_result.set_status(phantom.APP_ERROR, 'Failed to connect: {}'.format(action_result.get_message()))

        else:
            success = True
            message = 'found containers'
            
            export_url = f"/rest/container/{container}/export"
            att_url_str = "?"
            attachment_count = resp_data.get('count')
            if attachment_count>0:
                attachment_data = resp_data.get('data')
                for ids in attachment_data:
                    attachments.append(ids['id'])
                attachments.sort()
                max_att_id = max(attachments)
                for att_id in attachments:
                    if att_id==max_att_id:
                        att_url_str = att_url_str + "file_list[]=" + str(att_id)
                    else:
                        att_url_str = att_url_str + "file_list[]=" + str(att_id) + "&"
                export_url = "{}{}".format(export_url,att_url_str)

        return success, message, attachments, export_url
    
    def export_container(self,csrftoken=None,export_url=None,archive_path=None,container=None,container_create_time=None):

        skip_export = None
        filepath = str(archive_path) + "/" + str(re.sub(r'\/|\\|\s+|!|\'|\`|\"|:','_',container_create_time)) + "__" + str(container)

        with self.s.get(export_url, stream=True, verify=False) as r:
            if r.headers.get('filename') is not None:
                fname = r.headers.get('filename')
            else:
                fname = 'No_Name.tgz'

            fname = re.sub(r'\/|\\|\s+|!|\'|\`|\"|:','_',fname)
            filepath = filepath + "__" + str(fname)

            # Skip saving the exported file if the file already exist and is not of 0 bytes
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                # print(f"Container {container} was already exported as {filepath}, SKIPPING.")
                skip_export = True
            else:
                with open(filepath, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
        return filepath,skip_export
    
    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="", param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="", param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="non-negative", param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="non-zero positive", param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = PHANTOM_ERR_CODE_UNAVAILABLE
        error_msg = PHANTOM_ERR_MSG_UNAVAILABLE
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.debug_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _get_error_details(self, resp_json):

        # The device that this app talks to does not sends back a simple message,
        # so this function does not need to be that complicated
        message = resp_json.get('message')
        if not message:
            message = "Error message is unavailable"
        return message

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        # In 2.0 the platform does not like braces in messages, unless it's format parameters
        message = message.replace('{', ' ').replace('}', ' ')

        return RetVal3(action_result.set_status(phantom.APP_ERROR, message), response)

    def _process_json_response(self, response, action_result):

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                        PHANTOM_ERR_PARSE_JSON_RESPONSE.format(self._get_error_message_from_exception(e))), response)

        if isinstance(resp_json, list):
            # Let's not parse it here
            return RetVal3(phantom.APP_SUCCESS, response, resp_json)

        failed = resp_json.get('failed', False)

        if failed:
            return RetVal3(
                    action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_SERVER.format(response.status_code,
                        self._get_error_details(resp_json))), response)

        if 200 <= response.status_code < 399:
            return RetVal3(phantom.APP_SUCCESS, response, resp_json)

        return RetVal3(
                action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_SERVER.format(response.status_code,
                    self._get_error_details(resp_json))), response, None)

    def _process_response(self, response, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if response is not None:
                action_result.add_debug_data({'r_text': response.text})
                action_result.add_debug_data({'r_headers': response.headers})
                action_result.add_debug_data({'r_status_code': response.status_code})
            else:
                action_result.add_debug_data({'r_text': 'response is None'})

        # There are just too many differences in the response to handle all of them in the same function
        if (('json' in response.headers.get('Content-Type', '')) or ('javascript' in response.headers.get('Content-Type'))):
            return self._process_json_response(response, action_result)

        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not an html or json, handle if it is a successful empty response
        if (200 <= response.status_code < 399):
            if not response.text:
                return RetVal3(phantom.APP_SUCCESS, response, action_result)
            if response.headers.get('Content-Type') == 'application/x-gzip':
                return RetVal3(phantom.APP_SUCCESS, response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, response.text.replace('{', ' ').replace('}', ' '))

        return RetVal3(action_result.set_status(phantom.APP_ERROR, message), response, None)

    # creating custom version for few api calls where _make_rest_call is causing trouble
    def _make_rest_call_custom(self, endpoint, headers=None, params=None, data=None, method="get", ignore_auth=False):

        config = self.get_config()

        # Create the headers
        if headers is None:
            headers = {}

        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                return (phantom.APP_ERROR,
                            "Unable to load headers as JSON: {}".format(self._get_error_message_from_exception(e)))

        # auth_token is a bit tricky, it can be in the params or config
        auth_token = config.get('auth_token')

        if ((auth_token) and ('ph-auth-token' not in headers)):
            headers['ph-auth-token'] = auth_token

        if 'Content-Type' not in headers:
            headers.update({'Content-Type': 'application/json'})

        request_func = getattr(requests, method)

        if not request_func:
             return (phantom.APP_ERROR, "Unsupported HTTP method '{0}' requested".format(method))

        auth = self._auth

        # To avoid '//' in the URL(due to self._base_uri + endpoint)
        self._base_uri = self._base_uri.strip('/')

        if ignore_auth:
            auth = None
            if 'ph-auth-token' in headers:
                del headers['ph-auth-token']

        try:
            url = '{0}{1}'.format(self._base_uri, endpoint)
            response = request_func(url,
                    auth=auth,
                    json=data,
                    headers=headers if headers else None,
                    verify=False if ignore_auth else self._verify_cert,
                    params=params,
                    timeout=TIMEOUT)

        except Timeout as e:
            return (phantom.APP_ERROR,
                        "Request timed out: {}".format(self._get_error_message_from_exception(e)))
        except SSLError as e:
            return (phantom.APP_ERROR,
                        "HTTPS SSL validation failed: {}".format(self._get_error_message_from_exception(e)))
        except Exception as e:
            return (phantom.APP_ERROR,
                        "Error connecting to server. Error Details: {}".format(self._get_error_message_from_exception(e)))
            
        #if response.json().get('count'):
        ret_success = False
        if (200 <= response.status_code < 399):
            ret_success = True

        return ret_success, response.status_code, response.json(), self._base_uri
        #return response.json().get('success'),response.status_code, response.json(), self._base_uri

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", ignore_auth=False):

        config = self.get_config()
        # print(config)
        # Create the headers
        if headers is None:
            headers = {}

        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                            "Unable to load headers as JSON: {}".format(self._get_error_message_from_exception(e)))

        # auth_token is a bit tricky, it can be in the params or config
        auth_token = config.get('auth_token')

        if ((auth_token) and ('ph-auth-token' not in headers)):
            headers['ph-auth-token'] = auth_token

        if 'Content-Type' not in headers:
            headers.update({'Content-Type': 'application/json'})

        request_func = getattr(requests, method)

        if not request_func:
            action_result.set_status(phantom.APP_ERROR, "Unsupported HTTP method '{0}' requested".format(method))

        auth = self._auth

        # To avoid '//' in the URL(due to self._base_uri + endpoint)
        self._base_uri = self._base_uri.strip('/')

        if ignore_auth:
            auth = None
            if 'ph-auth-token' in headers:
                del headers['ph-auth-token']

        try:
            url = '{0}{1}'.format(self._base_uri, endpoint)
            response = request_func(url,
                    auth=auth,
                    json=data,
                    headers=headers if headers else None,
                    verify=False if ignore_auth else self._verify_cert,
                    params=params,
                    timeout=TIMEOUT)

        except Timeout as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                        "Request timed out: {}".format(self._get_error_message_from_exception(e))), None, None)
        except SSLError as e:
            return (action_result.set_status(phantom.APP_ERROR,
                        "HTTPS SSL validation failed: {}".format(self._get_error_message_from_exception(e))), None, None)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR,
                        "Error connecting to server. Error Details: {}".format(self._get_error_message_from_exception(e))), None, None)

        return self._process_response(response, action_result)


    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response, resp_data = self._make_rest_call('/rest/version', action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR, 'Failed to connect: {}'.format(action_result.get_message()))

        version = resp_data['version']
        self.save_progress("Connected to Phantom appliance version {}".format(version))
        self.save_progress("Test connectivity passed")

        return action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')

    def load_dirty_json(self, dirty_json, action_result, parameter):
        import re
        regex_replace = [
            (r"([ \{,:\[])(u?\\?)?'([^']*)'([^'])", r'\1"\3"\4'),   # Replace single quotes with double quotes
            (r" False([, \}\]])", r' false\1'),                     # Replace python "False" with json "false"
            (r" True([, \}\]])", r' true\1'),                       # Replace python "True" with json "true"
            (r" None([, \}\]])", r' null\1')                        # Replace python "None" with json "null"
        ]
        for r, s in regex_replace:
            dirty_json = re.sub(r, s, dirty_json)
        dirty_json = dirty_json.replace(": ''", ': ""')

        try:
            clean_json = json.loads(dirty_json)
            if not clean_json:
                action_result.set_status(phantom.APP_ERROR,
                        "Please provide a non-empty JSON in {parameter} parameter".format(parameter=parameter))
                return None
            if not isinstance(clean_json, dict):
                action_result.set_status(phantom.APP_ERROR, "Please provide {parameter} parameter in JSON format".format(parameter=parameter))
                return None
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR,
                        "Could not load JSON from {parameter} parameter".format(parameter=parameter), self._get_error_message_from_exception(e))
            return None

        return clean_json

    def _update_artifact(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_id = param['artifact_id']

        name = param.get('name')
        label = param.get('label')
        severity = param.get('severity')
        cef_json = param.get('cef_json')
        cef_types_json = param.get('cef_types_json')
        tags = param.get('tags')
        art_json = param.get('artifact_json')

        overwrite = param.get('overwrite', False)

        # Check if at least one of the following parameters have been supplied:
        if not any((name, label, severity, cef_json, cef_types_json, tags, art_json)):
            req_params = 'name, label, severity, cef_json, cef_types_json, tags, artifact_json'
            return action_result.set_status(phantom.APP_ERROR,
                    'At least one of the following parameters are required to update an artifact: {}'.format(req_params))

        endpoint = "/rest/artifact/{}".format(artifact_id)

        output_artifact = {}

        # name, label, and severity should always be overwritten, if provided
        if name:
            output_artifact['name'] = name

        if label:
            output_artifact['label'] = label

        if severity:
            output_artifact['severity'] = severity

        existing_artifact = {}  # If overwriting, this will be used.

        # //// Start workaround for PPS-18970 ////
        ''' Use this once PPS-18970 is fixed
        if overwrite is False:
            # Get the existing artifact to append provided parameters to existing values
            ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

            if phantom.is_fail(ret_val):
                self.save_progress(PHANTOM_ERR_FIND_ARTIFACT)
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

            existing_artifact = resp_data
        '''

        # First get the artifacts json
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(PHANTOM_ERR_FIND_ARTIFACT)
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

        if overwrite is False:
            existing_artifact = resp_data
        if 'label' not in output_artifact:
            output_artifact['label'] = resp_data.get('label')
            if not output_artifact['label']:
                output_artifact['label'] = 'event'

        # Get the CEF JSON and update the artifact
        myData = existing_artifact.get('cef', {})

        if cef_json:
            try:
                clean_json = json.loads(cef_json)
            except Exception:
                clean_json = self.load_dirty_json(cef_json, action_result, "cef_json")

            if clean_json is None:
                return action_result.get_status()

            try:
                myData = dict((k, v) for k, v in myData.iteritems() if v)
            except Exception:
                myData = dict((k, v) for k, v in myData.items() if v)
            myData.update(clean_json)

        try:
            myData = dict((k, v) for k, v in myData.iteritems() if v)
        except Exception:
            myData = dict((k, v) for k, v in myData.items() if v)

        # //// End workaround for PPS-18970 ////

        output_artifact['cef'] = myData

        if cef_types_json:
            # If overwrite is False, need to update existing cef_types verses replacing whole thing
            contains = existing_artifact.get('cef_types', {})
            cef_types_json = self.load_dirty_json(cef_types_json, action_result, "cef_types_json")
            if cef_types_json is None:
                return action_result.get_status()
            contains.update(cef_types_json)
            output_artifact['cef_types'] = contains

        if tags:
            # If overwrite is False, need to add to the existing tags. Otherwise replace list of tags.
            cleaned_tags = [tag.strip().strip('\'"') for tag in tags.strip('[]').split(',')]
            output_artifact['tags'] = list(set(existing_artifact.get('tags', []) + cleaned_tags))  # make sure any duplicates are removed

        # This will always overwrite any existing fields provided.
        if art_json:
            art_json = self.load_dirty_json(art_json, action_result, "art_json")
            if art_json is None:
                return action_result.get_status()
            output_artifact.update(art_json)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=output_artifact, method="post")

        action_result.add_data({
            'requested_artifact': output_artifact,
            'response': resp_data
        })

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to update artifact.')
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UPDATE_ARTIFACT.format(action_result.get_message()))

        return action_result.set_status(phantom.APP_SUCCESS, 'Artifact updated successfully.')

    def _tag_artifact(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_id = param['artifact_id']
        add_tags = param.get('add_tags', '')
        remove_tags = param.get('remove_tags', '')

        # These come in as str, so split, then convert to set
        add_tags = set([x.strip() for x in add_tags.split(',')])
        remove_tags = set([x.strip() for x in remove_tags.split(',')])

        endpoint = "/rest/artifact/{}".format(artifact_id)
        # First get the artifacts json
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Unable to get artifact, please check the artifact id")
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

        resp_label = resp_data.get("label")

        if not resp_label:
            self.debug_print("The provided aritfact does not have any label")

        # Label has to be included or it gets clobbered in POST
        fields = ['tags', 'label']
        art_data = {f: response.json().get(f) for f in fields}

        # In case the label is None empty string will be passed
        if not art_data.get("label"):
            art_data["label"] = ""

        current_tags = set(art_data['tags'])
        tags_already_added = set()
        tags_already_removed = set()

        # Find tags which are already present
        for tag in add_tags:
            if tag in current_tags:
                tags_already_added.add(tag)

        # Find tags that are to be removed but are not present
        for tag in remove_tags:
            if tag not in current_tags:
                tags_already_removed.add(tag)

        # Set union first to add, then difference to remove, then cast back to list to update
        _tags = (current_tags | add_tags) - remove_tags
        art_data['tags'] = list(_tags)

        # Post our changes
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=art_data, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress("Unable to modify artifact")
            msg = PHANTOM_ERR_UPDATE_ARTIFACT.format(action_result.get_message())
            if not resp_label:
                msg = "{}. {}".format("The reason of the failure can be the unavailability of the label in the provided artifact", msg)
            return action_result.set_status(phantom.APP_ERROR, msg)

        action_result.set_summary({'tags_added': ', '.join((list(add_tags - tags_already_added))),
                                'tags_removed': ', '.join((list(remove_tags - tags_already_removed))),
                                'tags_already_present': ', '.join((list(tags_already_added))),
                                'tags_already_absent': ', '.join((list(tags_already_removed)))})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_note(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        phase_id = param.get('phase_id', None)

        ret_val, phase_id = self._validate_integer(action_result, phase_id, 'phase_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        container_id = param.get('container_id', self.get_container_id())
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = '/rest/note'
        # the following is to replace the escaped \\n with \n so markdown can recognize it as a new line
        contents = param.get('content', '')
        contents = contents.replace('\\n','\n')
        note_data = {
            'container_id': container_id,
            'title': param.get('title', ''),
            'content': contents,
            'note_type': "general",
            'phase': phase_id
        }

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=note_data, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to create note')
            return action_result.set_status(phantom.APP_ERROR, "Failed to create note: {}".format(action_result.get_message()))
        return action_result.set_status(phantom.APP_SUCCESS, "Note created")

    def _find_artifacts(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        limit_search = param.get("limit_search", False)
        container_ids = param.get("container_ids", "current")
        values = param.get('values', '')
        if limit_search:
            container_ids = list(
                set([
                    a for a in [
                        int(z) if isinstance(z, int) or z.isdigit() else None for z in [
                            self.get_container_id() if y == "current" else y for y in
                            [x.strip() for x in container_ids.replace(",", " ").split()]
                        ]
                    ] if a
                ])
            )
            action_result.update_param({"container_ids": str(sorted(container_ids)).strip("[]")})

        if limit_search and not container_ids:
            action_result.update_summary({'artifacts_found': 0, 'server': self._base_uri})
            return action_result.set_status(phantom.APP_SUCCESS)

        cef_key = param.get("cef_key")

        exact_match = param.get('exact_match', False)

        if exact_match and not cef_key:
            values = '"{}"'.format(values)

        url_enc_values = quote(values, safe='')

        if cef_key and exact_match:
            endpoint = '/rest/artifact?_filter_cef__{}={}&page_size=0&pretty'.format(quote(cef_key, safe=''), repr(url_enc_values))
        elif cef_key:
            endpoint = '/rest/artifact?_filter_cef__{}__{}={}&page_size=0&pretty'.format(quote(cef_key, safe=''),
                                                                                        "icontains", repr(url_enc_values))
        else:
            endpoint = '/rest/artifact?_filter_cef__{}={}&page_size=0&pretty'.format("icontains", repr(url_enc_values))

        if limit_search:
            endpoint += '&_filter_container__in={}'.format(container_ids)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, 'Error retrieving records: {0}'.format(action_result.get_message()))

        records = resp_data['data']

        values = values.lower()

        for rec in records:
            key, value = None, None

            try:
                cef_dict_items = rec['cef'].iteritems()
            except Exception:
                cef_dict_items = rec['cef'].items()

            for k, v in cef_dict_items:

                curr_value = v

                try:
                    # if we convert this if/elif statement to if/else, then it will try to
                    # perform str() operation on even the already string/basestring data.
                    # This works for every situation except for the unicode characters for which it will fail.
                    # Hence, we are avoiding the str() on already string/basestring formatted data.
                    if isinstance(curr_value, dict):
                        curr_value = json.dumps(curr_value)
                    if not isinstance(curr_value, str):  # For python 3
                        curr_value = str(curr_value)
                except Exception as e:
                    self.debug_print('Error occurred while processing the artifacts data')
                    return action_result.set_status(phantom.APP_ERROR,
                            'Error occurred while processing the artifacts data: {}'.format(self._get_error_message_from_exception(e)))

                if values in curr_value.lower() or (exact_match and values.strip('"') == curr_value.lower()):
                    key = k
                    value = curr_value
                    break

            result = {
                "id": rec['id'],
                "container": rec['container'],
                "container_name": rec['_pretty_container'],
                "name": rec.get('name'),
                "found in": key if key else "N/A",
                "matched": value if value else "",
            }
            action_result.add_data(result)

        action_result.update_summary({'artifacts_found': len(records), 'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_artifact(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param.get('name')
        container_id = param.get('container_id', self.get_container_id())
        sdi = param.get('source_data_identifier')
        label = param.get('label', 'event')
        contains = param.get('contains')
        cef_name = param.get('cef_name')
        cef_value = param.get('cef_value')
        cef_dict = param.get('cef_dictionary')
        run_automation = param.get('run_automation', False)

        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        loaded_cef = {}
        loaded_contains = {}

        if cef_dict:

            try:
                loaded_cef = json.loads(cef_dict)
                if not isinstance(loaded_cef, dict):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide cef_dictionary parameter in JSON format")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                                "Could not load JSON from CEF parameter: {}".format(self._get_error_message_from_exception(e)))

        if contains:
            try:
                loaded_contains = json.loads(contains)
                if isinstance(loaded_contains, list):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide contains parameter in JSON or string format only")
                if not isinstance(loaded_contains, dict):
                    loaded_contains = {}
                    raise Exception
            except Exception:
                if cef_name and cef_value:
                    contains_list = [x.strip() for x in contains.split(",")]
                    contains_list = list(filter(None, contains_list))
                    loaded_contains[cef_name] = contains_list
                else:
                    self.debug_print("Please provide contains parameter in JSON format")
                    return action_result.set_status(phantom.APP_ERROR, "Please provide contains parameter in JSON format")

        if cef_name and cef_value:
            loaded_cef[cef_name] = cef_value

        artifact = {}
        artifact['name'] = name
        artifact['label'] = label
        artifact['container_id'] = container_id
        artifact['cef'] = loaded_cef
        artifact['cef_types'] = loaded_contains
        if sdi:
            artifact['source_data_identifier'] = sdi
        artifact['run_automation'] = run_automation

        for cef_name in loaded_cef:

            if loaded_contains.get(cef_name):
                continue

            if cef_name not in CEF_NAME_MAPPING:
                determined_contains = determine_contains(loaded_cef[cef_name]) if loaded_cef[cef_name] else None
                if determined_contains:
                    artifact['cef_types'][cef_name] = determined_contains
            else:
                try:
                    artifact['cef_types'][cef_name] = CEF_JSON[cef_name]['contains']
                except Exception:
                    pass

        success, response, resp_data = self._make_rest_call('/rest/artifact', action_result, method='post', data=artifact)

        if not resp_data:
            return action_result.get_status()

        if phantom.is_fail(success):
            artifact_id = resp_data.get('existing_artifact_id')
            if not artifact_id:
                return action_result.get_status()
        else:
            artifact_id = resp_data.get('id')

        action_result.add_data(resp_data)

        action_result.update_summary({'artifact_id': artifact_id, 'container_id': container_id, 'server': self._base_uri})
        self.debug_print("Successfully executed the action")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_file_to_vault(self, action_result, data_stream, file_name, recursive, container_id):

        save_as = file_name or '_invalid_file_name_'

        # PAPP-9543 append a random string to the filename to make concurrent action runs succeed
        random_suffix = '_{}'.format(''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(16)))
        save_as = '{0}{1}'.format(save_as, random_suffix)

        # if the path contains a directory
        if os.path.dirname(save_as):
            save_as = '-'.join(save_as.split(os.sep))

        if hasattr(Vault, 'get_vault_tmp_dir'):
            vault_tmp_dir = Vault.get_vault_tmp_dir()
        else:
            vault_tmp_dir = '/opt/phantom/vault/tmp'

        try:
            save_path = os.path.join(vault_tmp_dir, save_as)
            with open(save_path, 'wb') as uncompressed_file:
                uncompressed_file.write(data_stream)
        except IOError as e:
            error_message = self._get_error_message_from_exception(e)
            try:
                if "File name too long" in error_message:
                    new_file_name = "ph_long_file_name_{}{}".format(self._level, random_suffix)
                    save_path = os.path.join(vault_tmp_dir, new_file_name)
                    self.debug_print("Original filename: {}".format(file_name))
                    self.debug_print("Modified filename: {}".format(new_file_name))
                    with open(save_path, 'wb') as uncompressed_file:
                        uncompressed_file.write(data_stream)
                else:
                    return (action_result.set_status(phantom.APP_ERROR, "Error occurred while adding file to Vault. Error Details:{}".format(
                        self._get_error_message_from_exception(e))))
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR, "Error occurred while adding file to Vault. Error Details:{}".format(
                    self._get_error_message_from_exception(e))))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                            "Error occurred while adding file to Vault. Error Details:{}".format(self._get_error_message_from_exception(e)))

        try:
            success, message, vault_id = ph_rules.vault_add(container=container_id, file_location=save_path, file_name=file_name)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                        "Failed to add file into vault: {}".format(self._get_error_message_from_exception(e)))

        if not success:
            return action_result.set_status(phantom.APP_ERROR, "Failed to add file into vault: {0}".format(message))

        try:
            success, message, resp_data = ph_rules.vault_info(vault_id=vault_id.lower())

            if not success:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_VAULT_INFO.format(message))

            for resp_element in resp_data:
                resp_filename = resp_element['name']

                if file_name == resp_filename:
                    vault_info = resp_element
                    break

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                            "Failed to retrieve info about file added to vault {}".format(self._get_error_message_from_exception(e)))

        action_result.add_data(vault_info)

        if recursive:

            file_path = vault_info['path']

            file_name = vault_info['name']

            file_type = magic.from_file(file_path, mime=True)

            if file_type not in SUPPORTED_FILES:
                return (phantom.APP_SUCCESS)

            self._extract_file(action_result, file_path, file_name, recursive, container_id)
            self._level -= 1

        return (phantom.APP_SUCCESS)

    @staticmethod
    def _is_ooxml_zip(member_filenames):
        return OOXML_FILES.issubset(member_filenames)

    @staticmethod
    def _has_allowed_archive_extension(file_name, allowed_extensions):
        if allowed_extensions:
            allowed_extension_suffixes = set(allowed_extensions.split(','))
            file_extension = Path(file_name).suffix.lstrip('.')
            if file_extension not in allowed_extension_suffixes:
                return False

        return True

    def _extract_file(self, action_result, file_path, file_name, recursive, container_id=None, password=None):

        self._level += 1
        if container_id is None:
            container_id = self.get_container_id()

        file_type = magic.from_file(file_path, mime=True)

        if file_type not in SUPPORTED_FILES:
            return action_result.set_status(phantom.APP_ERROR, "Deflation of file type: {0} not supported".format(file_type))

        config = self.get_config()
        allowed_extensions = config.get('deflate_item_extensions', '')
        if not self._has_allowed_archive_extension(file_name, allowed_extensions):
            self.debug_print(f'Skipping extraction of {file_name} since it is not in the allowed extensions list: {allowed_extensions}')
            return phantom.APP_SUCCESS

        data = None
        if file_type == 'application/x-bzip2':
            # gz and bz2 don't provide a nice way to test, so trial and error
            try:
                with bz2.BZ2File(file_path, 'r') as f:
                    data = f.read()
            except IOError:
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate bz2 file")

            if data is None:
                return phantom.APP_SUCCESS

            ret_val = self._add_file_to_vault(action_result, data, os.path.splitext(file_name)[0], recursive, container_id)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_DECOMPRESSING_FILE.format(file_type, action_result.get_message()))

        elif file_type == 'application/x-gzip' or file_type == 'application/gzip':
            try:
                with gzip.GzipFile(file_path, 'r') as f:
                    data = f.read()
            except IOError:
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate gzip file")

            if data is None:
                return phantom.APP_SUCCESS

            ret_val = self._add_file_to_vault(action_result, data, os.path.splitext(file_name)[0], recursive, container_id)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_DECOMPRESSING_FILE.format(file_type, action_result.get_message()))

        elif file_type == 'application/zip':
            if not zipfile.is_zipfile(file_path):
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate zip file")

            try:
                compressed_file = ''
                with zipfile.ZipFile(file_path, 'r') as vault_file:
                    if password:
                        vault_file.setpassword(password.encode())

                    archived_files = vault_file.namelist()

                    for compressed_file in archived_files:

                        save_as = os.path.basename(compressed_file)

                        if not os.path.basename(save_as):
                            continue

                        ret_val = self._add_file_to_vault(action_result, vault_file.read(compressed_file), save_as,
                                                          recursive, container_id)

                        if phantom.is_fail(ret_val):
                            return ret_val
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                error_message = error_message.replace(compressed_file, file_name)
                return action_result.set_status(phantom.APP_ERROR, "Unable to open the zip file: {}. {}".format(file_path, error_message))

            return (phantom.APP_SUCCESS)

        # a tgz is also a tar file, so first extract it and add it to the vault
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r') as vault_file:

                for member in vault_file.getmembers():

                    # Only interested in files, pass on dirs, links, etc.
                    if not member.isfile():
                        continue

                    ret_val = self._add_file_to_vault(action_result, vault_file.extractfile(member).read(),
                                                    os.path.basename(member.name), recursive, container_id)

                    if phantom.is_fail(ret_val):
                        return action_result.set_status(phantom.APP_ERROR, "Error decompressing tar file.")

            return (phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _deflate_item(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']

        container_id = param.get('container_id')
        password = param.get('password')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            success, message, vault_info = ph_rules.vault_info(vault_id=vault_id)

            if not success:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_VAULT_INFO.format(message))

            vault_info = list(vault_info)[0]

            file_path = vault_info['path']
            file_name = vault_info['name']
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR,
                                "Error occurred while accessing the vault ID. Please verify the provided vault ID in the action parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                "Failed to get vault item info: {}".format(self._get_error_message_from_exception(e)))

        try:
            file_type = magic.from_file(file_path, mime=True)
        except IOError:
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_FILE_PATH_NOT_FOUND)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_FILE_PATH_NOT_FOUND)

        if file_type not in SUPPORTED_FILES:
            return action_result.set_status(phantom.APP_ERROR, "Deflation of file type: {0} not supported".format(file_type))

        ret_val = self._extract_file(action_result, file_path, file_name, param.get('recursive', False),
                                     container_id, password=password)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['total_vault_items'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _find_listitem(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        values = param.get('values')
        list_name = param['list']
        exact_match = param.get('exact_match', False)
        column_index = param.get('column_index')

        ret_val, column_index = self._validate_integer(action_result, column_index, 'column_index', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Encode list_name to consider special url encoded characters like '\' in URL
        list_name = quote(list_name, safe='')

        endpoint = '/rest/decided_list/{}'.format(list_name)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        j = resp_data
        list_id = j['id']
        content = j.get('content')  # pylint: disable=E1101
        coordinates = []
        found = 0
        for rownum, row in enumerate(content):
            for cid, value in enumerate(row):
                if column_index is None or cid == column_index:
                    if exact_match and value == values:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))
                    elif not exact_match and value and values in value:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))

        action_result.update_summary({'server': self._base_uri, 'found_matches': found, 'locations': coordinates, 'list_id': list_id})
        self.debug_print("Successfully executed the action")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_list(self, list_name, row, action_result):

        try:
            if type(row) in (str, int, float, bool):
                row = [row]
        except Exception:
            if type(row) in (str, int, float, bool):
                row = [row]

        payload = {
            'content': [row],
            'name': list_name,
        }

        ret_val, response, resp_data = self._make_rest_call('/rest/decided_list', action_result, method='post', data=payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_data)

        action_result.update_summary({'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_listitem(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_name = param['list']

        row = param.get('new_row')

        try:
            row = ast.literal_eval(row)
        except Exception:
            # it's just a string
            pass

        # Encode list_name to consider special url encoded characters like '\' in URL

        url_enc_list_name = quote(list_name, safe='')

        url = '/rest/decided_list/{}'.format(url_enc_list_name)

        payload = {
            'append_rows': [
                row,
            ]
        }

        ret_val, response, resp_data = self._make_rest_call(url, action_result, method='post', data=payload)

        if phantom.is_fail(ret_val):
            if response is not None and response.status_code == 404:
                if param.get('create', False):
                    self.save_progress('List "{}" not found, creating'.format(list_name))
                    return self._create_list(list_name, row, action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Error appending to list: {0}'.format(action_result.get_message()))

        action_result.add_data(resp_data)
        action_result.update_summary({'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_artifact_list(self, action_result, artifacts, ignore_auth=False):
        """ Add a list of artifacts """
        ret_val, response, resp_data = self._make_rest_call('/rest/artifact', action_result,
                                        method='post', data=artifacts, ignore_auth=ignore_auth)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Error adding artifact: {}".format(action_result.get_message()))
        failed = 0
        for resp in resp_data:  # is a list
            if resp.get('failed') is True:
                self.debug_print(resp.get('message'))
                failed += 1
        if failed:
            action_result.update_summary({'failed_artifact_count': failed})
            return action_result.set_status(phantom.APP_ERROR, "Failed to add one or more artifacts")
        return phantom.APP_SUCCESS

    def _create_container_copy(self, action_result, container_id, destination, source, source_local=False,
                               destination_local=False, keep_owner=False, run_automation=True, label=None):
        """ destination: where new container is being made """
        """ source: where the original container is """
        """ Create a copy of this existing container, including all of its artifacts """

        # Retrieve original container
        self._base_uri = source
        url = '/rest/container/{}'.format(container_id)

        ret_val, response, resp_data = self._make_rest_call(url, action_result, ignore_auth=source_local)

        if phantom.is_fail(ret_val):
            return ret_val

        container = resp_data
        # Remove data from original we dont want
        container.pop('asset', None)
        container.pop('artifact_count', None)
        container.pop('start_time', None)
        container.pop('source_data_identifier', None)
        container.pop('ingest_app')
        container.pop('tenant')
        container.pop('id')
        if label:
            container['label'] = label
        if keep_owner:
            container['owner_id'] = container.pop('owner')
        else:
            container.pop('owner')

        if destination_local:
            container['asset_id'] = int(self.get_asset_id())
        # container['ingest_app_id'] = container.pop('ingest_app', None)

        self._base_uri = destination
        ret_val, response, resp_data = self._make_rest_call('/rest/container', action_result,
                                method='post', data=container, ignore_auth=destination_local)

        if phantom.is_fail(ret_val):

            act_message = action_result.get_message()

            if 'ingesting asset_id' in act_message:
                act_message += 'If Multi-tenancy is enabled, please make sure the asset is assigned a tenant'
                action_result.set_status(ret_val, act_message)

            elif '"owner_id" Not found' in act_message:
                act_message += '. Try setting the keep_owner parameter to false.'
                action_result.set_status(ret_val, act_message)

            return ret_val

        try:
            new_container_id = resp_data['id']
        except KeyError:
            # The newly created container wont get cleaned up
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UNABLE_RETRIEVE_ID)

        # Retrieve artifacts from old container
        url = '/rest/container/{}/artifacts'.format(container_id)
        params = {'sort': 'id', 'order': 'asc', 'page_size': 0}
        self._base_uri = source
        ret_val, response, resp_data = self._make_rest_call(url, action_result, params=params, ignore_auth=source_local)

        artifacts = resp_data['data']
        if artifacts:
            for artifact in artifacts:
                # Remove data from artifacts that we dont want
                artifact.pop('update_time', None)
                artifact.pop('create_time', None)
                artifact.pop('start_time', None)
                artifact.pop('end_time', None)
                artifact.pop('asset_id', None)
                artifact.pop('container', None)
                artifact.pop('id', None)
                artifact['run_automation'] = False
                artifact['container_id'] = new_container_id
                artifact['owner_id'] = artifact.pop('owner')
            artifacts[-1]['run_automation'] = run_automation

            self._base_uri = destination
            ret_val = self._add_artifact_list(action_result, artifacts, ignore_auth=destination_local)
            if phantom.is_fail(ret_val):
                return action_result.set_status(ret_val, "Container created:{0}. {1}".format(new_container_id, action_result.get_message()))

        action_result.update_summary({'container_id': new_container_id, 'artifact_count': len(artifacts)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container_new(self, action_result, container_json, artifact_json_list):
        try:
            container = json.loads(container_json)
            if not isinstance(container, dict):
                return action_result.set_status(phantom.APP_ERROR, "Please provide json formatted dictionary in container_json action parameter")

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                    "Error parsing container JSON: {}".format(self._get_error_message_from_exception(e)))

        if artifact_json_list:
            try:
                artifacts = json.loads(artifact_json_list)
                if not isinstance(artifacts, list):
                    return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_CONTAINER_ARTIFACT)
                else:
                    for artifact in artifacts:
                        if not isinstance(artifact, dict):
                            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_CONTAINER_ARTIFACT)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                                "Error parsing artifacts list JSON: {}".format(self._get_error_message_from_exception(e)))
        else:
            artifacts = []

        ret_val, response, resp_data = self._make_rest_call('/rest/container', action_result, method='post', data=container)
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            new_container_id = resp_data['id']
        except KeyError:
            # The newly created container wont get cleaned up
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UNABLE_RETRIEVE_ID)

        if artifacts:
            for artifact in artifacts:
                artifact['run_automation'] = False
                artifact['container_id'] = new_container_id
            artifacts[-1]['run_automation'] = True

            ret_val = self._add_artifact_list(action_result, artifacts)
            if phantom.is_fail(ret_val):
                return action_result.set_status(ret_val, "Container created:{0}. {1}".format(new_container_id, action_result.get_message()))

        action_result.update_summary({'container_id': new_container_id, 'artifact_count': len(artifacts)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_json = param['container_json']
        container_artifacts = param.get('container_artifacts')
        return self._create_container_new(action_result, container_json, container_artifacts)

    def _export_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        label = param.get('label')
        run_automation = param.get('run_automation', False)

        container_id = param.get('container_id')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        destination = self._base_uri
        source = self.get_phantom_base_url()

        return self._create_container_copy(action_result, container_id, destination,
                    source, source_local=True, keep_owner=param.get('keep_owner', False),
                    run_automation=run_automation, label=label)

    def _import_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param.get('container_id')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        destination = self.get_phantom_base_url()
        source = self._base_uri

        return self._create_container_copy(action_result, container_id, destination,
                source, destination_local=True, keep_owner=param.get('keep_owner', False))

    def _get_action(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url_params = {
                '_filter_action': '"{0}"'.format(param['action_name']),
                'include_expensive': '',
                'sort': 'start_time',
                'order': 'desc',
            }

        parameters = {}
        if 'parameters' in param:

            try:
                parameters = json.loads(param.get('parameters'))
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Could not load JSON from 'parameters' parameter")

            search_key, search_value = parameters.popitem()

            try:
                is_not_string = isinstance(search_value, (float, int, bool))
                formatted_search_value = json.dumps(search_value) if is_not_string else '\\"{}\\"'.format(search_value)
                url_params['_filter_result_data__regex'] = '\'parameter.*\\"{0}\\": {1}\''.format(search_key, formatted_search_value)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while creating filter string to search action results data")

        if 'time_limit' in param:
            hours = param.get('time_limit')
            ret_val, hours = self._validate_integer(action_result, hours, 'time_limit')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            time_str = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            url_params['_filter_start_time__gt'] = '"{0}"'.format(time_str)

        if 'max_results' in param:
            limit = param.get('max_results')
            ret_val, limit = self._validate_integer(action_result, limit, 'max_results')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            url_params['page_size'] = limit

        if 'app' in param:

            app_name = param.get('app')
            app_params = {'_filter_name__iexact': '"{0}"'.format(app_name)}
            ret_val, response, resp_json = self._make_rest_call('/rest/app', action_result, params=app_params)

            if phantom.is_fail(ret_val):
                return ret_val

            if resp_json['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Could not find app with name '{0}'".format(app_name))

            url_params['_filter_app'] = resp_json['data'][0]['id']

        if 'asset' in param:

            asset = param.get('asset')
            asset_params = {'_filter_name__iexact': '"{0}"'.format(asset)}
            ret_val, response, resp_json = self._make_rest_call('/rest/asset', action_result, params=asset_params)

            if phantom.is_fail(ret_val):
                return ret_val

            if resp_json['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Could not find asset with name '{0}'".format(asset))

            url_params['_filter_asset'] = resp_json['data'][0]['id']

        ret_val, response, resp_json = self._make_rest_call('/rest/app_run', action_result, params=url_params)

        if phantom.is_fail(ret_val):
            return ret_val

        count = 0
        if len(parameters) > 0:

            for action_run in resp_json['data']:

                for result in action_run['result_data']:

                    cur_params = result['parameter']

                    found = True

                    try:
                        parameters_items = parameters.iteritems()
                    except Exception:
                        parameters_items = parameters.items()

                    for k, v in parameters_items:
                        if cur_params.get(k) != v:
                            found = False
                            break

                    if found:
                        count += 1
                        action_result.add_data(action_run)

            if count == 0:
                return action_result.set_status(phantom.APP_SUCCESS, PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)
            else:
                action_result.set_summary({'num_results': count})
                return action_result.set_status(phantom.APP_SUCCESS)

        elif resp_json['count'] == 0:
            return action_result.set_status(phantom.APP_SUCCESS, PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)

        for action_run in resp_json['data']:
            action_result.add_data(action_run)

        action_result.set_summary({'num_results': len(resp_json['data'])})
        self.debug_print("Successfully executed the action.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_list(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        row_number = param.get('row_number')
        ret_val, row_number = self._validate_integer(action_result, row_number, 'row_number', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        row_values_as_list = param['row_values_as_list']

        list_name = param.get('list_name')
        list_id = param.get('id')

        if not list_name and not list_id:
            return action_result.set_status(phantom.APP_ERROR, "Either the custom list's name or id must be provided")

        if list_name:
            # Encode list_identifier to consider special url encoded characters like '\' in URL
            list_identifier = quote(list_name, safe='')
        else:
            ret_val, list_identifier = self._validate_integer(action_result, list_id, 'id')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            row_values = json.loads(row_values_as_list)
            if not isinstance(row_values, list):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_NON_EMPTY_PARAM_VALUE)
            if not row_values:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_NON_EMPTY_PARAM_VALUE)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                "Could not load JSON formatted list from the row_values_as_list parameter: {}".format(
                    self._get_error_message_from_exception(e)))

        data = {
            "update_rows": {
                str(row_number): row_values
            }
        }

        # make rest call
        ret_val, response, resp_data = self._make_rest_call('/rest/decided_list/{}'.format(list_identifier),
                                        action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(resp_data)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = True
        self.debug_print("Successfully executed the action.")
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _no_op(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sleep_seconds = param.get('sleep_seconds')
        ret_val, sleep_seconds = self._validate_integer(action_result, sleep_seconds, 'sleep_seconds', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        remainder = sleep_seconds % 60

        self.send_progress("Sleeping...")
        for i in range(0, int(sleep_seconds / 60)):
            time.sleep(60)
            self.send_progress("Slept for {} minute{}...", i + 1, 's' if i else '')

        if remainder:
            time.sleep(remainder)

        return action_result.set_status(phantom.APP_SUCCESS, "Slept for {} seconds".format(sleep_seconds))

    def _handle_get_custom_fields(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param['container_id']
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        custom_fields_endpoint = f"/rest/container/{container_id}"
        ret_val, response, resp_data = self._make_rest_call(
            custom_fields_endpoint, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        custom_fields = resp_data['custom_fields']
        final_cf = {}
        for cf in custom_fields:
            if custom_fields[cf]:
                final_cf[cf] = custom_fields[cf]

        if final_cf=={}:
            return action_result.set_status(phantom.APP_SUCCESS, "No custom fields were found.")
        
        action_result.add_data(final_cf)
        return action_result.set_status(phantom.APP_SUCCESS, "custom fields were found.")

    def _handle_add_comment(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param.get('container_id', self.get_container_id())
        comment = param.get('comment')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = '/rest/container_comment'

        comment_data = {
            "container_id": container_id,
            "comment": comment
        }

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=comment_data, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to create comment')
            return action_result.set_status(phantom.APP_ERROR, "Failed to create comment: {}".format(action_result.get_message()))
        return action_result.set_status(phantom.APP_SUCCESS, "Comment created")

    
    def _handle_export_container_tgz(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        
        ## Umair - Debug
        # import debugpy
        # debugpy.listen(("127.0.0.1", 5678))
        # debugpy.wait_for_client()
        # debugpy.breakpoint()
        
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param['container_id']
        path = param['export_path']

        endpoint = f'/rest/container/{container_id}/attachments'
        params = {'sortKey':'create_time', 'sortOrder': 'desc','pretty': 'true', 'page_size': 0}
        ret_val, response, resp_data = self._make_rest_call(
            endpoint, action_result, params=params, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = f'/rest/container/{container_id}/export'
        params = None
        if resp_data['data']:
            params = {'file_list[]': [x['id'] for x in resp_data['data']]}

        ret_val, response, resp_data = self._make_rest_call(
            endpoint, action_result, params=params, headers=None
        )

        try:
            if not os.path.exists(f"{path}"):
                os.makedirs(f"{path}")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Failure creating directory {path}. Details: {e}")
        
        filename = f"{container_id}_{response.headers.get('filename')}"
        exported_filename = f"{path}/{filename}"

        if not os.path.isfile(exported_filename):
            with open(exported_filename,'wb') as f:
                f.write(response.content)
        else:
            result = {'filename':exported_filename, 'file_available': True,'message':'Failed to export the container, exported file already exists.', 'container_id': container_id}
            action_result.add_data(result)
            summary = action_result.update_summary(result)
            return action_result.set_status(phantom.APP_ERROR, f"Failure exporting container, already exists {exported_filename}.")
        
        result = {'filename':exported_filename, 'file_available': True, 'message':'Container exported successfully.', 'container_id': container_id}
        action_result.add_data(result)
        
        summary = action_result.update_summary(result)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_markdownify(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        html_string = param['html_string']

        response = markdownify(html_string)
        if response:
            ret_val = True

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)
    

    def _handle_update_custom_fields(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        custom_fields_json = param['custom_fields_json']

        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        
        update = {}

        if custom_fields_json:
            try:
                clean_json = json.loads(custom_fields_json)
            except Exception:
                clean_json = self.load_dirty_json(custom_fields_json, action_result, "custom_fields_json")

            if clean_json is None:
                # print(clean_json)
                return action_result.get_status()

        update["custom_fields"] = clean_json
        custom_fields_endpoint = f"/rest/container/{container_id}"
        ret_val, response, resp_data = self._make_rest_call(
            custom_fields_endpoint, action_result, data=update, headers=None, method="post"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_data)

        return action_result.set_status(phantom.APP_SUCCESS, "Custom fields were updated successfully.")


    def _handle_import_container_tgz(self, param):
        success = False
        message = None
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        file_path = param['file_path']
        delete_after_import = param['delete_after_import']

        if not os.path.isfile(file_path):
            result = {'filename':file_path, 'file_available': False,'message':'Container to upload must be a valid file, can not find the file to upload.'}
            action_result.add_data(result)
            summary = action_result.update_summary(result)
            return action_result.set_status(phantom.APP_ERROR, f"Container to upload must be a valid file, can not find {file_path}.")

        config = self.get_config()
        baseurl = 'https://{}'.format(config['phantom_server'])
        verify_cert = config.get('verify_certificate', False)
        auth = None

        if config.get('username') or config.get('password') or config.get('auth_token'):
            auth = (config.get('username'), config.get('password'))
            uid = config.get('username',None)
            pwd = config.get('password',None)
            ph_auth_token = config.get('auth_token',None)


        soar = splunksoarupload(baseurl=baseurl, username=uid, password=pwd,ph_auth_token=ph_auth_token, verify_certificate=verify_cert)
        authenticated, message, csrf = soar.login()
        if authenticated:
            ret_val, response = soar.upload_chunked(csrftoken=csrf,file=file_path)
            # print(f"Importing container {file_path} - ret_val: {ret_val} - response: {response}")


        if phantom.is_fail(ret_val):      
            result = {'message':response}
            action_result.add_data(result)
            summary = action_result.update_summary(result)
            return action_result.set_status(phantom.APP_ERROR, response)

        if delete_after_import:
            os.remove(file_path)

        result = {'message':response}
        action_result.add_data(result)

        summary = action_result.update_summary(result)
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_find_containers(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_key = param.get("container_key")
        exact_match = param.get('exact_match', False)
        value = param.get('value', '')
        numeric_value = param.get('numeric_value', '')
        
        url_enc_value = quote(value, safe='')
        if container_key and exact_match and numeric_value is False:
            endpoint = '/rest/container?_filter_{}={}&page_size=0&pretty'.format(container_key, repr(url_enc_value))
        elif container_key and exact_match and numeric_value:
            endpoint = '/rest/container?_filter_{}={}&page_size=0&pretty'.format(quote(container_key, safe=''), value)
        elif container_key and numeric_value is False:
            endpoint = '/rest/container?_filter_{}__{}={}&page_size=0&pretty'.format(quote(container_key, safe=''),"icontains", repr(url_enc_value))
        elif container_key and numeric_value:
            endpoint = '/rest/container?_filter_{}__{}={}&page_size=0&pretty'.format(quote(container_key, safe=''),"icontains", value)
        else:
            endpoint = '/rest/container?_filter_{}__{}={}&page_size=0&pretty'.format(quote(container_key, safe=''),"icontains", repr(url_enc_value))

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            action_result.update_summary({'containers_found': 0, 'server_ip': self._base_uri.split('//')[1]})
            return action_result.set_status(phantom.APP_ERROR, 'Error retrieving records: {0}'.format(action_result.get_message()))
        
        result_records = []
        if 'data' in resp_data:
            records = resp_data['data']
            for rec in records:
                result_records.append(
                    {
                        'id': rec['id'], 
                        'name': rec['name'], 
                        'description': rec['description'],
                        'label': rec['label'],
                        'status': rec['status']
                })
            action_result.update_data(result_records)

            action_result.update_summary({'containers_found': len(records),'server_ip': self._base_uri.split('//')[1]})
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.update_summary({'containers_found': 0, 'server_ip': self._base_uri.split('//')[1]})
            return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_artifact_json(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        artifact_id = param['artifact_id']

        endpoint = '/rest/artifact/' + str(artifact_id)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_status())
            return action_result.get_status()

        action_result.add_data(resp_data)

        summary = action_result.update_summary({})
        return action_result.set_status(phantom.APP_SUCCESS, 'Artifact JSON retrieved successfully.')
    

    def _handle_put_artifact_json(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_json = param['artifact_json']
        destination_container_id = param['destination_container_id']

        endpoint = '/rest/artifact'
        art_json  = json.loads(artifact_json)
        art_json['container_id'] = str(destination_container_id)
        art_json.pop('container')
        art_json.pop('id')

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=art_json, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        
        action_result.add_data(resp_data)

        summary = action_result.update_summary({})
        summary['destination_container_id'] = int(destination_container_id)
        summary['destination_artifact_id'] = int(resp_data['id'])
        return action_result.set_status(phantom.APP_SUCCESS, "The artifact was uploaded/created successfully.")


    def _handle_upload_to_vault(self, param):
        success = False
        message = None
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_file_path = param['vault_file_path']
        container_id = param['container_id']
        vault_file_name = param['vault_file_name']

        if not os.path.isfile(vault_file_path):
            result = {'filename':vault_file_path, 'file_available': False,'message':'Vault file to upload must be a valid file, can not find the file to upload.'}
            action_result.add_data(result)
            summary = action_result.update_summary(result)
            return action_result.set_status(phantom.APP_ERROR, f"Vault file to upload must be a valid file, can not find {vault_file_path}.")


        config = self.get_config()
        baseurl = 'https://{}'.format(config['phantom_server'])
        verify_cert = config.get('verify_certificate', False)
        auth = None

        if config.get('username') or config.get('password') or config.get('auth_token'):
            auth = (config.get('username'), config.get('password'))
            uid = config.get('username',None)
            pwd = config.get('password',None)
            ph_auth_token = config.get('auth_token',None)


        soar = splunksoarupload(baseurl=baseurl, username=uid, password=pwd,ph_auth_token=ph_auth_token, verify_certificate=verify_cert)
        authenticated, message, csrf = soar.login()
        if authenticated:
            ret_val, response = soar.upload_chunked_to_vault(csrftoken=csrf,file=vault_file_path,filename=vault_file_name,container_id=container_id)
            # print(f"Importing Vault File {vault_file_name} with path {vault_file_path} - ret_val: {ret_val} - response: {response}")
        else:
            message = "Failed to authenticate"
            return action_result.set_status(phantom.APP_ERROR, message)

        if phantom.is_fail(ret_val):     
            result = {'message':response}
            action_result.add_data(result)
            summary = action_result.update_summary(result)
            return action_result.set_status(phantom.APP_ERROR, response)


        result = {'message':response}
        action_result.add_data(result)
        summary = action_result.update_summary(result)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_vault_item_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']
        container_id = param['container_id']

        if not container_id and not vault_id:
            container_id = ph_rules.get_current_container_id_()
        if vault_id and not isinstance(vault_id, str):
            raise TypeError(f"vault_id must be a string. A {type(vault_id)} was provided.")
        if container_id:
            if isinstance(container_id, str):
                try:
                    container_id = int(container_id)
                except ValueError:
                    raise ValueError(f"container_id must be an integer or integer-type string. A non-integer string was provided.") from None
            if not isinstance(container_id, int):
                raise TypeError(f"container_id must be an integer or integer-type string. A {type(container_id)} was provided.")


        vault_info_endpoint = '/rest/vault_document'
        vault_info_endpoint = vault_info_endpoint + f"?_filter_hash='{vault_id}'&_filter_container='{container_id}'&page_size=1&page=0&pretty"
        ret_success, ret_status_code, response = self._make_rest_call(vault_info_endpoint, action_result, params=None, headers=None)

        if ret_success and response['count']>0:
            vault_info = response['data']
            for item in vault_info:
                attach_info_endpoint = '/rest/container'
                attach_info_endpoint = attach_info_endpoint + f"/{container_id}/attachments?_filter_vault_document={item['id']}&page_size=1&page=0&pretty"
                ret_success, ret_status_code, response = self._make_rest_call(attach_info_endpoint, action_result, params=None, headers=None)
                if ret_success and response['count']>0:
                    attach_info = response['data']
                    for attachitem in attach_info:
                        item['vault_item_path'] = attachitem['_pretty_path']
                        item['container_attachment_id'] = attachitem['id']
                        item['container_vault_document_id'] = item['id']
                        if attachitem['task']:
                            item['container_task_id'] = attachitem['task']
                        if attachitem['_pretty_task']:
                            item['container_task_name'] = attachitem['_pretty_task']
                        if attachitem['created_via']:
                            item['vault_item_created_via'] = attachitem['created_via']
                        if attachitem['container']:
                            item['vault_item_container_id'] = attachitem['container']
                        if attachitem['_pretty_container']:
                            item['vault_item_container_name'] = attachitem['_pretty_container']
                        action_result.add_data(item)
                        summary = action_result.update_summary({})
                        action_result.update_summary({
                            'vault_item_count': len(vault_info),
                            'vault_item_tags' : item.get('tags', None),
                            'vault_item_first_seen': item['first_seen_time'],
                            'vault_item_meta': item['meta'],
                            'vault_item_size': item['size'],
                            'message': 'Vault item was found.',
                            'vault_item_id':item['id'],
                            'vault_item_names':item['names'],
                            'vault_item_path':attachitem['_pretty_path'],
                            'container_attachment_id':attachitem['id'],
                            'container_vault_document_id':item['id'],
                            'container_task_id':attachitem['task'],
                            'container_task_name':attachitem['_pretty_task'],
                            'vault_item_created_via':attachitem['created_via'],
                            'vault_item_container_id':attachitem['container'],
                            'vault_item_container_name':attachitem['_pretty_container'],
                            })
                        return action_result.set_status(phantom.APP_SUCCESS, "Vault item was found.")
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Error: No vault items found for criteria provided.")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error: No vault items found for criteria provided.")


    def _handle_get_users_and_roles(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        include_automation = param.get('include_automation', False)
        user_info_endpoint = '/rest/user_info'
        ret_success, ret_status_code, response = self._make_rest_call(user_info_endpoint, action_result, params=None, headers=None)
        
        if phantom.is_fail(ret_success):
            return action_result.get_status()

        users = []
        roles = []

        users = response['users']
        roles = response['roles']
        raw = {}
        raw['users'] = users
        raw['roles'] = roles
        temp_users_list = []
        temp_roles_list = []
        temp_user = []
        temp_role = []
        act_output_users = []
        act_output_roles = []
        
        for user in users:
            tmp_out_users = {}
            if include_automation:
                temp_user_info = (f"{user['id']}",f"{user['username']}",f"{user['display_name']}")
                temp_users_list.append(temp_user_info)
                temp_user.append(user['display_name'])
                if 'id' in user and user['id']:
                    tmp_out_users['id'] = user['id']
                if 'username' in user and user['username']:
                    tmp_out_users['username'] = user['username']
                if 'display_name' in user and user['display_name']:
                    tmp_out_users['display_name'] = user['display_name']
                
                if tmp_out_users:
                    act_output_users.append(tmp_out_users)
                    
            else:
                if not user['automation']:
                    temp_user_info = (f"{user['id']}",f"{user['username']}",f"{user['display_name']}")
                    temp_users_list.append(temp_user_info)
                    temp_user.append(user['display_name'])
                    
                    if 'id' in user and user['id']:
                        tmp_out_users['id'] = user['id']
                    if 'username' in user and user['username']:
                        tmp_out_users['username'] = user['username']
                    if 'display_name' in user and user['display_name']:
                        tmp_out_users['display_name'] = user['display_name']

                    if tmp_out_users:
                        act_output_users.append(tmp_out_users)


        for role in roles:
            tmp_out_roles = {}
            if include_automation and role['count']!=0:
                temp_role_info = (f"{role['id']}",f"{role['name']}")
                temp_roles_list.append(temp_role_info)
                temp_role.append(role['name'])
                
                if 'id' in role and role['id']:
                    tmp_out_roles['id'] = role['id']
                if 'name' in role and role['name']:
                    tmp_out_roles['name'] = role['name']
                
                if tmp_out_roles:
                    act_output_roles.append(tmp_out_roles)
                    
            else:
                if role['name']!="Automation" and role['count']!=0:
                    temp_role_info = (f"{role['id']}",f"{role['name']}")
                    temp_roles_list.append(temp_role_info)
                    temp_role.append(role['name'])
                    
                    if 'id' in role and role['id']:
                        tmp_out_roles['id'] = role['id']
                    if 'name' in role and role['name']:
                        tmp_out_roles['name'] = role['name']

                    if tmp_out_roles:
                        act_output_roles.append(tmp_out_roles)
        

        final_output = {}
        final_output['users'] = act_output_users
        final_output['roles'] = act_output_roles
        final_output['raw'] = raw

        action_result.add_data(final_output)

        summary = action_result.update_summary({'users_count' : len(act_output_users)})
        summary = action_result.update_summary({'roles_count' : len(act_output_roles)})
        
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_create_task(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        
        task_name = param['task_name']
        phase_name = param['phase']

        task_desc = param.get('task_desc', '')
        create_new_container = param.get('create_new_container', '')
        container_id = param.get('container_id', '')
        task_note_required = param.get('task_note_required_to_complete')
        label_for_new_container = param.get('label_for_new_container')
        name_for_new_container = param.get('name_for_new_container')
        assign_to_user = param.get('assign_to_user')
        assign_to_role = param.get('assign_to_role')
        create_task_tracking_artifacts = param.get('create_task_tracking_artifacts')
        task_playbooks = param.get('task_playbooks')
        
        create_new_container = None
        task_tmpl = {}
        tasks_list = []
        task = {}
        pb_list=[]
        ac_list = []
        task_desc_detail = None
        phase_id = None
        task_result = []
        soar_server_ip = self._base_uri.split('//')[1]
        
        if not isinstance(phase_name, str):
            raise TypeError("phase is required or is not a string")

        if not isinstance(task_name, str):
            raise TypeError("task_name is required or is not a string")
            
        if not container_id:
            raise TypeError("container_id param can not be empty.")
            
        # function to parse the task playbook input    
        def parse_task_pb_str(task_pb_str):
            output = []
            items = task_pb_str.split(",")

            for item in items:
                if "/" not in item:
                    # print(f"Warning: Skipping malformed item without '/': {item}")
                    continue

                scm, playbook = item.split("/", 1)

                # Trim whitespace just in case
                scm = scm.strip()
                playbook = playbook.strip()

                if not scm or not playbook:
                    # print(f"Warning: Skipping incomplete entry: {item}")
                    continue

                playbook_entry = {"scm": scm, "playbook": playbook}

                output.append(playbook_entry)

            return output
        

        def find_user_id(username):
            user_id = None
            user_info_endpoint = '/rest/ph_user'
            ret_success, ret_status_code, resp, baseuri = self._make_rest_call_custom(user_info_endpoint, data=None, headers=None)

            if ret_status_code==200 and resp['count']>0:
                users_list = resp['data']
                user_id = next((item['id'] for item in users_list if item['username'] == username), None) 

            return user_id
        
        def find_role_id(role):
            role_id = None
            role_info_endpoint = '/rest/role'
            ret_success, ret_status_code, resp, baseuri = self._make_rest_call_custom(role_info_endpoint, data=None, headers=None)
            if ret_status_code==200 and resp['count']>0:
                role_list = resp['data']
                role_id = next((item['id'] for item in role_list if item['name'] == role), None) 

            return role_id


        
        if container_id:
            if container_id in ['new', 'New', 'NEW']:
                create_new_container = True
            elif ',' in container_id:
                container_id = list(set(container_id.replace(" ", "").split(",")))
            elif isinstance(container_id,str):
                container_id = [int(container_id)]
            elif isinstance(container_id,int):
                container_id = [int(container_id)]
            else:
                raise TypeError("Unable to process container_id input.")
        else:
            raise TypeError("Please provide container id, or type new to create new container for the task.")
        
        if create_new_container and label_for_new_container:  # pylint: disable=used-before-assignment
            cdata = {}
            cdata['name'] = name_for_new_container if name_for_new_container else f"{phase_name} - {task_name}"
            cdata['label'] = str(label_for_new_container)
            ret_success, ret_status_code, resp, baseuri = self._make_rest_call_custom('/rest/container', data=cdata, headers=None, method='post')
            if ret_success:
                container_id = [resp['id']]
            else:
                raise Exception(f"Unable to create a new container under label {cdata['label']}.")
                return
        
        def fetch_local_asset_conf(local_asset_id):
            local_asset_url = ph_rules.build_phantom_rest_url('asset')
            local_asset_url = local_asset_url + "/" + str(local_asset_id)
            local_asset_name = None
            asset_response = ph_rules.requests.get(local_asset_url,verify=False)
            if asset_response.status_code==200:
                local_asset_name = asset_response.json()['name']
            return local_asset_name
        
        
        def add_phase(container_id: int,phase_name: str):
            phase_tmpl = {}
            phase_tmpl['name'] = phase_name
            phase_tmpl['container_id'] = container_id
            ret_success, ret_status_code, resp = self._make_rest_call('/rest/workbook_phase', action_result, data=phase_tmpl, headers=None, method='post')            

            if ret_status_code.status_code==200 and ret_success:
                phase_id = resp['id']
            else:
                phase_id = None
                return action_result.set_status(phantom.APP_ERROR, "Failed to add the Phase(s).")

            return phase_id
        

        def get_phase_id(container_id: int,phase_name: str):
            phase_url = f"/rest/container/{container_id}/phases"
            phase_url = phase_url + f'?_filter_name="{phase_name}"&sort=id&order=desc&page_size=1'
            ret_success, ret_status_code, resp = self._make_rest_call(phase_url, action_result, params=None, headers=None, method='get')  

            if ret_status_code.status_code==200 and ret_success and resp['count']>0:
                phase_id = resp['data'][0]['id']
            else:
                phase_id = add_phase(int(container_id),phase_name)

            return phase_id
        

        def add_task(task):
            ret_success, ret_status_code, resp = self._make_rest_call('/rest/workbook_task', action_result, data=task, params=None, headers=None, method='post')
            if ret_status_code.status_code==200 and ret_success and resp['id']:
                task_id = resp['id']
                # print(f"Task Tracking Artifact setting is {create_task_tracking_artifacts}")
                if create_task_tracking_artifacts:
                    raw={}
                    cef={}
                    cef['local_asset_name'] = fetch_local_asset_conf(self.get_asset_id())
                    cef['soar_server_ip'] = soar_server_ip
                    cef['container_id'] = task['container_id']
                    cef['phase_id'] = task['phase_id']
                    cef['task_id'] = task_id
                    cef['task_desc'] = task['description']
                    cef['task_name'] = task['name']
                    cef['asset_id'] = self.get_asset_id()
                    if assign_to_user:
                        cef['owner'] = assign_to_user
                    if assign_to_role:
                        cef['role'] = assign_to_role
                    success, message, artifact_id= ph_rules.add_artifact(
                        container=self.get_container_id(), raw_data=raw, cef_data=cef, label='artifact',
                        name=f"{cef['local_asset_name']} - Remote Task Tracking Artifact", severity='medium',
                        identifier=None,
                        artifact_type='network')

            else:
                task_id = None

            return ret_success, ret_status_code.status_code, task_id

        def find_task(task):
            task_url = '/rest/workbook_task'
            task_url = task_url + f"?_filter_container_id={task['container_id']}&_filter_name='{task['name']}'&_filter_description='{task['description']}'&_filter_phase={task['phase_id']}&pretty&sort=id&order=asc&page_size=100&page=0"

            ret_success, ret_status_code, resp = self._make_rest_call(task_url, action_result, params=None, headers=None, method='get')
            if ret_status_code.status_code==200 and ret_success and resp['count']>0:

                task_id = resp['data'][0]['id']
                existing_task = True
                task_data = resp['data']
            else:
                task_id = None
                existing_task = False
                task_data = None

            return existing_task, task_id, task_data

        action_result = self.add_action_result(ActionResult(dict(param)))

        task_result_old = []
        for it in container_id:
            task_new = {}
            task_old = {}

            phase_id = get_phase_id(int(it), phase_name)
            task['container_id'] = int(it)
            task['phase_id'] = phase_id
        
            if isinstance(task_name, str):
                task['name'] = task_name

            if task_note_required is True:
                task['is_note_required'] = True
            elif task_note_required is False:
                task['is_note_required'] = False
                
            if task_desc:    
                task['description'] = task_desc
            else:
                task['description'] = "Task Description is Not Available"
            
            if assign_to_user:
                task_owner = find_user_id(assign_to_user)
                if task_owner:
                    task['owner'] = task_owner

            if assign_to_role:
                task_owner_role = find_role_id(assign_to_role)
                if task_owner_role:
                    task['role'] = task_owner_role

            if 'role' in task and 'owner' in task:
                task.pop('role', None)

            if task_playbooks:
                pb_list = parse_task_pb_str(task_playbooks)

                if pb_list:
                    task['playbooks'] = pb_list    

            existing_task, task_id, task_data = find_task(task)

            if not existing_task:
                task_add_success, ret_status_code, task_id = add_task(task)
                if not task_add_success:
                    return action_result.set_status(phantom.APP_ERROR, "Failed to add the task(s).")

                task_new['container_id'] = int(it)
                task_new['phase_id'] = phase_id
                task_new['phase_name'] = phase_name
                task_new['task_id'] = task_id
                task_new['task_desc'] = task_desc
                task_new['task_name'] = task_name
                task_new['exiting_task'] = False
                if assign_to_user:
                    task_new['owner'] = assign_to_user
                if assign_to_role:
                    task_new['role'] = assign_to_role

                task_result.append(task_new)

            elif existing_task:
                task_new['exiting_task'] = True
                task_new['container'] = int(it)
                task_new['phase_id'] = task_data[0]['phase']
                task_new['phase_name'] = phase_name
                task_new['task_id'] = task_data[0]['id']
                task_new['task_desc'] = task_data[0]['description']
                task_new['task_name'] = task_data[0]['name']

                if task_data[0]['status'] in [0,1,2]:
                    if task_data[0]['status']==0:
                        task_new['status'] = 'Not Started Yet'
                    elif task_data[0]['status']==1:
                        task_new['status'] = 'Completed'
                    elif task_data[0]['status']==2:
                        task_new['status'] = 'In Progress'
                if task_data[0]['create_time']:
                    task_new['create_time'] = task_data[0]['create_time']
                if task_data[0]['modified_time']:
                    task_new['modified_time'] = task_data[0]['modified_time']
                if task_data[0]['start_time']:
                    task_new['start_time'] = task_data[0]['start_time']
                if task_data[0]['end_time']:
                    if task_data[0]['status']==1:
                        task_new['end_time'] = task_data[0]['end_time']
                if task_data[0]['notes']:
                    task_new['notes'] = task_data[0]['notes']
                if task_data[0]['files']:
                    task_new['files'] = task_data[0]['files']

                if task_data[0]['_pretty_owner']:
                    task_new['owner'] = task_data[0]['_pretty_owner']
                if task_data[0]['_pretty_role']:
                    task_new['role'] = task_data[0]['_pretty_role']

                task_result_old.append(task_old)

            action_result.add_data(task_new)

        summary = action_result.update_summary({})
        summary['total_new_tasks'] = len(task_result)
        summary['total_existing_tasks'] = len(task_result_old)
        summary['soar_server'] = soar_server_ip
        summary['message'] = "Task(s) created successfully."

        return action_result.set_status(phantom.APP_SUCCESS, "Task(s) created successfully.")


    def _handle_get_task_status(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        task_id = param['task_id']
        task_data = None

        task_url = '/rest/workbook_task'
        task_url = task_url + f"?_filter_id={task_id}&pretty&sort=id"

        ret_success, ret_status_code, resp = self._make_rest_call(task_url, action_result, params=None, headers=None, method='get')

        if ret_status_code.status_code==200 and ret_success and resp['count']>0:

            task_id = resp['data'][0]['id']
            existing_task = True
            task_data = resp['data'][0]
            if task_data['status'] in [0,1,2]:
                if task_data['status']==0:
                    task_data['status'] = 'Not Started Yet'
                elif task_data['status']==1:
                    task_data['status'] = 'Completed'
                elif task_data['status']==2:
                    task_data['status'] = 'In Progress'

        else:
            existing_task = False
            return action_result.set_status(phantom.APP_ERROR, "Task was not found.")

        if isinstance(task_data,dict):
            action_result.add_data(task_data)

        summary = action_result.update_summary({})
        summary['task_id'] = task_data['id']
        if task_data['_pretty_role']:
            summary['role'] = task_data['_pretty_role']
        if task_data['_pretty_owner']:
            summary['owner'] = task_data['_pretty_owner']
        summary['container_id'] = task_data['container']
        summary['status'] = task_data['status']

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_user_id(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param['username']

        ret_val, response, resp_data = self._make_rest_call(
            '/rest/ph_user', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response.status_code==200 and resp_data['count']>0:
            users_list = resp_data['data']
            user_id = next((item['id'] for item in users_list if item['username'] == username), None)
            user_detail = next((item for item in users_list if item['username'] == username), None) 

        if user_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Could not find the user.")
        
        action_result.add_data(user_detail)

        summary = action_result.update_summary({})
        summary['username'] = username
        summary['user_id'] = user_id

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_get_role_id(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        role = param['role']

        ret_val, response, resp_data = self._make_rest_call(
            '/rest/role', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response.status_code==200 and resp_data['count']>0:
            role_list = resp_data['data']
            role_id = next((item['id'] for item in role_list if item['name'] == role), None)
            role_detail = next((item for item in role_list if item['name'] == role), None) 

        if role_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Could not find the role.")
        
        action_result.add_data(role_detail)

        summary = action_result.update_summary({})
        summary['role'] = role
        summary['role_id'] = role_id

        return action_result.set_status(phantom.APP_SUCCESS)



    def _handle_get_vault_item(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']
        container_id = param['vault_container_id']
        local_container_id = param['local_container_id']


        def fetch_vault_item_id(vault_hash, container_id):

            vault_info_endpoint = '/rest/vault_document'
            vault_info_endpoint = vault_info_endpoint + f"?_filter_hash='{vault_hash}'&_filter_container='{container_id}'&page_size=1&page=0&pretty"

            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(vault_info_endpoint, data=None, headers=None, method='get')

            vault_document_id = None
            if ret_status_code==200 and response['count']>0:
                vault_info = response['data'][0]
                vault_document_id = vault_info['id']

            return vault_document_id, vault_hash, container_id


        def fetch_container_attachment_id(vault_document_id, container_id):
            container_attachment_endpoint = '/rest/container_attachment'
            container_attachment_endpoint = container_attachment_endpoint + f"?_filter_container='{container_id}'&_filter_vault_document={vault_document_id}&page_size=1&page=0&pretty"
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(container_attachment_endpoint, data=None, headers=None, method='get')

            container_attachment_id = None
            if ret_status_code==200 and response['count']>0:
                attach_id_info = response['data'][0]
                container_attachment_id = attach_id_info['id']

            return container_attachment_id, vault_document_id, container_id

        
        vault_document_id, vault_id, container_id = fetch_vault_item_id(vault_hash=vault_id, container_id=container_id)

        if vault_document_id:
            container_attachment_id, vault_document_id, container_id = fetch_container_attachment_id(vault_document_id, container_id)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve the vault document id from container vault.")

        if container_attachment_id:
            vault_item_download = f"/download?id={container_attachment_id}&container_id={container_id}"

            config = self.get_config()
            baseurl = 'https://{}'.format(config['phantom_server'])
            verify_cert = config.get('verify_certificate', False)
            auth = None

            if config.get('username') or config.get('password') or config.get('auth_token'):
                auth = (config.get('username'), config.get('password'))
                uid = config.get('username',None)
                pwd = config.get('password',None)
                ph_auth_token = config.get('auth_token',None)


            soar = splunksoarupload(baseurl=baseurl, username=uid, password=pwd,ph_auth_token=ph_auth_token, verify_certificate=verify_cert)
            authenticated, message, csrf = soar.login()
            if authenticated:
                ret_val, message, response = soar.get_file_attachment(csrftoken=csrf,attachment_id=container_attachment_id,container_id=container_id)

                if response.headers['Content-Disposition']:
                    fname = response.headers['Content-Disposition']
                    fname = fname.split('"')
                    fname = fname[1]
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Failed to download the vault file from the container vault.")

        else:
            return action_result.set_status(phantom.APP_ERROR, "Failed to retrieve the container attachment id from container vault.")
        
        ret_val = self._add_file_to_vault(action_result, data_stream=response.content, file_name=fname, recursive=None, container_id=local_container_id)

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to upload the file to the vault.')
            return action_result.set_status(phantom.APP_ERROR, "{}".format(action_result.get_message()))

        res_data = action_result.get_data()
        summ_data = res_data[0]
        summary = action_result.update_summary({})
        summary['vault_document_id'] = summ_data['vault_document']
        summary['vault_attachment_id'] = summ_data['id']
        summary['vault_document_hash'] = summ_data['hash']
        summary['vault_document_sha256hash'] = summ_data['metadata']['sha256']
        summary['vault_document_name'] = summ_data['name']
        summary['vault_document_path'] = summ_data['path']
        summary['vault_document_size'] = summ_data['size']
        summary['vault_document_type'] = summ_data['mime_type']
        summary['remote_container_id'] = container_id
        summary['local_container_id'] = local_container_id

        return action_result.set_status(phantom.APP_SUCCESS, 'The file was retrieved and uploaded to the vault successfully.')    


    def _handle_update_indicator_tags(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        indicator_value = param['indicator_value']
        add_tags = param.get('add_tags','')
        remove_tags = param.get('remove_tags','')
        tags_already_added = set()
        tags_already_removed = set()
        final_ind_tags = {}

        if not add_tags and not remove_tags:
            self.save_progress(f"No tags were provided.")
            return action_result.set_status(phantom.APP_ERROR, "No tags were provided")
        
        if add_tags:
            add_tags = set([x.strip() for x in add_tags.split(',')])
        else:
            add_tags = set()

        if remove_tags:
            remove_tags = set([x.strip() for x in remove_tags.split(',')])
        else:
            remove_tags = set()

        search_indicators_url = f"/rest/indicator_by_value?indicator_value={indicator_value}&_special_fields=true&_special_labels=true&_special_contains=true"

        ret_success, ret_status_code, resp = self._make_rest_call(
            search_indicators_url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_success):
            self.save_progress(f"Unable to find the indicator with the provided ioc value {indicator_value}.")
            return action_result.set_status(phantom.APP_ERROR, "{}".format(action_result.get_message()))

        current_ind_tags = resp['tags']
        current_ind_id = resp['id']
        current_ind_tags = set(current_ind_tags)

        for tag in add_tags:
            if tag in current_ind_tags:
                tags_already_added.add(tag)


        for tag in remove_tags:
            if tag not in current_ind_tags:
                tags_already_removed.add(tag)


        _tags = (current_ind_tags | add_tags) - remove_tags
        final_ind_tags['tags'] = list(_tags)

        update_indicators_url = f"/rest/indicator/{current_ind_id}"

        ret_success, ret_status_code, resp = self._make_rest_call(
            update_indicators_url, action_result, data=final_ind_tags, params=None, headers=None, method="post"
        )

        if phantom.is_fail(ret_success):
            self.save_progress(f"Unable to update the indicator having ioc value {indicator_value}.")
            return action_result.set_status(phantom.APP_ERROR, "{}".format(action_result.get_message()))


        action_result.add_data(resp)

        action_result.set_summary({
            'indicator_id': current_ind_id,
            'indicator_value': indicator_value,
            'current_tags':final_ind_tags['tags'],
            'tags_added': ', '.join((list(add_tags - tags_already_added))),
            'tags_removed': ', '.join((list(remove_tags - tags_already_removed))),
            'tags_already_present': ', '.join((list(tags_already_added))),
            'tags_already_absent': ', '.join((list(tags_already_removed)))
            })


        return action_result.set_status(phantom.APP_SUCCESS, "Indicator was updated successfully.")


    def _handle_find_indicator(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ioc_value = param['ioc_value']

        search_indicators_url = f"/rest/indicator_by_value?indicator_value={ioc_value}&_special_fields=true&_special_labels=true&_special_contains=true"

        ret_success, ret_status_code, resp = self._make_rest_call(
            search_indicators_url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_success):
            self.save_progress(f"Unable to find the indicator with the provided ioc value {ioc_value}.")
            return action_result.set_status(phantom.APP_ERROR, "{}".format(action_result.get_message()))

        action_result.add_data(resp)
        return action_result.set_status(phantom.APP_SUCCESS,"Found Indicator.")


    def _handle_get_container_options(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_success, ret_status_code, resp = self._make_rest_call(
            '/rest/container_options', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_success):
            self.save_progress(f"Unable to get container options from destination.")
            return action_result.set_status(phantom.APP_ERROR, "Unable to get container options from destination. Error: {}".format(action_result.get_message()))

        action_result.add_data(resp)
        summary = action_result.update_summary({})
        summary['status_count'] = len(resp['status'])
        summary['severity_count'] = len(resp['severity'])
        summary['sensitivity_count'] = len(resp['sensitivity'])
        summary['label_count'] = len(resp['label'])
        summary['tags_count'] = len(resp['tags'])
        summary['message'] = "Successfully retrieved container options."
        
        return action_result.set_status(phantom.APP_SUCCESS,"Successfully retrieved container options.")


    def _handle_set_container_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        status = param['status']
        
        ret_success, ret_status_code, resp = self._make_rest_call(
            '/rest/container_options', action_result, params=None, headers=None
        )

        if resp is None or (ret_status_code!=200 and len(resp['status'])==0):
            return action_result.set_status(phantom.APP_ERROR, "Unable to get container status options from destination.. Error: {}".format(action_result.get_message()))
        
        valid_status_list = []
        for items in resp['status']:
            valid_status_list.append(items['name'])
        
        if status in valid_status_list:
            container_endpoint = f"/rest/container/{container_id}"
            data = {"status":status}

            ret_success, ret_status_code, resp = self._make_rest_call(
                container_endpoint, action_result, data=data, headers=None, method='post'
            )

            if phantom.is_fail(ret_success):
                return action_result.set_status(phantom.APP_ERROR, "Unable to set container status options from destination.. Error: {}".format(action_result.get_message()))
            
            # Add the response into the data section
            action_result.add_data(resp)
            summary = action_result.update_summary({})
            summary['status'] = status
            summary['success'] = resp['success']
            summary['container_id'] = resp['id']
            summary['message'] = "Successfully updated container status."
            return action_result.set_status(phantom.APP_SUCCESS,"Successfully updated container status.")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Invalid status value provided for the destination environment. Valid status values are: {}".format(valid_status_list))


    def _handle_get_container_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']

        container_status_endpoint = f"/rest/container/{container_id}/status"
        ret_val, ret_status_code, response = self._make_rest_call(
            container_status_endpoint, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['status'] = response['status']
        summary['status_type'] = response['status_type']
        summary['status_name'] = response['name']
        summary['status_id'] = response['id']

        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved the container status successfully.")


    def _handle_get_all_vault_items_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']

        url = f'/rest/container/{container_id}/attachments?pretty&page_size=0'
        ret_val, ret_status_code, response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Function to rename the keys as specified
        def rename_keys(data):
            for item in data:
                # Rename keys according to the provided mapping
                item['container_name'] = item.pop('_pretty_container', None)
                item['relative_create_time'] = item.pop('_pretty_create_time', None)
                item['user_displayname'] = item.pop('_pretty_user', None)
                item['hash'] = item.pop('_pretty_hash', None)
                item['vault_id'] = item.pop('_pretty_vault_id', None)
                item['size'] = item.pop('_pretty_size', None)
                item['path'] = item.pop('_pretty_path', None)
                item['metadata'] = item.pop('_pretty_metadata', None)
                item['aka'] = item.pop('_pretty_aka', None)
                item['container_id'] = item.pop('_pretty_container_id', None)
                item['contains'] = item.pop('_pretty_contains', None)

            return data

        # Process the data list and rename the keys
        processed_data = rename_keys(response['data'])

        for d in processed_data:
            action_result.add_data(d)

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_delete_vault_item(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']
        container_id = param['container_id']

        # function to get the attachment id from the container
        def get_vault_attachment_id(vault_id, container_id):

            if not container_id and not vault_id:
                container_id = ph_rules.get_current_container_id_()

            if vault_id and not isinstance(vault_id, str):
                raise TypeError(f"vault_id must be a string. A {type(vault_id)} was provided.")
            
            if container_id:
                if isinstance(container_id, str):
                    try:
                        container_id = int(container_id)
                    except ValueError:
                        raise ValueError(f"container_id must be an integer or integer-type string. A non-integer string was provided.") from None
                
                if not isinstance(container_id, int):
                    raise TypeError(f"container_id must be an integer or integer-type string. A {type(container_id)} was provided.")

            vault_attach_id = None
            vault_info_endpoint = '/rest/container'
            vault_info_endpoint = vault_info_endpoint + f"/{container_id}/attachments?page_size=0&pretty"
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(vault_info_endpoint, data=None, headers=None)

            if ret_status_code==200 and response['count']>0:
                vault_info = response['data']
                for item in vault_info:
                    if item['_pretty_vault_id']==vault_id:
                        vault_attach_id = item['id']
                    else:
                        continue

            return vault_attach_id

        vault_attachment_id = get_vault_attachment_id(vault_id, container_id)

        if vault_attachment_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Vault item was not found in the container.")

        vault_delete_endpoint = f'/rest/container_attachment/{vault_attachment_id}'
        ret_val, ret_status_code, response = self._make_rest_call(vault_delete_endpoint, action_result, params=None, headers=None, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "The vault item was successfully deleted from the container.")


    def _handle_get_container_notes(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']

        ret_val, ret_status_code, response = self._make_rest_call(
            f'/rest/container/{container_id}/notes?pretty&page_size=0', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if ret_status_code.status_code==200 and response['count']>0:
            for note in response['data']:
                note['task'] = note.pop('_pretty_task', None)
                note['phase'] = note.pop('_pretty_phase', None)
                note['author_username'] = note.pop('_pretty_author', None)
                note['author_userid'] = note.pop('author', None)
                note['artifact'] = note.pop('_pretty_artifact', None)
                note['container_name'] = note.pop('_pretty_container', None)
                note['container_id'] = note.pop('container', None)
                note['relative_create_time'] = note.pop('_pretty_create_time', None)
                note['relative_modified_time'] = note.pop('_pretty_modified_time', None)

                action_result.add_data(note)

            summary = action_result.update_summary({})
            summary['count'] = response['count']

        return action_result.set_status(phantom.APP_SUCCESS, "Notes from the container were fetched successfully.")


    def _handle_get_container_comments(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']

        ret_val, ret_status_code, response = self._make_rest_call(
            f'/rest/container/{container_id}/comments?pretty&page_size=0', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if ret_status_code.status_code==200 and response['count']>0:
            for comment in response['data']:
                comment['container_name'] = comment.pop('_pretty_container', None)
                comment['container_id'] = comment.pop('container', None)
                comment['relative_create_time'] = comment.pop('_pretty_create_time', None)
                comment['relative_time'] = comment.pop('_pretty_time', None)
                comment['user_display_name'] = comment.pop('_pretty_user', None)
                comment['user_id'] = comment.pop('user', None)

                action_result.add_data(comment)

            summary = action_result.update_summary({})
            summary['count'] = response['count']

        return action_result.set_status(phantom.APP_SUCCESS, "Comments from the container were fetched successfully.")


    def _handle_delete_artifact(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        artifact_id = param['artifact_id']

        artifact_delete_endpoint = f'/rest/artifact/{artifact_id}'
        ret_val, ret_status_code, response = self._make_rest_call(artifact_delete_endpoint, action_result, params=None, headers=None, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "The artifact was successfully deleted from the container.")


    def _handle_trigger_active_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param['container_id']
        rest_endpoint = f"/rest/container/{container_id}"
        data = {"run_automation":True}
        ret_val, ret_status, response = self._make_rest_call(
            rest_endpoint, action_result, data=data, headers=None, method='post'
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_run_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        playbook_to_run = param['playbook_to_run']
        playbook_scope = param['playbook_scope']

        run_data = {"container_id": int(container_id),"playbook_id": f"{playbook_to_run}","scope": f"{playbook_scope}","run": True}

        ret_val, ret_status_code, response = self._make_rest_call(
            '/rest/playbook_run', action_result, params=None, data=run_data, headers=None,method="post"
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['playbook_run_id'] = response['playbook_run_id']
        summary['received'] = response['received']

        return action_result.set_status(phantom.APP_SUCCESS, f"Playbook '{playbook_to_run}' with scope '{playbook_scope}' was launched on container '{container_id}' successfully.")



    def _handle_summarize_finding(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        ip_address_fields = param['ip_address_fields'].split(',')
        url_fields = param['url_fields'].split(',')
        hash_fields = param['hash_fields'].split(',')
        user_fields = param['user_fields'].split(',')
        domain_fields = param['domain_fields'].split(',')
        email_fields = param['email_fields'].split(',')
        mac_fields = param['mac_fields'].split(',')
        task_container_title_startswith = param.get('task_container_title_startswith')
        related_note_title_startswith = param.get('related_note_title_startswith')

        # # Set default value of related_event_count
        # related_event_count = 0
        
        # Events title begins with "Related Event ID: "
        if task_container_title_startswith:
            evi_evnt_str = task_container_title_startswith
        
        # Related note title starts with "Related Event"
        if related_note_title_startswith:
            note_evnt_str = related_note_title_startswith
        
        
        # Validate the container_id
        if container_id:
            if isinstance(container_id, str):
                try:
                    container_id = int(container_id)
                except ValueError:
                    raise ValueError(f"container_id must be an integer or integer-type string. A non-integer string was provided.") from None
            
            if not isinstance(container_id, int):
                raise TypeError(f"container_id must be an integer or integer-type string. A {type(container_id)} was provided.")

        # function to get the container information
        def get_container_info(container_id):

            c_info_endpoint = f'/rest/container/{container_id}'
            ret_success,ret_status_code, response, baseuri = self._make_rest_call_custom(c_info_endpoint, data=None, headers=None)

            container_info = None
            if ret_status_code==200 and response['id']:
                container_info = response
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the container information.")
            return container_info

        # function to get the artifacts from the container
        def get_container_artifacts(container_id):

            c_art_endpoint = f'/rest/container/{container_id}/artifacts?page_size=0'
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(c_art_endpoint, data=None, headers=None)

            container_artifacts = None
            if ret_status_code==200 and response['count']>0:
                container_artifacts = response

            return container_artifacts


        # function to get the container from the artifact
        def get_artifact_container(artifact_id):

            c_art_endpoint = f'/rest/artifact/{artifact_id}'
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(c_art_endpoint, data=None, headers=None)

            artifact_container = None
            if ret_status_code==200 and 'failed' not in response and response['container']:
                artifact_container = response['container']

            return artifact_container


        # function to get the related notes from the container
        def get_container_related_notes(container_id,note_evnt_str):
            c_note_endpoint = f"/rest/note?_filter_container_id={container_id}&_filter_title='{note_evnt_str}'&page_size=0"
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(c_note_endpoint, data=None, headers=None)

            container_related_notes = []
            related_ids = []
            if ret_status_code==200 and response['count']>0:
                for note in response['data']:
                    container_related_notes.append(note['content'])

                container_related_notes = list(set(container_related_notes))

            if container_related_notes:
                related_ids = re.findall(r'mission/(\d+)/analyst', '\n'.join(container_related_notes))
                related_ids = list(set(related_ids))

            related_ev_ids = []
            for r_id in related_ids:
                rid_info = get_container_info(r_id)
                if rid_info:
                    if rid_info['container_type'] == 'default':
                        rid_event_type = 'Event'
                    elif rid_info['container_type'] == 'case':
                        rid_event_type = 'Case'


                    if rid_info['container_update_time']:
                        rid_update_time = rid_info['container_update_time']
                    else:
                        rid_update_time = rid_info['create_time']

                    related_ev_ids.append({'event_id': r_id,
                                        'url' : f"{self._base_uri}/mission/{r_id}/analyst",
                                        'event_name': rid_info['name'],
                                        'event_type': rid_event_type,
                                        'event_status': rid_info['status'],
                                        'event_tags': rid_info['tags'],
                                        'event_label': rid_info['label'],
                                        'event_owner': rid_info['owner_name'],
                                        'event_update_time': convert_utc_to_local(rid_update_time)
                                        })
                
            return related_ev_ids



        # # function to get the related notes from the container
        # function to get the related case details if in_case is True
        def get_in_case_container(container_id):
            related_case_ids = None
            case_container_endpoint = f"/rest/case_container_map?_filter_source_container_id={container_id}"
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(case_container_endpoint, data=None, headers=None)

            case_ids = []
            if ret_status_code==200 and response['count']>0:
                for case_container in response['data']:
                    case_ids.append(case_container['case_container'])

                case_ids = list(set(case_ids))

            if case_ids:
                related_case_ids = []
                for r_id in case_ids:
                    rid_info = get_container_info(r_id)
                    if rid_info:
                        if rid_info['container_type'] == 'default':
                            rid_event_type = 'Event'
                        elif rid_info['container_type'] == 'case':
                            rid_event_type = 'Case'

                        if rid_info['container_update_time']:
                            rid_update_time = rid_info['container_update_time']
                        else:
                            rid_update_time = rid_info['create_time']

                        related_case_ids.append({'event_id': r_id,
                                            'url' : f"{self._base_uri}/mission/{r_id}/analyst",
                                            'event_name': rid_info['name'],
                                            'event_type': rid_event_type,
                                            'event_status': rid_info['status'],
                                            'event_tags': rid_info['tags'],
                                            'event_label': rid_info['label'],
                                            'event_owner': rid_info['owner_name'],
                                            'event_update_time': convert_utc_to_local(rid_update_time)
                                            })
                
            return related_case_ids


        # function to convert the UTC time to local time
        def convert_utc_to_local(utc_str):
            utc_dt = datetime.datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
            local_dt = utc_dt.astimezone()            
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")

        # function to get the indicator information
        ## New to add case info
        def get_indicator_info(ioc):
            #i_info_endpoint = f"/rest/indicator_by_value?indicator_value={ioc}&timerange=all"
            i_info_endpoint = f"/rest/indicator_by_value?indicator_value={ioc}&timerange=last_30_days"
            _,ret_status_code, response,baseurl = self._make_rest_call_custom(i_info_endpoint, data=None, headers=None)
            #print("######## DEBUG #######")
            #print(response)
            i_info = None
            if ret_status_code==200 and response['id']:
                i_info = {
                    "ioc": ioc,
                    "id": response["id"],
                    "first_seen": convert_utc_to_local(response["earliest_time"]),
                    "last_seen": convert_utc_to_local(response["latest_time"]),
                    "total_events": response["total_events"],
                    "open_events": response["open_events"],
                    "url": f"{baseurl}/indicators/{response['id']}/?timerange=all&sort=id&order=desc&per_page=10&page=1",
                    "tags": response["tags"],
                    "baseurl": f"{baseurl}",
                    "indicator_cases": []
                    }

                #indicators_events_endpoint = f'/rest/indicator_artifact?indicator_id={response["id"]}&page_size=0&sort=id&order=desc&timerange=all'
                indicators_events_endpoint = f'/rest/indicator_artifact?indicator_id={response["id"]}&page_size=0&sort=id&order=desc&timerange=last_30_days'
                _, another_ret_status_code, another_response, baseurl = self._make_rest_call_custom(indicators_events_endpoint, data=None, headers=None)

                if another_ret_status_code==200 and another_response['count']>0:
                    containers_list = []
                    for item in another_response['data']:
                        if item['container']:
                            containers_list.append(item['container'])
                    
                    containers_list = list(set(containers_list))
                    ind_cases = []
                    for cid in containers_list:
                        
                        ind_event_info = get_container_info(cid)
                        if ind_event_info and ind_event_info['container_type'] == 'case':
                            ind_cases.append(cid)

                    if ind_cases:
                        # sort and get the first 3 case ids
                        i_info['indicator_cases'] = sorted(ind_cases, reverse=True)[:3]

            return i_info


        evi_events_url = []
        evi_attachment_url = []
        evi_actionrun_url = []
        evi_notes_url = []
        evi_artifacts_url = []
        evidence_events = []
        task_events = []
        task_events_url = []
        related_case_ids = []

        # Function to get the evidences from the container
        def get_container_evidences(container_id):

            c_evi_endpoint = f'/rest/evidence?_special_content_type=True&_filter_container={container_id}&page_size=0'
            ret_success, ret_status_code, response, baseuri = self._make_rest_call_custom(c_evi_endpoint, data=None, headers=None)

            evidences = {}
            e_artifacts = []
            e_actionrun = []
            e_notes = []
            e_attach = []
            e_events = []
            evidence_found = False
            if ret_status_code==200 and response['count']>0:
                data = response['data']

                for item in data:
                    if item["_special_content_type"]=='container' or item['content_type']==16:
                        evidence_found = True
                        e_events.append({'event_id': item['object_id'],
                                        'url' : f"{baseuri}/mission/{item['object_id']}/analyst",
                                        'evidence_id': item['id']
                                        })
                        
                    elif item["_special_content_type"]=='artifact' or item['content_type']==13:
                        evidence_found = True                
                        e_artifacts.append({'artifact_id': item['object_id'],
                                        'url' : f"{baseuri}/mission/{container_id}/analyst/artifacts",
                                        'evidence_id': item['id']
                                        })
                        
                    elif item["_special_content_type"]=='containerattachment' or item['content_type']==17:
                        evidence_found = True
                        e_attach.append({'attachment_id': item['object_id'],
                                        'url' : f"{baseuri}/download?id={item['object_id']}&container_id={container_id}",
                                        'evidence_id': item['id']
                                        })
                        
                    elif item["_special_content_type"]=='actionrun' or item['content_type']==7:
                        evidence_found = True
                        e_actionrun.append({'actionrun_id': item['object_id'],
                                        'url' : f"{baseuri}/mission/{container_id}/analyst/action_run/{item['object_id']}",
                                        'evidence_id': item['id']
                                        })
                        
                    elif item["_special_content_type"]=='note' or item['content_type']==90:
                        evidence_found = True
                        e_notes.append({'note_id': item['object_id'],
                                        'url' : f"{baseuri}/mission/{container_id}/summary/notes/{item['object_id']}",
                                        'evidence_id': item['id']
                                        })


                if e_events and len(e_events) > 0:
                    evidences['events'] = e_events
                if e_actionrun and len(e_actionrun) > 0:
                    evidences['actionrun'] = e_actionrun
                if e_attach and len(e_attach) > 0:
                    evidences['attachments'] = e_attach
                if e_artifacts and len(e_artifacts) > 0:
                    evidences['artifacts'] = e_artifacts
                if e_notes and len(e_notes) > 0:
                    evidences['notes'] = e_notes

            return evidence_found, evidences


        # Function to flatten and deduplicate the list of IOCs
        def flatten_and_dedup(data):
            seen = set()
            result = []

            def should_split(s):
                # dont split if the string contains any of these characters
                block_chars = ['/', ':', ';', '?', '=', '@']
                return not any(c in s for c in block_chars)

            def process_item(item):
                if isinstance(item, list):
                    for sub_item in item:
                        process_item(sub_item)
                elif isinstance(item, str):
                    # split only if its likely multiple IOCs in one string (and not a command or url)
                    if ' ' in item and should_split(item):
                        for part in item.split():
                            part = part.strip()
                            if part and part not in seen:
                                seen.add(part)
                                result.append(part)
                    else:
                        item = item.strip()
                        if item and item not in seen:
                            seen.add(item)
                            result.append(item)

            process_item(data)
            return result


        # Process
        ret_val = False
        container_info = get_container_info(container_id)
        container_artifacts = get_container_artifacts(container_id)
        evidence_found, evidences = get_container_evidences(container_id)
        if note_evnt_str:
            related_ev_ids_notes = get_container_related_notes(container_id,note_evnt_str)

        if container_info:
            ret_val = True
            container_name = container_info['name']
            container_tags = container_info['tags']
            container_start_time = container_info['start_time']
            container_description = container_info['description']
            time_now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
            conainter_in_case = container_info['in_case']

        if conainter_in_case:
            related_case_ids = get_in_case_container(container_id)

        if container_artifacts:
            ret_val = True

    
        if phantom.is_fail(ret_val):
            return action_result.get_status()


        if evidence_found:
            if 'events' in evidences and len(evidences['events']) > 0:
                for event in evidences['events']:
                    # print("################################# DEBUG - Evidence #################################")
                    # print(event)
                    eid = event['event_id']
                    eid_info = get_container_info(eid)
                    # print("################################# DEBUG - Evidence Event Info #################################")
                    # print(eid_info)
                    eid_name = eid_info['name']
                    eid_tags = eid_info['tags']

                    if eid_info['container_update_time']:
                        eid_update_time = eid_info['container_update_time']
                    else:
                        eid_update_time = eid_info['create_time']

                    eid_status = eid_info['status']
                    eid_owner = eid_info['owner_name']

                    if eid_info['container_type'] == 'default':
                        eid_event_type = 'Event'
                    elif eid_info['container_type'] == 'case':
                        eid_event_type = 'Case'
                    
                    if evi_evnt_str and eid_name and eid_name.startswith(evi_evnt_str):
                        task_events.append({'event_id': eid,
                                            'url' : f"{self._base_uri}/mission/{eid}/analyst",
                                            'evidence_id': event['evidence_id'],
                                            'event_name': eid_name,
                                            'event_type': eid_event_type,
                                            'event_status': eid_status,
                                            'event_tags': eid_tags,
                                            'event_label': eid_info['label'],
                                            'event_owner': eid_owner,
                                            'event_update_time': convert_utc_to_local(eid_update_time)
                                            })
                    else:
                        evi_events_url.append({'event_id': eid,
                                            'url' : f"{self._base_uri}/mission/{eid}/analyst",
                                            'evidence_id': event['evidence_id'],
                                            'event_name': eid_name,
                                            'event_type': eid_event_type,
                                            'event_status': eid_status,
                                            'event_tags': eid_tags,
                                            'event_label': eid_info['label'],
                                            'event_owner': eid_owner,
                                            'event_update_time': convert_utc_to_local(eid_update_time)
                                            })


            if 'notes' in evidences and len(evidences['notes']) > 0:
                for note in evidences['notes']:
                    evi_notes_url.append(note['url'])

            if 'artifacts' in evidences and len(evidences['artifacts']) > 0:
                for artifact in evidences['artifacts']:
                    # evi_artifacts_url.append(artifact['url'])
                    # print("############################### DEBUG #################################")
                    # print(artifact)
                    artifact_container = get_artifact_container(artifact['artifact_id'])
                    # print(artifact_container)
                    if artifact_container:
                        eid_info = get_container_info(artifact_container)
                        # print(eid_info)
                        eid = artifact_container
                        eid_name = eid_info['name']
                        eid_tags = eid_info['tags']

                        if eid_info['container_update_time']:
                            eid_update_time = eid_info['container_update_time']
                        else:
                            eid_update_time = eid_info['create_time']

                        eid_status = eid_info['status']
                        eid_owner = eid_info['owner_name']

                        if eid_info['container_type'] == 'default':
                            eid_event_type = 'Event'
                        elif eid_info['container_type'] == 'case':
                            eid_event_type = 'Case'
                        
                        if evi_evnt_str and eid_name and eid_name.startswith(evi_evnt_str):
                            task_events.append({'event_id': eid,
                                                'url' : f"{self._base_uri}/mission/{eid}/analyst",
                                                'evidence_id': artifact['evidence_id'],
                                                'event_name': eid_name,
                                                'event_type': eid_event_type,
                                                'event_status': eid_status,
                                                'event_tags': eid_tags,
                                                'event_label': eid_info['label'],
                                                'event_owner': eid_owner,
                                                'event_update_time': convert_utc_to_local(eid_update_time)
                                                })
                            # print("############################### DEBUG #################################")
                            # print(task_events)

            if 'attachments' in evidences and len(evidences['attachments']) > 0:
                for attachment in evidences['attachments']:
                    evi_attachment_url.append(attachment['url'])

            if 'actionrun' in evidences and len(evidences['actionrun']) > 0:
                for actionrun in evidences['actionrun']:
                    evi_actionrun_url.append(actionrun['url'])


        es_finding = dict()
        ip_address_list = list()
        url_list = list()
        user_list = list()
        domain_list = list()
        email_list = list()
        hash_list = list()
        mac_list = list()
        temp_ip_address_list = list()
        temp_url_list = list()
        temp_user_list = list()
        temp_domain_list = list()
        temp_email_list = list()
        temp_hash_list = list()
        temp_mac_list = list()
        unique_ioc_count = int()

        artifact_count = None
        if container_artifacts and 'count' in container_artifacts and container_artifacts['count'] > 0:
            artifact_count = container_artifacts['count']
        if evi_events_url:
            evidence_events = evi_events_url

        if container_artifacts and 'data' in container_artifacts and len(container_artifacts['data']) > 0:
            for artifact in container_artifacts['data']:
                for field_name in artifact['cef']:
                    if field_name == "rule_description":
                        es_finding['finding_description'] = artifact['cef'][field_name]
                    if field_name == "drilldown_search":
                        es_finding['drilldown_search'] = artifact['cef'][field_name]
                    if field_name == "annotations.mitre_attack.mitre_technique":
                        es_finding['finding_mitre_techniques'] = artifact['cef'][field_name]
                    if field_name == "rule_title":
                        es_finding['finding_name'] = artifact['cef'][field_name]
                    if field_name == "_raw":
                        es_finding['finding_raw'] = artifact['cef'][field_name]
                    if field_name == "dvc":
                        es_finding['finding_dvc'] = artifact['cef'][field_name]
                    if field_name == "savedsearch_description":
                        es_finding['finding_search_description'] = artifact['cef'][field_name]                    
                    if field_name == "contributing_events":
                        es_finding['finding_contributing_events'] = artifact['cef'][field_name]
                        
                    ### IOCS                    
                    if field_name in ip_address_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_ip_address_list.append(artifact['cef'][field_name])

                    if field_name in url_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_url_list.append(artifact['cef'][field_name])

                    if field_name in hash_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_hash_list.append(artifact['cef'][field_name])

                    if field_name in user_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_user_list.append(artifact['cef'][field_name])

                    if field_name in domain_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_domain_list.append(artifact['cef'][field_name])

                    if field_name in email_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_email_list.append(artifact['cef'][field_name])

                    if field_name in mac_fields and artifact['cef'][field_name] != 'Not Available':
                        temp_mac_list.append(artifact['cef'][field_name])


        if temp_ip_address_list:
            # print("############################### DEBUG #################################")
            # print(f"temp_ip_address_list: {temp_ip_address_list}")
            # temp_ip_address_list = list(set(temp_ip_address_list))
            temp_ip_address_list = flatten_and_dedup(temp_ip_address_list)
            # print("############################### DEBUG #################################")
            # print(f"temp_ip_address_list: {temp_ip_address_list}")
            unique_ioc_count = unique_ioc_count + len(temp_ip_address_list)
            for ip in temp_ip_address_list:
                ip_indicator = get_indicator_info(ip)
                if ip_indicator:
                    ip_address_list.append(ip_indicator)
                else:
                    ip_address_list.append({"ioc": ip})


        if temp_url_list:
            # temp_url_list = list(set(temp_url_list))
            temp_url_list = flatten_and_dedup(temp_url_list)
            unique_ioc_count = unique_ioc_count + len(temp_url_list)
            for url in temp_url_list:
                url_indicator = get_indicator_info(url)
                if url_indicator:
                    url_list.append(url_indicator)
                else:
                    url_list.append({"ioc": url})


        if temp_user_list:
            # temp_user_list = list(set(temp_user_list))
            temp_user_list = flatten_and_dedup(temp_user_list)
            unique_ioc_count = unique_ioc_count + len(temp_user_list)
            for user in temp_user_list:
                user_indicator = get_indicator_info(user)
                if user_indicator:
                    user_list.append(user_indicator)
                else:
                    user_list.append({"ioc": user})


        if temp_domain_list:
            # temp_domain_list = list(set(temp_domain_list))
            temp_domain_list = flatten_and_dedup(temp_domain_list)
            unique_ioc_count = unique_ioc_count + len(temp_domain_list)
            for domain in temp_domain_list:
                domain_indicator = get_indicator_info(domain)
                if domain_indicator:
                    domain_list.append(domain_indicator)
                else:
                    domain_list.append({"ioc": domain})


        if temp_email_list:
            # temp_email_list = list(set(temp_email_list))
            temp_email_list = flatten_and_dedup(temp_email_list)
            unique_ioc_count = unique_ioc_count + len(temp_email_list)
            for email in temp_email_list:
                email_indicator = get_indicator_info(email)
                if email_indicator:
                    email_list.append(email_indicator)
                else:
                    email_list.append({"ioc": email})


        if temp_mac_list:
            # temp_mac_list = list(set(temp_mac_list))
            temp_mac_list = flatten_and_dedup(temp_mac_list)
            unique_ioc_count = unique_ioc_count + len(temp_mac_list)
            for mac in temp_mac_list:
                mac_indicator = get_indicator_info(mac)
                if mac_indicator:
                    mac_list.append(mac_indicator)
                else:
                    mac_list.append({"ioc": mac})


        if temp_hash_list:
            # temp_hash_list = list(set(temp_hash_list))
            temp_hash_list = flatten_and_dedup(temp_hash_list)
            unique_ioc_count = unique_ioc_count + len(temp_hash_list)
            for hash in temp_hash_list:
                hash_indicator = get_indicator_info(hash)
                if hash_indicator:
                    hash_list.append(hash_indicator)
                else:
                    hash_list.append({"ioc": hash})


        if 'finding_mitre_techniques' in es_finding and type(es_finding['finding_mitre_techniques']) is not list:
            tmp_mitre = es_finding['finding_mitre_techniques']
            es_finding['finding_mitre_techniques'] = list()
            es_finding['finding_mitre_techniques'].append(tmp_mitre)

        es_finding['ip_address_list'] = ip_address_list
        es_finding['url_list'] = url_list
        es_finding['user_list'] = user_list
        es_finding['domain_list'] = domain_list
        es_finding['email_list'] = email_list
        es_finding['hash_list'] = hash_list
        es_finding['mac_list'] = mac_list
        es_finding['container_id'] = container_id        
        
        
        container_stats = dict()
        if container_name:
            container_stats['container_name'] = container_name
        if artifact_count:
            container_stats['number_of_artifacts'] = artifact_count
        if unique_ioc_count>0:
            container_stats['unique_ioc_count'] = unique_ioc_count
        if container_id:
            container_stats['container_id'] = container_id
    

        data = dict()

        if es_finding:
            data['finding_information'] = es_finding
        if container_stats:
            data['container_stats'] = container_stats
        
        if evidence_events:
            data['evidence_events'] = evidence_events
        
        if task_events:
            data['task_events_list'] = task_events
        
        if related_ev_ids_notes:
            data['related_events'] = related_ev_ids_notes
        
        if related_case_ids:
            data['related_cases'] = related_case_ids

        # set base url
        data['baseurl'] = self._base_uri

        # Count length of related events
        related_record_count = 0
        if related_case_ids:
            related_record_count += len(related_case_ids)
        if related_ev_ids_notes:
            related_record_count += len(related_ev_ids_notes)
        if task_events:
            related_record_count += len(task_events)
        if evidence_events:
            related_record_count += len(evidence_events)

        # print("############################### DEBUG #################################")
        # print(f"related_record_count: {related_record_count}")

        if related_record_count > 0:
            data['related_record_count'] = related_record_count

        action_result.add_data(data)

        summary = action_result.update_summary({})
        summary['container_name'] = data['container_stats']['container_name']
        summary['number_of_artifacts'] = artifact_count
        summary['unique_ioc_count'] = unique_ioc_count
        summary['related_record_count'] = related_record_count
        return action_result.set_status(phantom.APP_SUCCESS)
    



    def _handle_get_evidence_data(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']

        c_evi_endpoint = f'/rest/evidence?_special_content_type=True&_filter_container={container_id}'

        ret_val, _,response = self._make_rest_call(
            c_evi_endpoint, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        
        evidences = {}
        e_artifacts = []
        e_actionrun = []
        e_notes = []
        e_attach = []
        e_events = []
        evidence_found = False
        if ret_val and response['count']>0:
            data = response['data']

            for item in data:
                if item["_special_content_type"]=='container' or item['content_type']==16:
                    evidence_found = True
                    e_events.append({'event_id': item['object_id'],
                                    'url' : f"{self._base_uri}/mission/{item['object_id']}/analyst",
                                    'evidence_id': item['id']
                                    })
                    
                elif item["_special_content_type"]=='artifact' or item['content_type']==13:
                    evidence_found = True                
                    e_artifacts.append({'artifact_id': item['object_id'],
                                    'url' : f"{self._base_uri}/mission/{container_id}/analyst/artifacts",
                                    'evidence_id': item['id']
                                    })
                    
                elif item["_special_content_type"]=='containerattachment' or item['content_type']==17:
                    evidence_found = True
                    e_attach.append({'attachment_id': item['object_id'],
                                    'url' : f"{self._base_uri}/download?id={item['object_id']}&container_id={container_id}",
                                    'evidence_id': item['id']
                                    })
                    
                elif item["_special_content_type"]=='actionrun' or item['content_type']==7:
                    evidence_found = True
                    e_actionrun.append({'actionrun_id': item['object_id'],
                                    'url' : f"{self._base_uri}/mission/{container_id}/analyst/action_run/{item['object_id']}",
                                    'evidence_id': item['id']
                                    })

                elif item["_special_content_type"]=='note' or item['content_type']==90:
                    evidence_found = True
                    e_notes.append({'note_id': item['object_id'],
                                    'url' : f"{self._base_uri}/mission/{container_id}/summary/notes/{item['object_id']}",
                                    'evidence_id': item['id']
                                    })

            if e_events and len(e_events) > 0:
                evidences['events'] = e_events
            if e_actionrun and len(e_actionrun) > 0:
                evidences['actionrun'] = e_actionrun
            if e_attach and len(e_attach) > 0:
                evidences['attachments'] = e_attach
            if e_artifacts and len(e_artifacts) > 0:
                evidences['artifacts'] = e_artifacts
            if e_notes and len(e_notes) > 0:
                evidences['notes'] = e_notes

        # Add the response into the data section
        action_result.add_data(evidences)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary_data = {}
        if e_events and len(e_events) > 0:
            summary_data['events'] = len(e_events)
        if e_actionrun and len(e_actionrun) > 0:
            summary_data['actionrun'] = len(e_actionrun)
        if e_attach and len(e_attach) > 0:
            summary_data['attachments'] = len(e_attach)
        if e_artifacts and len(e_artifacts) > 0:
            summary_data['artifacts'] = len(e_artifacts)
        if e_notes and len(e_notes) > 0:
            summary_data['notes'] = len(e_notes)

        summary = action_result.update_summary({})
        summary['count'] = summary_data
        summary['evidence_found'] = evidence_found

        return action_result.set_status(phantom.APP_SUCCESS, "Evidence data was fetched successfully.")
    

    def _handle_export_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        playbook_repo = param['playbook_repo']
        playbook_name = param['playbook_name']
        export_path = param['export_path']
        # export_path = "/opt/phantom/tmp"


        ## Function to get the SCM (Repo) information
        def get_scm_info(repo_name):
            scm_info_endpoint = f"/rest/scm?_filter_name='{repo_name}'"
            _, _,response,_ = self._make_rest_call_custom(scm_info_endpoint, data=None, headers=None)

            scm_info = None
            if 'count' in response and response['count'] > 0:
                scm_info = response['data'][0]
                # print(scm_info)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the SCM information.")
            return scm_info

        # Find Playbook IDs
        def get_playbook_ids(repo_id, name_contains=None):
            url = f"/rest/playbook?pretty=1&page_size=0&sort=name&order=asc&_filter_scm={repo_id}"
  
            name_contains = name_contains.strip().lower() if name_contains else None

            if name_contains and name_contains != "all":
                url += f"&_filter_name__icontains='{quote(name_contains)}'"

            _, _,response,_ = self._make_rest_call_custom(url, data=None, headers=None)

            if 'count' not in response or response['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Unable to find the playbook with given information.")

            data = response['data']
            playbooks = [{"id": playbook.get("id"), "name": playbook.get("name")} for playbook in data]
            return playbooks



        # Export the playbooks
        def export_playbooks(playbooks, export_path):
            if not playbooks and not isinstance(playbooks, list):
                return action_result.set_status(phantom.APP_ERROR, "The playbooks var is empty or not a list.")

            if not os.path.exists(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not available.")
            if not os.path.isdir(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not a directory.")
            if not os.access(export_path, os.W_OK):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not writable.")
            
            os.chdir(export_path)

            all_exports_successful = True
            exported_pb_count = 0
            failed_pb_count = 0
            total_pb_count = len(playbooks)
            exported_pb = []
            failed_pb = []
            for playbook in playbooks:
                playbook_id = playbook['id']
                playbook_name = playbook['name']
                url = f"/rest/playbook/{playbook_id}/export"

                ret_val,response,_ = self._make_rest_call(url, action_result,data=None, headers=None)

                if not response or not ret_val:
                    failed_pb.append(playbook_name)
                    failed_pb_count += 1
                    continue
                elif response and ret_val:
                    filename = f"{playbook_id}_{playbook_name}.tgz"
                    filename = filename.replace(" ", "_")
                    filepath = os.path.join(os.getcwd(), filename)
                    with open(filepath, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    exported_pb_count += 1
                    exported_pb.append({"playbook_id":playbook_id,"playbook_name": playbook_name, "exported_pb_path": filepath})

            return ret_val, exported_pb_count, exported_pb,failed_pb_count, failed_pb,total_pb_count



        # Find SCM IDs
        scm_info = get_scm_info(playbook_repo)

        if not scm_info:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the SCM with given information.")
        
        # Find Playbook IDs
        playbooks = get_playbook_ids(scm_info['id'], playbook_name)

        if not playbooks:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the playbook with given information.")

        ret_val, exported_pb_count, exported_pb,failed_pb_count, failed_pb,total_pb_count = export_playbooks(playbooks, export_path)

        if exported_pb_count > 0:
            action_result.add_data({"exported_playbooks": exported_pb})
            pb_export_success_message = f"Exported {exported_pb_count} out of {total_pb_count} playbooks successfully"

        if failed_pb_count > 0:
            action_result.add_data({"failed_playbooks": failed_pb})
            pb_export_success_message = f"Exported {exported_pb_count} out of {total_pb_count} playbooks successfully. Failed to export {failed_pb_count} playbooks."

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find and/or export playbook with given information.")

        summary = action_result.update_summary({})
        summary['exported_pb_count'] = exported_pb_count
        summary['failed_pb_count'] = failed_pb_count
        summary['total_pb_count'] = total_pb_count

        return action_result.set_status(phantom.APP_SUCCESS, pb_export_success_message)


    def _handle_export_custom_function(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        custom_function_repo = param['custom_function_repo']
        custom_function_name = param['custom_function_name']
        export_path = param['export_path']
        # export_path = "/opt/phantom/tmp"

        ## Function to get the SCM (Repo) information
        def get_scm_info(repo_name):
            scm_info_endpoint = f"/rest/scm?_filter_name='{repo_name}'"
            _, _,response,_ = self._make_rest_call_custom(scm_info_endpoint, data=None, headers=None)

            scm_info = None
            if 'count' in response and response['count'] > 0:
                scm_info = response['data'][0]
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the SCM information.")
            return scm_info

        # Find Playbook IDs
        def get_customfunctions_ids(repo_id, name_contains=None):
            url = f"/rest/custom_function?pretty=1&page_size=0&sort=name&order=asc&_filter_scm={repo_id}"

            # If name_contains is provided, add it to the URL
            name_contains = name_contains.strip().lower() if name_contains else None

            if name_contains and name_contains != "all":
                url += f"&_filter_name__icontains='{quote(name_contains)}'"

            _, _,response,_ = self._make_rest_call_custom(url, data=None, headers=None)

            if 'count' not in response or response['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Unable to find the Custom Functions with given information.")

            data = response['data']
            customfunctions = [{"id": cf.get("id"), "name": cf.get("name")} for cf in data]
            return customfunctions


        # Export the customfunctions
        def export_customfunctions(customfunctions, export_path):
            if not customfunctions and not isinstance(customfunctions, list):
                return action_result.set_status(phantom.APP_ERROR, "The customfunctions var is empty or not a list.")
            if not os.path.exists(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not available.")
            if not os.path.isdir(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not a directory.")
            if not os.access(export_path, os.W_OK):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not writable.")
            
            os.chdir(export_path)

            all_exports_successful = True
            exported_cf_count = 0
            failed_cf_count = 0
            total_cf_count = len(customfunctions)
            exported_cf = []
            failed_cf = []
            for cf in customfunctions:
                cf_id = cf['id']
                cf_name = cf['name']
                url = f"/rest/custom_function/{cf_id}/export"

                ret_val,response,_ = self._make_rest_call(url, action_result,data=None, headers=None)

                if not response or not ret_val:
                    failed_cf.append(cf_name)
                    failed_cf_count += 1
                    continue
                elif response and ret_val:
                    filename = f"{cf_id}_{cf_name}.tgz" 
                    filename = filename.replace(" ", "_")
                    filepath = os.path.join(os.getcwd(), filename)
                    with open(filepath, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    exported_cf_count += 1
                    exported_cf.append({"customfunction_id":cf_id,"customfunction_name": cf_name, "exported_cf_path": filepath})

            return ret_val, exported_cf_count, exported_cf,failed_cf_count, failed_cf,total_cf_count



        # Find SCM IDs
        scm_info = get_scm_info(custom_function_repo)
        if not scm_info:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the SCM with given information.")
        
        # Find Csutom Functions IDs
        customfunctions = get_customfunctions_ids(scm_info['id'], custom_function_name)

        if not customfunctions:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the customfunction with given information.")

        ret_val, exported_cf_count, exported_cf,failed_cf_count, failed_cf,total_cf_count = export_customfunctions(customfunctions, export_path)

        if exported_cf_count > 0:
            action_result.add_data({"exported_customfunctions": exported_cf})
            cf_export_success_message = f"Exported {exported_cf_count} out of {total_cf_count} customfunctions successfully"

        if failed_cf_count > 0:
            action_result.add_data({"failed_customfunctions": failed_cf})
            cf_export_success_message = f"Exported {exported_cf_count} out of {total_cf_count} customfunctions successfully. Failed to export {failed_cf_count} customfunctions."

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find and/or export custom function with given information.")

        summary = action_result.update_summary({})
        summary['exported_cf_count'] = exported_cf_count
        summary['failed_cf_count'] = failed_cf_count
        summary['total_cf_count'] = total_cf_count

        return action_result.set_status(phantom.APP_SUCCESS, cf_export_success_message)


    def _handle_export_custom_list(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        custom_list_name = param['custom_list_name']
        # export_path = param['export_path']
        # add as an action parameter later
        export_path = param['export_path']
        output_format = param['file_format']
        # add as an action parameter later
        # output_format = 'csv' # Default output format is csv, available options are "csv", "json", or "txt"

        # Find Custom List IDs
        def get_cl_ids(name_contains=None):
            url = f"/rest/decided_list?page_size=0&sort=id&order=desc"

            # If name_contains is provided, add it to the URL
            name_contains = name_contains.strip().lower() if name_contains else None

            if name_contains and name_contains != "all":
                url += f"&_filter_name__icontains='{quote(name_contains)}'"

            _, _,response,_ = self._make_rest_call_custom(url, data=None, headers=None)

            if 'count' not in response or response['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Unable to find the Custom List with given information.")

            data = response['data']
            customlists = [{"id": cl.get("id"), "name": cl.get("name")} for cl in data]
            return customlists


        # Export the customlists
        def export_customlists(customlists, export_path):
            if not customlists and not isinstance(customlists, list):
                return action_result.set_status(phantom.APP_ERROR, "The customlists var is empty or not a list.")
            if not os.path.exists(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not available.")
            if not os.path.isdir(export_path):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not a directory.")
            if not os.access(export_path, os.W_OK):
                return action_result.set_status(phantom.APP_ERROR, "The export path is not writable.")
            
            os.chdir(export_path)

            all_exports_successful = True
            exported_cl_count = 0
            failed_cl_count = 0
            total_cl_count = len(customlists)
            exported_cl = []
            failed_cl = []
            for cl in customlists:
                cl_id = cl['id']
                cl_name = cl['name']
                if output_format == 'json':
                    url = f"/rest/decided_list/{cl_id}"
                else:
                    url = f"/rest/decided_list/{cl_id}/formatted_content?_output_format={output_format}"

                ret_val,response,_ = self._make_rest_call(url, action_result,data=None, headers=None)

                if not response.text and response.status_code == 200:
                    ret_val = False
                    failed_cl.append(cl_name)
                    failed_cl_count += 1
                    continue
                elif response.text and response.status_code == 200:
                    ret_val = True
                    filename = f"{cl_id}_{cl_name}.{output_format}" 
                    filename = filename.replace(" ", "_")
                    filepath = os.path.join(os.getcwd(), filename)
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(response.text)
                    exported_cl_count += 1
                    file_size = os.path.getsize(filepath)
                    exported_cl.append({"customlist_id":cl_id,"customlist_name": cl_name, "exported_cl_filesize":file_size,"exported_cl_path": filepath})

            return ret_val, exported_cl_count, exported_cl,failed_cl_count, failed_cl,total_cl_count


        # Find Custom List IDs
        customlists = get_cl_ids(custom_list_name)

        if not customlists:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the custom lists with given information.")

        ret_val, exported_cl_count, exported_cl,failed_cl_count, failed_cl,total_cl_count = export_customlists(customlists, export_path)

        if exported_cl_count > 0:
            action_result.add_data({"exported_customlists": exported_cl})
            cl_export_success_message = f"Exported {exported_cl_count} out of {total_cl_count} custom lists successfully"

        if failed_cl_count > 0:
            action_result.add_data({"failed_customlists": failed_cl})
            cl_export_success_message = f"Exported {exported_cl_count} out of {total_cl_count} custom lists successfully. Failed to export {failed_cl_count} custom lists."

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find and/or export custom lists with given information.")

        summary = action_result.update_summary({})
        summary['exported_cl_count'] = exported_cl_count
        summary['failed_cl_count'] = failed_cl_count
        summary['total_cl_count'] = total_cl_count

        return action_result.set_status(phantom.APP_SUCCESS, cl_export_success_message)


    def _handle_add_evidence_data(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param['container_id']
        evidence_type = param['evidence_type']
        evidence_id = param['evidence_id']

        evi_data = {"container_id": container_id,"object_id": evidence_id,"content_type": evidence_type}

        # make rest call
        ret_val,_, response = self._make_rest_call(
            '/rest/evidence', action_result, params=None, data=evi_data,headers=None,method='post'
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)
    

    def _handle_list_playbooks(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        repo_name = param['repo_name']

        ## Function to get the SCM (Repo) information
        def get_scm_info(repo_name):
            scm_info_endpoint = f"/rest/scm?_filter_name='{repo_name}'"
            _, _,response,_ = self._make_rest_call_custom(scm_info_endpoint, data=None, headers=None)
            scm_info = None
            if 'count' in response and response['count'] > 0:
                scm_info = response['data'][0]
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the SCM information.")
            return scm_info

        # make rest call
        scm_info = get_scm_info(repo_name)
        if not scm_info:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the SCM with given information.")

        url = f"/rest/playbook?pretty=1&page_size=0&sort=name&order=asc&_filter_scm={scm_info['id']}"

        ret_val, _,response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if 'count' not in response or response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the playbook with given information.")

        for pb in response['data']:
            action_result.add_data(pb)

        summary = action_result.update_summary({})
        summary['playbook_count'] = len(response['data'])

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_find_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_name = param['repo_name']
        playbook_name = param['playbook_name']

        # make rest call
        if not repo_name:
            return action_result.set_status(phantom.APP_ERROR, "Repository name is required to find playbook.")
        if not playbook_name:
            return action_result.set_status(phantom.APP_ERROR, "Playbook name is required to find playbook.")
        
        if repo_name and repo_name.strip().lower()=='all':
            # If repo_name is 'all', we don't filter by repo, we look in all the repos
            url = f"/rest/playbook?pretty=1&page_size=0&sort=name&order=asc&_filter_name__icontains='{quote(playbook_name)}'"
        else:
            url = f"/rest/playbook?pretty=1&page_size=0&sort=name&order=asc&_filter_scm__name='{repo_name}'&_filter_name__icontains='{quote(playbook_name)}'"


        ret_val, _, response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "No playbook found with the given name in the specified repository.")
        
        # Add the response into the data section
        for item in response['data']:
            action_result.add_data(item)
        # action_result.add_data(response['data'])
        summary = action_result.update_summary({})
        summary['playbook_count'] = response['count']
        summary['repo_name'] = repo_name
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_import_playbook(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        repo = param['repo']
        playbook_tgz_file = param['playbook_tgz_file']
        ## add required param in action params input
        pb_force_import = param.get('force',False)
        if pb_force_import is False:
            pb_force_import = "false"
        elif pb_force_import is True:
            pb_force_import = "true"
        del_after_import = param.get('delete_after_import', False)
        # print("############################# DEBUG ##################################")
        # print(pb_force_import)
        # print("############################# DEBUG ##################################")
        # print(del_after_import)
        # return

        if not os.path.exists(playbook_tgz_file):
            return action_result.set_status(phantom.APP_ERROR, "No playbook found. Please provide a valid playbook .tgz file.")

        #### Function to delete the file after import
        def delete_file(file_path):
            if not os.path.exists(file_path):
                return f"File does not exist: {file_path}"
            
            if os.path.isdir(file_path):
                return f"Path is a directory, not a file: {file_path}"

            try:
                os.remove(file_path)
                return f"File deleted successfully: {file_path}", True
            except Exception as e:
                return f"Error deleting file: {file_path}\n{str(e)}", False

        ## read the file
        import base64

        with open(playbook_tgz_file, "rb") as f:
            playbook_content = f.read()
            encoded_playbook = base64.b64encode(playbook_content).decode("utf-8")

        data = {
            "playbook": encoded_playbook,
            "scm": repo,
            "force": pb_force_import
        }
        headers = {'Content-Type': 'application/json'}
        json_headers = json.dumps(headers)

        ret_val, _,response = self._make_rest_call(
            '/rest/import_playbook', action_result, params=None, headers=json_headers,method='post', data=data
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['success'] = response.get('success', False)
        summary['message'] = response.get('message', 'Playbook imported successfully.')
        summary['playbook_id'] = response.get('id', None)
        if del_after_import:
            delete_status,del_success = delete_file(playbook_tgz_file)
            if del_success:
                summary['file_deleted'] = del_success
                summary['delete_status'] = delete_status

        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_find_custom_function(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        repo_name = param['repo_name']
        custom_function_name = param['custom_function_name']

        # make rest call
        if not repo_name:
            return action_result.set_status(phantom.APP_ERROR, "Repository name is required to find custom function.")
        if not custom_function_name:
            return action_result.set_status(phantom.APP_ERROR, "Custom Function name is required to find custom function.")
        
        if repo_name and repo_name.strip().lower()=='all':
            # If repo_name is 'all', we don't filter by repo, we look in all the repos
            url = f"/rest/custom_function?pretty=1&page_size=0&sort=name&order=asc&_filter_name__icontains='{quote(custom_function_name)}'"
        else:
            url = f"/rest/custom_function?pretty=1&page_size=0&sort=name&order=asc&_filter_scm__name='{repo_name}'&_filter_name__icontains='{quote(custom_function_name)}'"


        ret_val, _, response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "No custom function found with the given name in the specified repository.")
        
        # Add the response into the data section
        for item in response['data']:
            action_result.add_data(item)
        # action_result.add_data(response['data'])
        summary = action_result.update_summary({})
        summary['custom_function_count'] = response['count']
        summary['repo_name'] = repo_name
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_find_custom_list(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        custom_list_name = param['custom_list_name']

        if custom_list_name and custom_list_name.strip().lower()=='all':
            url = f"/rest/decided_list?page_size=0&sort=id&order=desc"
        else:
            url = f"/rest/decided_list?page_size=0&sort=id&order=desc&_filter_name__icontains='{quote(custom_list_name)}'"

        # make rest call
        ret_val, _,response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "No custom list found with the given name.")
        
        # Add the response into the data section
        for item in response['data']:
            action_result.add_data(item)
        # action_result.add_data(response['data'])
        summary = action_result.update_summary({})
        summary['custom_list_count'] = response['count']
        return action_result.set_status(phantom.APP_SUCCESS)


    def _handle_list_custom_functions(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        repo_name = param['repo_name']

        ## Function to get the SCM (Repo) information
        def get_scm_info(repo_name):
            scm_info_endpoint = f"/rest/scm?_filter_name='{repo_name}'"
            _, _,response,_ = self._make_rest_call_custom(scm_info_endpoint, data=None, headers=None)
            scm_info = None
            if 'count' in response and response['count'] > 0:
                scm_info = response['data'][0]
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unable to fetch the SCM information.")
            return scm_info

        # make rest call
        scm_info = get_scm_info(repo_name)
        if not scm_info:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the SCM with given information.")

        url = f"/rest/custom_function?pretty=1&page_size=0&sort=name&order=asc&_filter_scm={scm_info['id']}"

        ret_val, _,response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if 'count' not in response or response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find the custom function with given information.")

        for pb in response['data']:
            action_result.add_data(pb)

        summary = action_result.update_summary({})
        summary['custom_function_count'] = len(response['data'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_custom_lists(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = f"/rest/decided_list?page_size=0&sort=id&order=desc"

        # make rest call
        ret_val, _,response = self._make_rest_call(
            url, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response['count'] == 0:
            return action_result.set_status(phantom.APP_ERROR, "No custom list were found.")
        
        # Add the response into the data section
        for item in response['data']:
            action_result.add_data(item)
        # action_result.add_data(response['data'])
        summary = action_result.update_summary({})
        summary['custom_list_count'] = response['count']
        return action_result.set_status(phantom.APP_SUCCESS)
    

    def _handle_import_custom_function(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        repo = param['repo']
        custom_function_tgz_file = param['custom_function_tgz_file']
        force = param['force']
        del_after_import = param['delete_after_import', False]

        if force is False:
            cf_force_import = "false"
        elif force is True:
            cf_force_import = "true"

        # print("############################# DEBUG ##################################")
        # print(cf_force_import)
        # print("############################# DEBUG ##################################")
        # print(del_after_import)
        # return

        if not os.path.exists(custom_function_tgz_file):
            return action_result.set_status(phantom.APP_ERROR, "No custom function found. Please provide a valid custom function .tgz file.")

        #### Function to delete the file after import
        def delete_file(file_path):
            if not os.path.exists(file_path):
                return f"File does not exist: {file_path}"
            
            if os.path.isdir(file_path):
                return f"Path is a directory, not a file: {file_path}"

            try:
                os.remove(file_path)
                return f"File deleted successfully: {file_path}", True
            except Exception as e:
                return f"Error deleting file: {file_path}\n{str(e)}", False

        ## read the file
        import base64

        with open(custom_function_tgz_file, "rb") as f:
            cf_content = f.read()
            encoded_customfunction = base64.b64encode(cf_content).decode("utf-8")

        data = {
            "custom_function": encoded_customfunction,
            "scm": repo,
            "force": cf_force_import
        }
        headers = {'Content-Type': 'application/json'}
        json_headers = json.dumps(headers)

        ret_val, _,response = self._make_rest_call(
            '/rest/import_custom_function', action_result, params=None, headers=json_headers,method='post', data=data
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['success'] = response.get('success', False)
        summary['message'] = response.get('message', 'Custom Function imported successfully.')
        summary['custom_function_id'] = response.get('id', None)
        if del_after_import:
            delete_status,del_success = delete_file(custom_function_tgz_file)
            if del_success:
                summary['file_deleted'] = del_success
                summary['delete_status'] = delete_status

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_import_custom_list(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        custom_list_json_file = param['custom_list_json_file']
        delete_after_import = param.get('delete_after_import', False)


        if not os.path.exists(custom_list_json_file):
            return action_result.set_status(phantom.APP_ERROR, "No custom list found. Please provide a valid custom list .json file.")

        #### Function to delete the file after import
        def delete_file(file_path):
            if not os.path.exists(file_path):
                return f"File does not exist: {file_path}"
            
            if os.path.isdir(file_path):
                return f"Path is a directory, not a file: {file_path}"

            try:
                os.remove(file_path)
                return f"File deleted successfully: {file_path}", True
            except Exception as e:
                return f"Error deleting file: {file_path}\n{str(e)}", False
            
        # Check if the file is a valid JSON file
        try:
            with open(custom_list_json_file, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return action_result.set_status(phantom.APP_ERROR, f"Invalid JSON file: {str(e)}")
        except FileNotFoundError:
            return action_result.set_status(phantom.APP_ERROR, f"File not found: {custom_list_json_file}")
        except Exception as e:  
            return action_result.set_status(phantom.APP_ERROR, f"Error reading file: {str(e)}")
        
        # Check if the JSON file contains the required fields
        if not isinstance(data, dict):
            return action_result.set_status(phantom.APP_ERROR, "JSON file must contain a dictionary with 'name' and 'content' fields.")
        if 'name' not in data or 'content' not in data:
            return action_result.set_status(phantom.APP_ERROR, "JSON file must contain 'name' and 'content' fields.")
        # Check if the content is a list
        if 'content' in data and not isinstance(data['content'], list):
            return action_result.set_status(phantom.APP_ERROR, "The 'content' field must be a list.")
        # Check if the name is a string
        if 'name' in data and not isinstance(data['name'], str):
            return action_result.set_status(phantom.APP_ERROR, "The 'name' field must be a string.")
        # Check if the content is not empty
        if 'content' in data and not data['content']:
            return action_result.set_status(phantom.APP_ERROR, "The 'content' field must not be empty.")
        # Check if the name is not empty
        if 'name' in data and not data['name']:
            return action_result.set_status(phantom.APP_ERROR, "The 'name' field must not be empty.")
        
        # Extract name and content
        list_name = data.get('name')
        content = data.get('content')

        if not list_name or not content:
            raise ValueError("JSON must contain 'name' and 'content' fields.")

        # URL-encode the list name for the REST URL
        url_enc_list_name = quote(list_name, safe='')

        # Prepare the payload with name and full content
        payload = {
            'name': url_enc_list_name,
            'content': content
        }

        # make rest call
        ret_val, _,response = self._make_rest_call(
            '/rest/decided_list', action_result, params=None, headers=None,method='post', data=payload
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['custom_list_id'] = response.get('id', None)
        summary['custom_list_name'] = url_enc_list_name
        summary['message'] = "Custom List imported successfully."

        if delete_after_import:
            delete_status,del_success = delete_file(custom_list_json_file)
            if del_success:
                summary['file_deleted'] = del_success
                summary['delete_status'] = delete_status

        return action_result.set_status(phantom.APP_SUCCESS)


    # Init function
    def initialize(self):

        # Validate that it is not localhost or 127.0.0.1,
        # this needs to be done just once, so do it here instead of handle_action,
        # since handle_action gets called for every item in the parameters list

        config = self.get_config()
        host = config['phantom_server']

        if host.startswith('http:') or host.startswith('https:'):
            return self.set_status(phantom.APP_ERROR,
                    'Please specify the actual IP or hostname used by the Phantom instance in the Asset config wihtout http: or https:')

        # Split hostname from port
        host = host.split(':')[0]

        if ph_utils.is_ip(host):
            try:
                packed = socket.inet_aton(host)
                unpacked = socket.inet_ntoa(packed)
            except Exception as e:
                return self.set_status(phantom.APP_ERROR,
                            "Unable to do ip to name conversion on {0}".format(host), self._get_error_message_from_exception(e))
        else:
            try:
                unpacked = socket.gethostbyname(host)
            except Exception:
                return self.set_status(phantom.APP_ERROR, "Unable to do name to ip conversion on {0}".format(host))

        if unpacked.startswith('127.'):
            return self.set_status(phantom.APP_ERROR, PHANTOM_ERR_SPECIFY_IP_HOSTNAME)

        if '127.0.0.1' in host or 'localhost' in host:
            return self.set_status(phantom.APP_ERROR, PHANTOM_ERR_SPECIFY_IP_HOSTNAME)

        self._base_uri = 'https://{}'.format(config['phantom_server'])
        self._verify_cert = config.get('verify_certificate', False)

        self._auth = None

        if config.get('username') and config.get('password'):
            self._auth = (config.get('username'), config.get('password'))

        self._level = 0

        return (phantom.APP_SUCCESS)


    ## Action Handler
    def handle_action(self, param):

        ## Umair - Debug app
        # import debugpy 
        # debugpy.listen(("127.0.0.1", 5678)) 
        # debugpy.wait_for_client() 
        # debugpy.breakpoint()

        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None

        action = self.get_action_identifier()


        if action == 'find_artifacts':
            result = self._find_artifacts(param)
        elif action == 'add_artifact':
            result = self._add_artifact(param)
        elif action == 'add_listitem':
            result = self._add_listitem(param)
        elif action == 'find_listitem':
            result = self._find_listitem(param)
        elif action == 'deflate_item':
            result = self._deflate_item(param)
        elif action == 'test_asset_connectivity':
            result = self._test_connectivity(param)
        elif action == 'create_container':
            result = self._create_container(param)
        elif action == 'export_container':
            result = self._export_container(param)
        elif action == 'import_container':
            result = self._import_container(param)
        elif action == 'get_action':
            result = self._get_action(param)
        elif action == 'update_list':
            result = self._update_list(param)
        elif action == 'no_op':
            return self._no_op(param)
        elif action == "update_artifact":
            return self._update_artifact(param)
        elif action == "add_note":
            return self._add_note(param)
        elif action == "tag_artifact":
            return self._tag_artifact(param)
        elif action == 'import_container_tgz':
            return self._handle_import_container_tgz(param)  
        elif action == 'update_custom_fields':
            return self._handle_update_custom_fields(param)
        elif action == 'markdownify':
            return self._handle_markdownify(param)
        elif action == 'export_container_tgz':
            return self._handle_export_container_tgz(param)
        elif action == 'add_comment':
            return self._handle_add_comment(param)
        elif action == 'get_custom_fields':
            return self._handle_get_custom_fields(param)
        elif action == 'find_containers':
            return self._handle_find_containers(param)
        elif action == 'get_artifact_json':
            return self._handle_get_artifact_json(param)
        elif action == 'put_artifact_json':
            return self._handle_put_artifact_json(param)
        elif action == 'upload_to_vault':
            return self._handle_upload_to_vault(param)
        elif action == 'get_vault_item_info':
            return self._handle_get_vault_item_info(param)
        elif action == 'create_task':
            return self._handle_create_task(param)
        elif action == 'get_users_and_roles':
            return self._handle_get_users_and_roles(param)
        elif action == 'get_task_status':
            return self._handle_get_task_status(param)
        elif action == 'get_role_id':
            return self._handle_get_role_id(param)
        elif action == 'get_user_id':
            return self._handle_get_user_id(param)
        elif action == 'get_vault_item':
            return self._handle_get_vault_item(param)
        elif action == 'update_indicator_tags':
            return self._handle_update_indicator_tags(param)
        elif action == 'find_indicator':
            return self._handle_find_indicator(param)
        elif action == 'set_container_status':
            return self._handle_set_container_status(param)
        elif action == 'get_container_options':
            return self._handle_get_container_options(param)
        elif action == 'get_container_status':
            return self._handle_get_container_status(param)
        elif action == 'get_all_vault_items_info':
            return self._handle_get_all_vault_items_info(param)
        elif action == 'delete_vault_item':
            return self._handle_delete_vault_item(param)
        elif action == 'get_container_comments':
            return self._handle_get_container_comments(param)
        elif action == 'get_container_notes':
            return self._handle_get_container_notes(param)
        elif action == 'delete_artifact':
            return self._handle_delete_artifact(param)
        elif action == 'run_playbook':
            return self._handle_run_playbook(param)
        elif action == 'trigger_active_playbook':
            return self._handle_trigger_active_playbook(param)
        elif action == 'summarize_finding':
            return self._handle_summarize_finding(param)
        elif action == 'export_custom_list':
            return self._handle_export_custom_list(param)
        elif action == 'export_custom_function':
            return self._handle_export_custom_function(param)
        elif action == 'export_playbook':
            return self._handle_export_playbook(param)
        elif action == 'get_evidence_data':
            return self._handle_get_evidence_data(param)
        elif action == 'find_playbook':
            return self._handle_find_playbook(param)
        elif action == 'list_playbooks':
            return self._handle_list_playbooks(param)
        elif action == 'add_evidence_data':
            return self._handle_add_evidence_data(param)
        elif action == 'import_playbook':
            return self._handle_import_playbook(param)
        elif action == 'import_custom_list':
            return self._handle_import_custom_list(param)
        elif action == 'import_custom_function':
            return self._handle_import_custom_function(param)
        elif action == 'list_custom_lists':
            return self._handle_list_custom_lists(param)
        elif action == 'list_custom_functions':
            return self._handle_list_custom_functions(param)
        elif action == 'find_custom_list':
            return self._handle_find_custom_list(param)
        elif action == 'find_custom_function':
            return self._handle_find_custom_function(param)

        return result


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = '{}login'.format(BaseConnector._get_phantom_base_url())
            r = requests.get(login_url, verify=verify, timeout=TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PhantomConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
