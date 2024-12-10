#!/usr/bin/python
#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) H3C.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from ansible.module_utils.urls import open_url
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.six.moves import http_client
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.six.moves.urllib.parse import urlparse


# Request header fields for different request types
GET_HEADERS = {'accept': 'application/json', 'OData-Version': '4.0'}
POST_HEADERS = {'content-type': 'application/json',
                'accept': 'application/json',
                'OData-Version': '4.0'}
PATCH_HEADERS = {'content-type': 'application/json',
                 'accept': 'application/json',
                 'OData-Version': '4.0'}
DELETE_HEADERS = {'accept': 'application/json', 'OData-Version': '4.0'}

# Failure message
FAIL_MSG = 'ID of the target %(resource)s resource when there is more ' \
           'than one %(resource)s is no longer allowed. Use the ' \
           '`resource_id` option to specify the target %(resource)s ID.'


class HDMRedfishUtils(object):

    def __init__(self, creds, root_uri, timeout, module, resource_id=None,
                 data_modification=False, strip_etag_quotes=False):
        """
        Initialization function
        :param creds: authentication field
        :param root_uri: root uri
        :param timeout: timeout
        :param module: module name
        :param resource_id: resource id
        :param data_modification: Whether the data is modified
        :param strip_etag_quotes: etag value
        """
        self.root_uri = root_uri
        self.creds = creds
        self.timeout = timeout
        self.module = module
        self.service_root = '/redfish/v1/'
        self.resource_id = resource_id
        self.data_modification = data_modification
        self.strip_etag_quotes = strip_etag_quotes
        self._init_session()

    def _auth_params(self, headers):
        """
        Return tuple of required authentication params based on the presence
        of a token in the self.creds dict. If using a token, set the
        X-Auth-Token header in the `headers` param.

        :param headers: dict containing headers to send in request
        :return: tuple of username, password and force_basic_auth
        """
        if self.creds.get('token'):
            username = None
            password = None
            force_basic_auth = False
            headers['X-Auth-Token'] = self.creds['token']
        else:
            username = self.creds['user']
            password = self.creds['pswd']
            force_basic_auth = True
        return username, password, force_basic_auth

    # GET、POST、PATCH、DELETE
    def get_request(self, uri):
        """
        Function for get requests
        :param uri: uniform resource identifier
        :return: dict
        """
        req_headers = dict(GET_HEADERS)
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            resp = open_url(uri, method="GET", headers=req_headers,
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            data = json.loads(to_native(resp.read()))
            headers = dict((k.lower(), v) for (k, v) in resp.info().items())
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {
                'ret': False,
                'msg': "HTTP Error %s on GET request to '%s', "
                       "extended message: '%s'" % (e.code, uri, msg),
                'status': e.code}
        except URLError as e:
            return {'ret': False,
                    'msg': "URL Error on GET request to '%s': '%s'"
                           % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed GET request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'data': data, 'headers': headers}

    def post_request(self, uri, payload):
        """
        Function for post requests
        :param uri: uniform resource identifier
        :param payload: request body
        :return: dict
        """
        req_headers = dict(POST_HEADERS)
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            resp = open_url(uri, data=json.dumps(payload),
                            headers=req_headers, method="POST",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            headers = dict((k.lower(), v) for (k, v) in resp.info().items())
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {
                'ret': False,
                'msg': "HTTP Error %s on POST request to '%s', "
                       "extended message: '%s'" % (e.code, uri, msg),
                'status': e.code}
        except URLError as e:
            return {'ret': False,
                    'msg': "URL Error on POST request to '%s': '%s'"
                           % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed POST request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'headers': headers, 'resp': resp}

    def patch_request(self, uri, payload):
        """
        Function for patch requests
        :param uri: uniform resource identifier
        :param payload: request body
        :return: dict
        """
        req_headers = dict(PATCH_HEADERS)
        # Obtain the interface etag information
        # as the request header If-Match value
        r = self.get_request(uri)
        if r['ret']:
            # Get etag from etag header or @odata.etag property
            etag = r['headers'].get('etag')
            if not etag:
                etag = r['data'].get('@odata.etag')
            if etag:
                if self.strip_etag_quotes:
                    # Remove " before and after etag
                    etag = etag.strip('"')
                req_headers['If-Match'] = etag
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            resp = open_url(uri, data=json.dumps(payload),
                            headers=req_headers, method="PATCH",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {
                'ret': False,
                'msg': "HTTP Error %s on PATCH request to '%s', "
                       "extended message: '%s'" % (e.code, uri, msg),
                'status': e.code}
        except URLError as e:
            return {'ret': False,
                    'msg': "URL Error on PATCH request to '%s': '%s'"
                           % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed PATCH request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'resp': resp}

    def delete_request(self, uri, payload=None):
        """
        Function for delete requests
        :param uri: uniform resource identifier
        :param payload: request body, the default value is None
        :return: dict
        """
        req_headers = dict(DELETE_HEADERS)
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            data = json.dumps(payload) if payload else None
            resp = open_url(uri, data=data,
                            headers=req_headers, method="DELETE",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
        except HTTPError as e:
            msg = self._get_extended_message(e)
            return {
                'ret': False,
                'msg': "HTTP Error %s on DELETE request to '%s', "
                       "extended message: '%s'" % (e.code, uri, msg),
                'status': e.code}
        except URLError as e:
            return {'ret': False,
                    'msg': "URL Error on DELETE request to '%s': '%s'"
                           % (uri, e.reason)}
        # Almost all errors should be caught above, but just in case
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed DELETE request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'resp': resp}

    @staticmethod
    def _get_extended_message(error):
        """
        Get extended information
        :param error: error response
        :return: str
        """
        msg = http_client.responses.get(error.code, '')
        # The response code is greater than 400
        if error.code >= 400:
            try:
                body = error.read().decode('utf-8')
                data = json.loads(body)
                ext_info = data['error']['@Message.ExtendedInfo']
                # if the ExtendedInfo contains a user friendly message send it
                # otherwise try to send the entire contents of ExtendedInfo
                try:
                    # Get the Message field value of the first element
                    msg = ext_info[0]['Message']
                except (ValueError, Exception):
                    msg = str(data['error']['@Message.ExtendedInfo'])
            except (ValueError, Exception):
                pass
        return msg

    def _init_session(self):
        """
        Initialize the session, which is only defined here for future expansion
        """
        pass

    def _get_vendor(self):
        """
        Get manufacturer information
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return {'ret': False, 'Vendor': ''}
        data = response['data']
        if 'Vendor' in data:
            return {'ret': True, 'Vendor': data['Vendor']}
        else:
            return {'ret': True, 'Vendor': ''}

    def _find_accountservice_resource(self):
        """
        Query the current user service information of the server
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'AccountService' not in data:
            return {'ret': False, 'msg': "AccountService resource not found"}
        else:
            account_service = data["AccountService"]["@odata.id"]
            response = self.get_request(self.root_uri + account_service)
            if response['ret'] is False:
                return response
            data = response['data']
            accounts = data['Accounts']['@odata.id']
            if accounts[-1:] == '/':
                accounts = accounts[:-1]
            self.accounts_uri = accounts
        return {'ret': True}

    def _find_sessionservice_resource(self):
        """
        Query session resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'SessionService' not in data:
            return {'ret': False, 'msg': "SessionService resource not found"}
        else:
            session_service = data["SessionService"]["@odata.id"]
            response = self.get_request(self.root_uri + session_service)
            if response['ret'] is False:
                return response
            data = response['data']
            sessions = data['Sessions']['@odata.id']
            if sessions[-1:] == '/':
                sessions = sessions[:-1]
            self.sessions_uri = sessions
        return {'ret': True}

    def _find_taskservice_resource(self):
        """
        Query task resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'Tasks' not in data:
            return {'ret': False, 'msg': "TaskService resource not found"}
        else:
            task_service = data["Tasks"]["@odata.id"]
            response = self.get_request(self.root_uri + task_service)
            if response['ret'] is False:
                return response
            data = response['data']
            tasks = data['Tasks']['@odata.id']
            # Remove the / at the end of the url
            if tasks[-1:] == '/':
                tasks = tasks[:-1]
            self.tasks_uri = tasks
        return {'ret': True}

    def _find_updateservice_resource(self):
        """
        Query update service resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'UpdateService' not in data:
            return {'ret': False, 'msg': "UpdateService resource not found"}
        else:
            update = data["UpdateService"]["@odata.id"]
            self.update_uri = update
            response = self.get_request(self.root_uri + update)
            if response['ret'] is False:
                return response
            data = response['data']
            self.firmware_uri = self.software_uri = None
            if 'FirmwareInventory' in data:
                self.firmware_uri = data['FirmwareInventory'][u'@odata.id']
            return {'ret': True}

    def _find_systems_resource(self):
        """
        Query system resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'Systems' not in data:
            return {'ret': False, 'msg': "Systems resource not found"}
        system_resource = data['Systems']['@odata.id']
        response = self.get_request(self.root_uri + system_resource)
        if response['ret'] is False:
            return response
        self.systems_uris = [
            i['@odata.id'] for i in response['data'].get('Members', [])]
        if not self.systems_uris:
            return {
                'ret': False,
                'msg': "ComputerSystem's Members array is "
                       "either empty or missing"}
        self.systems_uri = self.systems_uris[0]
        if self.data_modification:
            if self.resource_id:
                self.systems_uri = self._get_resource_uri_by_id(
                    self.systems_uris,
                    self.resource_id)
                if not self.systems_uri:
                    return {
                        'ret': False,
                        'msg': "System resource %s not found" % self.resource_id}
            # When there are multiple resource uris, you need to specify the id
            elif len(self.systems_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'System'})
        return {'ret': True}

    def _find_managers_resource(self):
        """
        Query manager resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'Managers' not in data:
            return {'ret': False, 'msg': "Manager resource not found"}
        manager = data["Managers"]["@odata.id"]
        response = self.get_request(self.root_uri + manager)
        if response['ret'] is False:
            return response
        self.manager_uris = [
            i['@odata.id'] for i in response['data'].get('Members', [])]
        if not self.manager_uris:
            return {'ret': False,
                    'msg': "Managers Members array is either empty or missing"}
        self.manager_uri = self.manager_uris[0]
        if self.data_modification:
            if self.resource_id:
                self.manager_uri = self._get_resource_uri_by_id(
                    self.manager_uris,
                    self.resource_id)
                if not self.manager_uri:
                    return {
                        'ret': False,
                        'msg': "Manager resource %s not found" %
                               self.resource_id}
            # When there are multiple resource uris, you need to specify the id
            elif len(self.manager_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'Manager'})
        return {'ret': True}

    def _find_chassis_resource(self):
        """
        Query chassis resources
        :return: dict
        """
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'Chassis' not in data:
            return {'ret': False, 'msg': "Chassis resource not found"}
        chassis = data["Chassis"]["@odata.id"]
        response = self.get_request(self.root_uri + chassis)
        if response['ret'] is False:
            return response
        self.chassis_uris = [
            i['@odata.id'] for i in response['data'].get('Members', [])]
        if not self.chassis_uris:
            return {'ret': False,
                    'msg': "Chassis Members array is either empty or missing"}
        self.chassis_uri = self.chassis_uris[0]
        if self.data_modification:
            if self.resource_id:
                self.chassis_uri = self._get_resource_uri_by_id(
                    self.chassis_uris, self.resource_id)
                if not self.chassis_uri:
                    return {
                        'ret': False,
                        'msg': "Chassis resource %s not found" %
                               self.resource_id
                    }
            # When there are multiple resource uris, you need to specify the id
            elif len(self.chassis_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'Chassis'})
        return {'ret': True}

    def _get_resource_uri_by_id(self, uris, id_prop):
        """
        Get resource uri by id
        :param uris: uri list
        :param id_prop: specify id
        :return: str
        """
        for uri in uris:
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                continue
            data = response['data']
            if id_prop == data.get('Id'):
                return uri
        return None

    def _find_account_uri(self, username=None, acct_id=None):
        """
        Get specified user information
        :param username: user name
        :param acct_id: user id
        :return: dict
        """
        # Need to specify username or user id
        if not any((username, acct_id)):
            return {'ret': False, 'msg': 'Must provide either account_id or '
                                         'account_username'}

        response = self.get_request(self.root_uri + self.accounts_uri)
        if response['ret'] is False:
            return response
        data = response['data']

        uris = [a.get('@odata.id') for a in data.get('Members', []) if
                a.get('@odata.id')]
        for uri in uris:
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                continue
            data = response['data']
            headers = response['headers']
            if username:
                if username == data.get('UserName'):
                    return {'ret': True, 'data': data,
                            'headers': headers, 'uri': uri}
            if acct_id:
                if acct_id == data.get('Id'):
                    return {'ret': True, 'data': data,
                            'headers': headers, 'uri': uri}

        return {
            'ret': False,
            'no_match': True,
            'msg': 'No account with the '
            'given account_id or '
            'account_username found'}

    def add_user(self, user):
        """
        Add user
        :param user: new user profile
        :return: dict
        """
        if not user.get('account_username'):
            return {'ret': False, 'msg':
                    'Must provide account_username for AddUser command'}

        response = self._find_account_uri(
            username=user.get('account_username'))
        if response['ret']:
            # account_username already exists, nothing to do
            return {'ret': True, 'changed': False}

        response = self.get_request(self.root_uri + self.accounts_uri)
        if not response['ret']:
            return response

        payload = {}
        if user.get('account_username'):
            payload['UserName'] = user.get('account_username')
        if user.get('account_password'):
            payload['Password'] = user.get('account_password')
        if user.get('account_roleid'):
            payload['RoleId'] = user.get('account_roleid')
        if user.get('account_id'):
            payload['Id'] = user.get('account_id')
        payload['Locked'] = False
        payload['Enabled'] = True

        response = self.post_request(
            self.root_uri + self.accounts_uri, payload)
        if not response['ret']:
            return response
        return {'ret': True}

    # BEGIN: Added by dys46944, 2023-11-23, PN: NV202311221934,
    # Des:G6机型新增用户
    def add_user_G6_G7(self, user):
        """
        Add user
        :param user: new user profile
        :return: dict
        """
        if not user.get('account_username'):
            return {'ret': False, 'msg':
                'Must provide account_username for AddUser command'}

        response = self._find_account_uri(
            username=user.get('account_username'))
        if response['ret']:
            # account_username already exists, nothing to do
            return {'ret': True, 'changed': False}

        response = self.get_request(self.root_uri + self.accounts_uri)
        if not response['ret']:
            return response

        payload = {}
        if user.get('account_username'):
            payload['UserName'] = user.get('account_username')
        if user.get('account_password'):
            payload['Password'] = user.get('account_password')
        if user.get('account_roleid'):
            payload['RoleId'] = user.get('account_roleid')
        if user.get('account_id'):
            payload['Id'] = user.get('account_id')
        payload['Locked'] = False
        payload['Enabled'] = True
        oem = {}
        oem["Public"] = dict()
        oem['Public']['IPMIEnable'] = True
        oem['Public']['WebEnable'] = True
        oem["Public"]["RSAEncryptionEnabled"] = True
        if user.get('snmp_v3_enable'):
            oem['Public']['SnmpV3Enable'] = user.get('snmp_v3_enable')
        else:
            oem['Public']['SnmpV3Enable'] = False
        if user.get('snmp_v3_access_permission'):
            oem['Public']['SnmpV3AccessPermission'] = user.get('snmp_v3_access_permission')
        else:
            oem['Public']['SnmpV3AccessPermission'] = "read_only"
        if user.get('snmp_v3_auth_protocol'):
            oem['Public']['SnmpV3AuthProtocol'] = user.get('snmp_v3_auth_protocol')
        else:
            oem['Public']['SnmpV3AuthProtocol'] = "sha"
        if user.get('snmp_v3_priv_protocol'):
            oem['Public']['SnmpV3PrivProtocol'] = user.get('snmp_v3_priv_protocol')
        else:
            oem['Public']['SnmpV3PrivProtocol'] = "des"
        if user.get('snmp_v3_password'):
            oem['Public']['SnmpV3Password'] = user.get('snmp_v3_password')
        else:
            oem['Public']['SnmpV3Password'] = ""
        payload['Oem'] = oem
        response = self.post_request(
            self.root_uri + self.accounts_uri, payload)
        if not response['ret']:
            return response
        return {'ret': True}
    # END: Added by dys46944, 2023-11-23, PN: NV202311221934,
    # Des:G6机型新增用户

    def list_users(self):
        result = {}
        user_list = []
        users_results = []
        # Get these entries, but does not fail if not found
        properties = [
            'Id',
            'Name',
            'UserName',
            'RoleId',
            'Locked',
            'Enabled'
        ]

        response = self.get_request(self.root_uri + self.accounts_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for users in data.get('Members', []):
            user_list.append(users[u'@odata.id'])   # user_list[] are URIs

        # for each user, get details
        for uri in user_list:
            user = {}
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                return response
            data = response['data']

            for prop in properties:
                if prop in data:
                    user[prop] = data[prop]

            users_results.append(user)
        result["entries"] = users_results
        return result

    @staticmethod
    def _construct_account_request_body(user_data):
        """
        Construct the basic request body for user configuration
        :param user_data: user's current configuration
        :return: dict
        """
        # List of useless attributes
        del_lst = ['@odata.context', '@odata.id', '@odata.type',
                   'Description', 'Id', 'Links', 'Name', 'Oem']
        # Remove useless attributes
        for attr in del_lst:
            if attr in user_data:
                del user_data[attr]
        return user_data

    def enable_user(self, user):
        """
        Enable user
        :param user: user Info
        :return: dict
        """
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']

        if data.get('Enabled', True):
            # account already enabled, nothing to do
            return {'ret': True, 'changed': False}
        payload = self._construct_account_request_body(data)
        payload['Enabled'] = True
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def disable_user(self, user):
        """
        Disable user
        :param user: user Info
        :return: dict
        """
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']

        if not data.get('Enabled'):
            # account already disabled, nothing to do
            return {'ret': True, 'changed': False}
        payload = self._construct_account_request_body(data)
        payload['Enabled'] = False
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def delete_user(self, user):
        """
        Delete user
        :param user: user Info
        :return:
        """
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            if response.get('no_match'):
                # account does not exist, nothing to do
                return {'ret': True, 'changed': False}
            else:
                # some error encountered
                return response
        uri = response['uri']
        response = self.delete_request(self.root_uri + uri)
        if not response['ret']:
            return response
        return {'ret': True}

    def update_user_role(self, user):
        """
        Modify user role groups
        :param user: user Info
        :return: dict
        """
        if not user.get('account_roleid'):
            return {'ret': False, 'msg':
                    'Must provide account_roleid for UpdateUserRole command'}

        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']

        if data.get('RoleId') == user.get('account_roleid'):
            # account already has RoleId , nothing to do
            return {'ret': True, 'changed': False}
        payload = self._construct_account_request_body(data)
        payload['RoleId'] = user.get('account_roleid')
        # BEGIN: Added by dys46944, 2023-11-23, PN: NV202311221934,
        # Des: 适配G6
        del payload['Password']
        # END: Added by dys46944, 2023-11-23, PN: NV202311221934,
        # Des: 适配G6
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def update_user_password(self, user):
        """
        Modify user password
        :param user: user Info
        :return: dict
        """
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']
        payload = self._construct_account_request_body(data)
        payload['Password'] = user.get('account_password')
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def update_user_name(self, user):
        """
        Modify user name
        :param user: user Info
        :return: dict
        """
        if not user.get('account_updatename'):
            return {
                'ret': False,
                'msg': 'Must provide account_updatename '
                       'for UpdateUserName command'
            }

        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040680,
        # Des: Nothing to do
        if data.get('UserName') == user.get('account_updatename'):
            return {'ret': True, 'changed': False}
        # END: Added by t18444, 2023-01-04, PN: 202301040680,
        # Des: Nothing to do
        payload = self._construct_account_request_body(data)
        payload['UserName'] = user.get('account_updatename')
        # BEGIN: Added by dys46944, 2023-11-07, PN: NV202311070547,
        # Des: 适配G6
        del payload['Password']
        # END: Added by dys46944, 2023-11-07, PN: NV202311070547,
        # Des: 适配G6
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def set_ntp_server(self, mgr_attributes):
        """
        Set NTP Server
        :param mgr_attributes: attr: value
        :return: dict
        """
        payload = {}
        attr_name = mgr_attributes["mgr_attr_name"]
        attr_value = mgr_attributes["mgr_attr_value"]
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040701,
        # Des: Add parameter value selection range limit
        if attr_name == "ServiceEnabled":
            if attr_value not in ['True', 'False']:
                return {'ret': False, 'msg':
                        'Must choose True or False'}
            attr_value = True if attr_value == 'True' else False
            payload["ServiceEnabled"] = attr_value
        # END: Added by t18444, 2023-01-04, PN: 202301040701,
        # Des: Add parameter value selection range limit
        elif attr_name == "PreferredNtpServer":
            payload["PreferredNtpServer"] = attr_value
        elif attr_name == "AlternateNtpServer":
            payload["AlternateNtpServer"] = attr_value
        elif attr_name in {"RefreshInterval", "TertiaryNtpServer", "TimeZone"}:
            if attr_name == "RefreshInterval":
                attr_value = int(attr_value)
            payload["Oem"] = {
                "Public": {attr_name: attr_value}
            }
        else:
            return {'ret': False, 'msg':
                    'The specified field is not available'}
        service_resp = self.get_manager_ntp_uri()
        if not service_resp['ret']:
            return service_resp
        service_uri = service_resp['uri']
        response = self.patch_request(self.root_uri + service_uri, payload)
        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Modified %s" % mgr_attributes["mgr_attr_name"],
        }

    def get_manager_ntp_uri(self):
        """
        Get NTP Service uri
        :return: str
        """
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response['ret']:
            return response
        data = response['data']
        if 'NtpService' not in data:
            return {'ret': False, 'msg': "NtpService resource not found"}
        else:
            return {'ret': True, 'uri': data["NtpService"]["@odata.id"]}

    def set_bios_attributes(self, attributes):
        """
        Set Bios
        :param attributes: bios config
        :return: dict
        """
        result = {}
        key = "Bios"
        # Search bios uri
        response = self.get_request(self.root_uri + self.systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        bios_uri = data[key]["@odata.id"]

        response = self.get_request(self.root_uri + bios_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        # Make a copy of the attributes dict
        attrs_to_patch = dict(attributes)

        # List to save unsupported attributes
        attrs_bad = {}

        # Check the attributes
        for attr_name, attr_value in attributes.items():
            # Check if attribute exists
            if attr_name not in data[u'Attributes']:
                # Remove and proceed to next attribute if this isn't valid
                attrs_bad.update({attr_name: attr_value})
                del attrs_to_patch[attr_name]
                continue

            # If already set to requested value, remove it from PATCH payload
            if data[u'Attributes'][attr_name] == attributes[attr_name]:
                del attrs_to_patch[attr_name]
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040735,
        # Des: The configuration item does not exist and returns directly
        warning = ""
        if attrs_bad:
            warning = "Incorrect attributes %s" % attrs_bad
            return {'ret': False, 'msg': warning}
        # END: Added by t18444, 2023-01-04, PN: 202301040735,
        # Des: The configuration item does not exist and returns directly
        # Return success w/ changed=False if no attrs need to be changed
        if not attrs_to_patch:
            return {'ret': True, 'changed': False,
                    'msg': "BIOS attributes already set",
                    'warning': warning}

        # Get the SettingsObject URI
        set_bios_attr_uri = (
            data["@Redfish.Settings"]["SettingsObject"]["@odata.id"])

        # Construct payload and issue PATCH command
        payload = {"Attributes": attrs_to_patch}
        response = self.patch_request(
            self.root_uri + set_bios_attr_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True,
                'msg': "Modified BIOS attributes %s" % attrs_to_patch,
                'warning': warning}

    def set_boot_override(self, boot_opts):
        """
        Set system boot item
        :param boot_opts: boot item
        :return: dict
        """
        result = {}
        key = "Boot"

        boot_target = boot_opts.get('boot_target')
        boot_enable = boot_opts.get('boot_enable')
        boot_mode = boot_opts.get('boot_mode')

        # Search uri
        response = self.get_request(self.root_uri + self.systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        boot = data[key]

        req_dict = {}

        # BEGIN: Added by t18444, 2023-01-31, PN: 202301300710,
        # Des: When the parameter value is not specified,
        # it needs to be filled according to the current value
        # Determine whether the boot device is legal
        if boot_target is not None:
            annotation = 'BootSourceOverrideTarget@Redfish.AllowableValues'
            if annotation in boot:
                allowable_values = boot[annotation]
                if isinstance(allowable_values,
                              list) and boot_target not in allowable_values:
                    return {
                        'ret': False,
                        'msg': "Boot override target %s not in list of "
                               "allowable "
                               "values (%s)" % (boot_target, allowable_values)
                    }
                else:
                    req_dict["BootSourceOverrideTarget"] = boot_target
        else:
            req_dict["BootSourceOverrideTarget"] = boot.get(
                "BootSourceOverrideTarget")
        # Determine whether the validity period of the boot item is legal
        if boot_enable is not None:
            annotation = 'BootSourceOverrideEnabled@Redfish.AllowableValues'
            if annotation in boot:
                allowable_values = boot[annotation]
                if isinstance(allowable_values,
                              list) and boot_enable not in allowable_values:
                    return {
                        'ret': False,
                        'msg': "Boot override enable %s not in list of "
                               "allowable "
                               "values (%s)" % (boot_enable, allowable_values)
                    }
                else:
                    req_dict["BootSourceOverrideEnabled"] = boot_enable
        else:
            req_dict["BootSourceOverrideEnabled"] = boot.get(
                "BootSourceOverrideEnabled")

        # Determine whether the boot mode is legal
        if boot_mode is not None:
            annotation = 'BootSourceOverrideMode@Redfish.AllowableValues'
            if annotation in boot:
                allowable_values = boot[annotation]
                if isinstance(allowable_values,
                              list) and boot_mode not in allowable_values:
                    return {
                        'ret': False,
                        'msg': "Boot override mode %s not in list of "
                               "allowable "
                               "values (%s)" % (boot_mode, allowable_values)
                    }
                else:
                    req_dict["BootSourceOverrideMode"] = boot_mode
        else:
            req_dict["BootSourceOverrideMode"] = boot.get(
                "BootSourceOverrideMode")
        # END: Added by t18444, 2023-01-31, PN: 202301300710,
        # Des: When the parameter value is not specified,
        # it needs to be filled according to the current value

        # Determine whether the field value has been modified
        for key, value in req_dict.items():
            if value != boot.get(key):
                break
        else:
            return {'ret': True, 'changed': False}
        payload = {
            'Boot': req_dict
        }
        response = self.patch_request(
            self.root_uri + self.systems_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True}

    def manage_system_power(self, command):
        """
        Power management operations under the Systems interface
        :param command: operation command
        :return: dict
        """
        return self.manage_power(command, self.systems_uri,
                                 '#ComputerSystem.Reset')

    def manage_manager_power(self, command):
        """
        Power management operations under the Managers interface
        :param command: operation command
        :return: dict
        """
        return self.manage_power(command, self.manager_uri,
                                 '#Manager.Reset')

    def manage_power(self, command, resource_uri, action_name):
        key = "Actions"
        reset_type_values = [
            'On',
            'ForceOff',
            'ForceRestart',
            'GracefulShutdown',
            'ForcePowerCycle',
            'Nmi'
        ]

        # command should be PowerOn, PowerForceOff, etc.
        if not command.startswith('Power'):
            return {'ret': False, 'msg': 'Invalid Command (%s)' % command}
        # Remove the first 5 letters of the type, that is, the field after
        # 'Power'
        reset_type = command[5:]

        # map Reboot to a ResetType that does a reboot
        if reset_type == 'Reboot':
            reset_type = 'ForceRestart'

        if reset_type not in reset_type_values:
            return {'ret': False, 'msg': 'Invalid Command (%s)' % command}

        # read the resource and get the current power state
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        data = response['data']
        power_state = data.get('PowerState')

        # if power is already in target state, nothing to do
        if power_state == "On":
            if reset_type in ['On']:
                return {'ret': True, 'changed': False}
        elif power_state == "Off":
            # if power is already in target state, nothing to do
            if reset_type in ['GracefulShutdown', 'ForceOff']:
                return {'ret': True, 'changed': False}
            elif reset_type in ['ForceRestart', 'PowerCycle']:
                return {'ret': False, 'msg': '(%s) command not available in '
                                             'shutdown state' % command}

        # get the reset Action and target URI
        if key not in data or action_name not in data[key]:
            return {'ret': False, 'msg': 'Action %s not found' % action_name}

        reset_action = data[key][action_name]
        if 'target' not in reset_action:
            return {'ret': False,
                    'msg': 'target URI missing from Action %s' % action_name}

        action_uri = reset_action['target']
        # get AllowableValues
        allowable_values = reset_action['ResetType@Redfish.AllowableValues']

        # define payload
        payload = {'ResetType': reset_type}

        # POST to Action URI
        response = self.post_request(self.root_uri + action_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True}

    def _find_ethernet_interface_uri(self, eth_id, service_uri):
        """
        get the ethernet interface uri
        :param eth_id: ethernet id
        :param service_uri: service uri
        :return: dict
        """
        response = self.get_request(self.root_uri + service_uri)
        if response['ret'] is False:
            return response
        data = response['data']

        uris = [a.get('@odata.id') for a in data.get('Members', []) if
                a.get('@odata.id')]
        for uri in uris:
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                continue
            data = response['data']
            headers = response['headers']
            if eth_id == data.get('Id'):
                return {'ret': True, 'data': data,
                        'headers': headers, 'uri': uri}
        return {
            'ret': False,
            'no_match': True,
            'msg': 'No ethernet interface with the given eth_id'}

    def get_manager_ethernet_uri(self):
        """
        Get EthernetInterfaces uri
        :return: dict
        """
        response = self.get_request(self.root_uri + self.manager_uri)
        if not response['ret']:
            return response
        data = response['data']
        if 'EthernetInterfaces' not in data:
            return {
                'ret': False,
                'msg': "EthernetInterfaces resource not found"
            }
        else:
            return {'ret': True,
                    'uri': data["EthernetInterfaces"]["@odata.id"]}

    def set_ipv4(self, info):
        """
        Set IPv4
        :param info: ipv4 config info
        :return: dict
        """
        if not info.get('net_id'):
            return {'ret': False, 'msg':
                    'Must provide net_id for SetIPv4 command'}
        ethernet_resp = self.get_manager_ethernet_uri()
        if not ethernet_resp['ret']:
            return ethernet_resp
        service_uri = ethernet_resp['uri']
        interface_resp = self._find_ethernet_interface_uri(info['net_id'],
                                                           service_uri)
        if not interface_resp['ret']:
            return interface_resp

        data = interface_resp['data']
        uri = interface_resp['uri']

        ipv4_info = data.get('IPv4Addresses')[0]
        if info.get("new_origin") == "DHCP":
            target_info = {"AddressOrigin": "DHCP"}
        else:
            target_info = {
                "Address": info.get("new_addr"),
                "AddressOrigin": "Static",
                "SubnetMask": info.get("new_sub"),
                "Gateway": info.get("new_gateway")
            }
        for key, value in target_info.items():
            if value and value != ipv4_info[key]:
                break
        else:
            # nothing to do
            return {'ret': True, 'changed': False}

        payload = {"IPv4Addresses": [target_info]}
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def set_ipv6(self, info):
        """
        Set IPv6
        :param info: ipv6 config info
        :return: dict
        """
        if not info.get('net_id'):
            return {'ret': False, 'msg':
                    'Must provide net_id for SetIPv6 command'}
        ethernet_resp = self.get_manager_ethernet_uri()
        if not ethernet_resp['ret']:
            return ethernet_resp
        service_uri = ethernet_resp['uri']
        interface_resp = self._find_ethernet_interface_uri(info['net_id'],
                                                           service_uri)
        if not interface_resp['ret']:
            return interface_resp

        uri = interface_resp['uri']
        payload = {}

        if info.get("new_origin") == "DHCPv6":
            payload["IPv6Addresses"] = [
                {
                    "AddressOrigin": "DHCPv6"
                }
            ]
        else:
            payload["IPv6Addresses"] = [
                {
                    "Address": info.get("new_addr"),
                    "AddressOrigin": "Static",
                    "PrefixLength": info.get("prefix_length")
                }
            ]
            payload["IPv6DefaultGateway"] = info.get("new_gateway")
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def create_logical_driver(self, details):
        """
        Create logical driver
        :param details: logical drive configuration
        :return: dict
        """
        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for CreateLogicalDrive command'}
        # storage resource uri
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        resource_uri = ("/redfish/v1/Systems/1/Storages/%s" %
                        details.get('storage_id'))
        # END: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        # Get current control card information
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        try:
            physical_lst = details["raid"]["PhysicalDiskList"]
            if isinstance(physical_lst, list):
                for physical in physical_lst:
                    phy_id = physical.get("id")
                    phy_uri = "/redfish/v1/Chassis/1/Drives/%s" % phy_id
                    response = self.get_request(self.root_uri + phy_uri)
                    if response['ret'] is False:
                        return response
                    data = response['data']
                    con_id = data["Oem"]["Public"]["ConnectionID"]
                    # Convert physical disk id to connnection id
                    physical["id"] = con_id
            else:
                msg = 'List information required'
                return {'ret': False, 'msg': msg}
        except (KeyError, ValueError, Exception) as e:
            return {'ret': False, 'msg': to_text(e)}
        payload = {"Oem": details.get("raid")}
        resource_uri = "%s/Volumes" % resource_uri
        response = self.post_request(self.root_uri + resource_uri, payload)
        if not response['ret']:
            return response
        return {'ret': True}

    def delete_logical_driver(self, details):
        """
        Delete Logical Drive
        :param details: logical drive details
        :return: dict
        """
        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for DeleteLogicalDrive command'}
        if not details.get('logical_id'):
            return {'ret': False, 'msg':
                    'Must provide logical_id for DeleteLogicalDrive command'}
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        resource_uri = ("/redfish/v1/Systems/1/Storages/%s/Volumes/%s" %
                        (details['storage_id'], details['logical_id']))
        # END: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        # Get the current specified logical disk configuration
        response = self.get_request(self.root_uri + resource_uri)
        # The specified logical disk does not exist
        if response['ret'] is False:
            return response
        response = self.delete_request(self.root_uri + resource_uri)
        if not response['ret']:
            return response
        return {'ret': True}

    def modify_logical_driver(self, details):
        """
        Modify Logical Driver
        :param details: logical drive details
        :return:
        """
        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for ModifyLogicalDrive command'}
        if not details.get('logical_id'):
            return {'ret': False, 'msg':
                    'Must provide logical_id for ModifyLogicalDrive command'}
        # BEGIN: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        resource_uri = ("/redfish/v1/Systems/1/Storages/%s/Volumes/%s" %
                        (details['storage_id'], details['logical_id']))
        # END: Added by t18444, 2023-01-04, PN: 202301040719,
        # Des: Modify the uri composition
        # Get the current specified logical disk configuration
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
		# BEGIN: Added by dys46944, 2023-11-13, PN: NV202311031274,
        # Des: 适配G6
        tmp = {}
        if details.get("write_policy") is not None:
            tmp["WritePolicy"] = details.get("write_policy")

        if details.get("read_policy") is not None:
            tmp["ReadPolicy"] = details.get("read_policy")

        if details.get("access_policy") is not None:
            tmp["AccessPolicy"] = details.get("access_policy")

        if details.get("drive_cache") is not None:
            tmp["DriveCache"] = details.get("drive_cache")

        # BEGIN: Added by dys46944, 2024-10-14, PN: 202410140627,
        # Des:适配G7
        if details.get("default_write_policy") is not None:
            tmp["DefaultWritePolicy"] = details.get("default_write_policy")

        if details.get("default_read_policy") is not None:
            tmp["DefaultReadPolicy"] = details.get("default_read_policy")
        # END: Added by dys46944, 2024-10-14, PN: 202410140627,
        # Des: 适配G7

        payload = {
            "Oem": {
                "Public": tmp
            }
        }
		# END: Added by dys46944, 2023-11-13, PN: NV202311031274,
        # Des: 适配G6
        response = self.patch_request(self.root_uri + resource_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def get_bios_attributes(self, systems_uri):
        """
        Get BIOS configuration
        :param systems_uri: System resource uri
        :return:
        """
        result = {}
        bios_attributes = {}
        key = "Bios"

        # Search for 'key' entry and extract URI from it
        response = self.get_request(self.root_uri + systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        bios_uri = data[key]["@odata.id"]

        response = self.get_request(self.root_uri + bios_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        for attribute in data[u'Attributes'].items():
            bios_attributes[attribute[0]] = attribute[1]
        result["entries"] = bios_attributes
        return result

    def get_multi_bios_attributes(self):
        """
        Get bios attributes
        :return: dict
        """
        return self.aggregate_systems(self.get_bios_attributes)

    def aggregate_chassis(self, func):
        """
        Chassis partial function
        :param func: Concrete function
        :return:
        """
        return self.aggregate(func, self.chassis_uris, 'chassis_uri')

    def aggregate_managers(self, func):
        """
        Managers partial function
        :param func: Concrete function
        :return:
        """
        return self.aggregate(func, self.manager_uris, 'manager_uri')

    def aggregate_systems(self, func):
        """
        Systems partial function
        :param func: Concrete function
        :return:
        """
        return self.aggregate(func, self.systems_uris, 'system_uri')

    @classmethod
    def aggregate(cls, func, uri_list, uri_name):
        """
        Association function and uri
        :param func: concrete function
        :param uri_list: uri  resource list
        :param uri_name: uri name
        :return:
        """
        ret = True
        entries = []
        for uri in uri_list:
            inventory = func(uri)
            ret = inventory.pop('ret') and ret
            if 'entries' in inventory:
                entries.append(({uri_name: uri},
                                inventory['entries']))
        return dict(ret=ret, entries=entries)

    def get_multi_psu_inventory(self):
        """
        Get multi psu attributes
        :return: dict
        """
        return self.aggregate_systems(self.get_psu_inventory)

    def get_psu_inventory(self):
        """
        Get psu attributes
        :return: dict
        """
        result = {}
        psu_results = []
        key = "PowerSupplies"
        # Get these entries, but does not fail if not found
        properties = [
            'Name',
            'Model',
            'PowerID'
            'SlotNumber',
            'SerialNumber',
            'PartNumber',
            'Manufacturer',
            'FirmwareVersion',
            'PowerCapacityWatts',
            'PowerSupplyType',
            'PowerOutputWatts',
            'LineInputVoltageType',
            'LineInputCurrent',
            'ActiveStandby',
            'Status'
        ]

        # Get a list of all Chassis and build URIs, then get all PowerSupplies
        # from each Power entry in the Chassis
        chassis_uri_list = self.chassis_uris
        for chassis_uri in chassis_uri_list:
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response

            result['ret'] = True
            data = response['data']

            if 'Power' in data:
                power_uri = data[u'Power'][u'@odata.id']
            else:
                continue

            response = self.get_request(self.root_uri + power_uri)
            data = response['data']

            if key not in data:
                return {'ret': False, 'msg': "Key %s not found" % key}
            psu_list = data[key]
            # Get useful fields
            psu_tmp_lst = []
            for psu in psu_list:
                psu_tmp = dict()
                for key, value in psu.items():
                    if key == '@odata.id':
                        pass
                    elif key == 'Oem':
                        # Get the Oem field
                        oem_dict = psu[key]['Public']
                        for oem_key, oem_value in oem_dict.items():
                            # avoid duplication of fields
                            if oem_key not in psu_tmp:
                                psu_tmp[oem_key] = oem_value
                    else:
                        # avoid duplication of fields
                        if key not in psu_tmp:
                            psu_tmp[key] = value
                psu_tmp_lst.append(psu_tmp)

            for psu in psu_tmp_lst:
                psu_not_present = False
                psu_data = dict()
                for prop in properties:
                    # Do not show empty fields
                    if prop in psu and psu[prop] is not None:
                        if (prop == 'Status' and 'State' in psu[prop] and
                                psu[prop]['State'] == 'Absent'):
                            psu_not_present = True
                        psu_data[prop] = psu[prop]
                if psu_not_present:
                    continue
                psu_results.append(psu_data)

        result['entries'] = psu_results
        if not result['entries']:
            return {'ret': False, 'msg': 'No PowerSupply objects found'}
        return result

    def get_physical_drive_inventory(self):
        """
        Get physical disk information
        :return: dict
        """
        result = {}
        physical_result = []
        properties = [
            'Id',
            'Model',
            'SerialNumber',
            'MediaType',
            'Protocol',
            'Manufacturer',
            'CapacityBytes',
            'CapableSpeedGbs',
            'Revision',
            'FirmwareStatus',
            'SpareforLogicalDrives',
            'HoursOfPoweredUp'
            'PredictedMediaLifeLeftPercent',
            'TemperatureCelsius',
            'IndicatorLED',
            'Status'
        ]
        phy_tmp_lst = []
        # Get a list of all Chassis and build URIs, then get all physical
        # drives
        chassis_uri_list = self.chassis_uris
        for chassis_uri in chassis_uri_list:
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response

            result['ret'] = True
            data = response['data']

            if 'Drives' in data:
                drives_uri = data[u'Drives'][u'@odata.id']
            else:
                continue

            response = self.get_request(self.root_uri + drives_uri)
            if response['ret'] is False:
                return response

            data = response['data']

            members = data[u"Members"]
            for member in members:
                member_uri = member[u'@odata.id']
                member_resp = self.get_request(self.root_uri + member_uri)
                if member_resp['ret'] is False:
                    return member_resp
                phy_data = member_resp['data']
                disk_tmp = dict()
                for key, value in phy_data.items():
                    if key in {'@odata.context', '@odata.id', '@odata.type'}:
                        pass
                    elif key == 'Oem':
                        # Get the Oem field
                        oem_dict = phy_data[key]['Public']
                        for oem_key, oem_value in oem_dict.items():
                            # avoid duplication of fields
                            if oem_key not in disk_tmp:
                                disk_tmp[oem_key] = oem_value
                    else:
                        # avoid duplication of fields
                        if key not in disk_tmp:
                            disk_tmp[key] = value
                phy_tmp_lst.append(disk_tmp)

            # Get the specified field value
            for phy in phy_tmp_lst:
                phy_dict = dict()
                for prop in properties:
                    if phy.get(prop) is not None:
                        phy_dict[prop] = phy[prop]
                physical_result.append(phy_dict)

        result["entries"] = physical_result
        if not result["entries"]:
            return {'ret': False, 'msg': "No Physical drive objects found"}
        return result

    def get_logical_drive_inventory(self):
        """
        Get logical disk information
        :return: dict
        """
        result = {}
        logical_result = []
        properties = [
            'Id',
            'Name',
            'CapacityBytes',
            'DriveCache',
            'ReadPolicy',
            'WritePolicy',
            'IOPolicy',
            'ReadPolicy',
            'AccessPolicy',
            'RaidControllerID'
            'VolumeRaidLevel',
            'SpanNumber',
            'NumDrivePerSpan',
            'BGIEnable',
            'BootEnable',
            'Status'
        ]
        log_tmp_lst = []
        systems_uri_list = self.systems_uris
        for systems_uri in systems_uri_list:
            response = self.get_request(self.root_uri + systems_uri)
            if response['ret'] is False:
                return response

            result['ret'] = True
            data = response['data']

            if 'Storage' in data:
                storage_uri = data[u'Storage'][u'@odata.id']
            else:
                continue

            response = self.get_request(self.root_uri + storage_uri)
            if response['ret'] is False:
                return response

            data = response['data']

            members = data[u"Members"]
            for member in members:
                member_uri = member[u'@odata.id']
                member_uri = "%s/Volumes" % member_uri
                member_resp = self.get_request(self.root_uri + member_uri)
                if member_resp['ret'] is False:
                    return member_resp
                logical_lst = member_resp['data'][u"Members"]
                for logical in logical_lst:
                    logical_uri = logical[u"@odata.id"]
                    logical_resp = self.get_request(
                        self.root_uri + logical_uri)
                    if logical_resp['ret'] is False:
                        return logical_resp
                    logical_data = logical_resp['data']
                    disk_tmp = dict()
                    for key, value in logical_data.items():
                        if key in {'@odata.context', '@odata.id',
                                   '@odata.type'}:
                            pass
                        elif key == 'Oem':
                            # Get the Oem field
                            oem_dict = logical_data[key]['Public']
                            for oem_key, oem_value in oem_dict.items():
                                # avoid duplication of fields
                                if oem_key not in disk_tmp:
                                    disk_tmp[oem_key] = oem_value
                        else:
                            # avoid duplication of fields
                            if key not in disk_tmp:
                                disk_tmp[key] = value
                    log_tmp_lst.append(disk_tmp)

                # Get the specified field value
                for phy in log_tmp_lst:
                    phy_dict = dict()
                    for prop in properties:
                        if phy.get(prop) is not None:
                            phy_dict[prop] = phy[prop]
                    logical_result.append(phy_dict)

        result["entries"] = logical_result
        if not result["entries"]:
            return {'ret': False, 'msg': "No Logical drive objects found"}
        return result

    def get_raid_storage_inventory(self):
        """
        Get raid information
        :return: dict
        """
        result = {}
        raid_result = []
        # main field
        properties = [
            'Id',
            'Name',
            'SerialNumber',
            'SpeedGbps',
            'SupportedDeviceProtocols',
            'Drives',
            'StorageControllers',
            'Status'
        ]
        # controller field
        controller_properties = [
            'MemberId',
            'Model',
            'Manufacturer',
            'FirmwareVersion',
            'ConfigurationVersion',
            'JBODState',
            'MaintainPDFailHistory',
            'MemorySizeMiB',
            'Mode',
            'PackageVersion',
            'SASAddress',
            'SupportedRAIDLevels',
            'BBUstate',
            'CapacitanceStatus',
            'TemperatureCelsius'
        ]
        raid_tmp_lst = []
        systems_uri_list = self.systems_uris
        for systems_uri in systems_uri_list:
            response = self.get_request(self.root_uri + systems_uri)
            if response['ret'] is False:
                return response

            result['ret'] = True
            data = response['data']

            if 'Storage' in data:
                storage_uri = data[u'Storage'][u'@odata.id']
            else:
                continue

            response = self.get_request(self.root_uri + storage_uri)
            if response['ret'] is False:
                return response

            data = response['data']

            members = data[u"Members"]
            for member in members:
                member_uri = member[u'@odata.id']
                member_resp = self.get_request(self.root_uri + member_uri)
                if member_resp['ret'] is False:
                    return member_resp
                storage_data = member_resp['data']
                raid_tmp = dict()
                # remove redirect field
                for key, value in storage_data.items():
                    if key in {'@odata.context', '@odata.id',
                               '@odata.type'}:
                        pass
                    elif key == "Drives":
                        drive_lst = []
                        if isinstance(value, list):
                            for drive in value:
                                drive_uri = drive.get("@odata.id")
                                if drive_uri is not None:
                                    try:
                                        # Take the last field of uri as
                                        # the physical disk id
                                        drive_id = drive_uri.split("/")[-1]
                                    except (IndexError, Exception):
                                        pass
                                    else:
                                        drive_lst.append(drive_id)
                        if key not in raid_tmp:
                            raid_tmp[key] = drive_lst
                    elif key == "StorageControllers":
                        if isinstance(value, list):
                            controller_tmp_lst = []
                            for controller in value:
                                controller_dict = dict()
                                for ctr_key, ctr_value in controller.items():
                                    if ctr_key == '@odata.id':
                                        pass
                                    elif ctr_key == "Oem":
                                        # Get the Oem field
                                        oem_dict = controller[ctr_key]['Public']
                                        # remove redirect field
                                        del oem_dict['AssociatedCard']
                                        for oem_key, oem_value in \
                                                oem_dict.items():
                                            # avoid duplication of fields
                                            if oem_key not in controller_dict:
                                                controller_dict[oem_key] = \
                                                    oem_value
                                    else:
                                        # avoid duplication of fields
                                        if ctr_key not in controller_dict:
                                            controller_dict[ctr_key] = ctr_value
                                controller_tmp_lst.append(controller_dict)
                            controller_lst = []
                            # Get the specified field value
                            for controller_tmp in controller_tmp_lst:
                                ctr_dict = dict()
                                for prop in controller_properties:
                                    if controller_tmp.get(prop) is not None:
                                        ctr_dict[prop] = controller_tmp[prop]
                                controller_lst.append(ctr_dict)
                            if key not in raid_tmp:
                                raid_tmp[key] = controller_lst
                    else:
                        # avoid duplication of fields
                        if key not in raid_tmp:
                            raid_tmp[key] = value
                raid_tmp_lst.append(raid_tmp)

                # Get the specified field value
                for raid in raid_tmp_lst:
                    raid_dict = dict()
                    for prop in properties:
                        if raid.get(prop) is not None:
                            raid_dict[prop] = raid[prop]
                    raid_result.append(raid_dict)

        result["entries"] = raid_result
        if not result["entries"]:
            return {'ret': False, 'msg': "No Raid storage objects found"}
        return result

    def get_firmware_inventory(self):
        """
        Get firmware version information
        :return:
        """
        if self.firmware_uri is None:
            return {'ret': False, 'msg': 'No FirmwareInventory resource found'}
        else:
            return self._software_inventory(self.firmware_uri)

    def get_software_inventory(self):
        """
        Get software version information
        :return:
        """
        if self.software_uri is None:
            return {'ret': False, 'msg': 'No SoftwareInventory resource found'}
        else:
            return self._software_inventory(self.software_uri)

    def _software_inventory(self, uri):
        """
        Get software version
        :param uri: resource uri
        :return: dict
        """
        result = {}
        response = self.get_request(self.root_uri + uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        result['entries'] = []
        for member in data[u'Members']:
            uri = self.root_uri + member[u'@odata.id']
            # Get details for each software or firmware member
            response = self.get_request(uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            software = {}
            # Get these standard properties if present
            for key in ['Name', 'Id', 'Status', 'Version', 'Updateable',
                        'SoftwareId', 'LowestSupportedVersion', 'Manufacturer',
                        'ReleaseDate']:
                if key in data:
                    software[key] = data.get(key)
            result['entries'].append(software)
        return result

    def get_multi_nic_inventory(self, resource_type):
        """
        Get nic information resource allocation function
        :param resource_type:
        :return:
        """
        ret = True
        entries = []

        #  Given resource_type, use the proper URI
        if resource_type == 'Systems':
            resource_uris = self.systems_uris
        elif resource_type == 'Manager':
            resource_uris = self.manager_uris
        else:
            resource_uris = self.chassis_uris
        for resource_uri in resource_uris:
            inventory = self.get_nic_inventory(resource_uri)
            ret = inventory.pop('ret') and ret
            if 'entries' in inventory:
                entries = inventory['entries']
        return dict(ret=ret, entries=entries)

    def get_nic_inventory(self, resource_uri):
        """
        Get nic collection information
        :param resource_uri: resource uri
        :return: dict
        """
        result = {}
        nic_list = []
        nic_results = []
        key = "NetworkAdapters"
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        adapter_uri = data[key]["@odata.id"]

        # Get a list of all network controllers and build respective URIs
        response = self.get_request(self.root_uri + adapter_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        for nic in data[u'Members']:
            nic_list.append(nic[u'@odata.id'])

        for n in nic_list:
            nic = self.get_nic(n)
            if nic['ret']:
                nic_results.append(nic['entries'])
        result["entries"] = nic_results
        return result

    def get_nic(self, resource_uri):
        """
        Get nic information
        :param resource_uri: nic resource uri
        :return: dict
        """
        result = {}
        properties = [
            'Name',
            'Id',
            'Model',
            'Manufacturer',
            'Status'
        ]
        oem_properties = [
            'CapableSpeedGbs',
            'CardManufacturer',
            'CardModel',
            'DeviceLocator',
            'FirmwareVersion',
            'NetworkTechnology',
            'Position',
            'RootBDF',
            'SerialNumber',
            'SlotNumber',
            'TemperatureCelsius'
        ]
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        nic = {}
        for prop in properties:
            if prop in data and prop not in nic and data[prop] is not None:
                nic[prop] = data[prop]
        oem_data = data["Oem"]["Public"]
        for prop in oem_properties:
            if prop in oem_data and prop not in nic and oem_data[prop] is not None:
                nic[prop] = oem_data[prop]
        port_lst = []
        # Get NIC controller port information
        controller_resource = data.get("Controllers")
        if isinstance(controller_resource, list):
            for ctrl in controller_resource:
                network_ports = []
                if isinstance(ctrl.get("Links"), dict):
                    if isinstance(ctrl["Links"].get(
                            "NetworkPorts"), list):
                        port_uris = ctrl["Links"].get(
                            "NetworkPorts")
                        for port_uri in port_uris:
                            network_ports.append(port_uri.get('@odata.id'))
                port_lst = self.package_port_info(network_ports)
        nic["ports"] = port_lst
        result['entries'] = nic
        return result

    def package_port_info(self, port_uris):
        """
        Get network card port information
        :param port_uris: port uris
        :return: list
        """
        result = []
        for port_uri in port_uris:
            response = self.get_request(self.root_uri + port_uri)
            if response['ret'] is False:
                return response
            data = response['data']
            port_dict = {
                "Id": data.get("Id"),
                "AssociatedNetworkAddresses": data.get("AssociatedNetworkAddresses"),
                "LinkStatus": data.get("LinkStatus")
            }
            if isinstance(data.get("Oem"),
                          dict) and isinstance(
                data["Oem"].get(
                    "Public"), dict):
                oem_resp = data["Oem"]["Public"]
                port_dict["PortType"] = oem_resp.get("PortType")
            result.append(port_dict)
        return result

    def get_sessions(self):
        """
        Get the current session collection
        :return: dict
        """
        result = {}
        session_list = []
        sessions_results = []
        # Get these entries, but does not fail if not found
        properties = [
            'Description',
            'Id',
            'Name',
            'UserName'
        ]
        oem_properties = [
            'UserIP',
            'UserRole',
            'UserTag'
        ]

        response = self.get_request(self.root_uri + self.sessions_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for sessions in data[u'Members']:
            # session list are uris
            session_list.append(sessions[u'@odata.id'])

        # for each session, get details
        for uri in session_list:
            session = {}
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                return response
            data = response['data']
            for prop in properties:
                if prop in data and prop not in session:
                    session[prop] = data[prop]
            oem_dict = response['data']['Oem']
            for prop in oem_properties:
                if prop in oem_dict and prop not in session:
                    session[prop] = oem_dict[prop]

            sessions_results.append(session)
        result["entries"] = sessions_results
        return result

    def clear_sessions(self):
        """
        delete all sessions
        :return: dict
        """
        response = self.get_request(self.root_uri + self.sessions_uri)
        if response['ret'] is False:
            return response
        data = response['data']

        # if no active sessions, return as success
        if data['Members@odata.count'] == 0:
            return {'ret': True, 'changed': False,
                    'msg': "There is no active sessions"}

        # loop to delete every active session
        for session in data[u'Members']:
            response = self.delete_request(
                self.root_uri + session[u'@odata.id'])
            if response['ret'] is False:
                return response

        return {'ret': True, 'changed': True,
                'msg': "Clear all sessions successfully"}

    def create_session(self):
        """
        create session
        :return: dict
        """
        if not self.creds.get('user') or not self.creds.get('pswd'):
            return {'ret': False, 'msg':
                    'Must provide the username and password parameters for '
                    'the CreateSession command'}

        payload = {
            'UserName': self.creds['user'],
            'Password': self.creds['pswd']
        }
        response = self.post_request(
            self.root_uri + self.sessions_uri, payload)
        if response['ret'] is False:
            return response

        headers = response['headers']
        if 'x-auth-token' not in headers:
            return {'ret': False, 'msg':
                    'The service did not return the X-Auth-Token header in '
                    'the response from the Sessions collection POST'}

        if 'location' not in headers:
            self.module.warn(
                'The service did not return the Location header for the '
                'session URL in the response from the Sessions collection '
                'POST')
            session_uri = None
        else:
            session_uri = urlparse(headers.get('location')).path

        session = dict()
        session['token'] = headers.get('x-auth-token')
        session['uri'] = session_uri
        return {'ret': True, 'changed': True, 'session': session,
                'msg': 'Session created successfully'}

    def delete_session(self, session_uri):
        """
        Delete the specified session
        :param session_uri:
        :return: dict
        """
        if not session_uri:
            return {'ret': False, 'msg':
                    'Must provide the session_uri parameter for the '
                    'DeleteSession command'}

        response = self.delete_request(self.root_uri + session_uri)
        if response['ret'] is False:
            return response

        return {'ret': True, 'changed': True,
                'msg': 'Session deleted successfully'}

    def manage_chassis_indicator_led(self, command):
        """
        Server positioning light management
        :param command: Position light status command
        :return:
        """
        return self.manage_indicator_led(command, self.chassis_uri)

    def manage_indicator_led(self, command, resource_uri=None):
        """
        Set the status of the server positioning light
        :param command: Position light status command
        :param resource_uri: resource uri
        :return:
        """
        key = 'IndicatorLED'
        if resource_uri is None:
            resource_uri = self.chassis_uri

        payloads = {
            'IndicatorLedOn': 'Lit',
            'IndicatorLedOff': 'Off',
            "IndicatorLedBlink": 'Blinking'
        }

        result = {}
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        if command in payloads.keys():
            payload = {'IndicatorLED': payloads[command]}
            response = self.patch_request(self.root_uri + resource_uri, payload)
            if response['ret'] is False:
                return response
        else:
            return {'ret': False, 'msg': 'Invalid command'}

        return result

    def get_multi_system_inventory(self):
        """
        Get multi system info
        :return:
        """
        return self.aggregate_systems(self.get_system_inventory)

    def get_system_inventory(self, systems_uri):
        """
        Get system information
        :param systems_uri:
        :return:
        """
        result = {}
        inventory = {}
        # Get these entries, but does not fail if not found
        properties = [
            'Status',
            'HostName',
            'PowerState',
            'Model',
            'Manufacturer',
            'PartNumber',
            'SystemType',
            'AssetTag',
            'SerialNumber',
            'BiosVersion',
            'MemorySummary',
            'ProcessorSummary',
            'Name',
            'Id'
        ]

        response = self.get_request(self.root_uri + systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for prop in properties:
            if prop in data:
                inventory[prop] = data[prop]

        result["entries"] = inventory
        return result

    def get_multi_cpu_inventory(self):
        """
        Get multi cpu info
        :return:
        """
        return self.aggregate_systems(self.get_cpu_inventory)

    def get_cpu_inventory(self, systems_uri):
        """
        Get cpu information
        :param systems_uri: system resource uri
        :return:
        """
        result = {}
        cpu_list = []
        cpu_results = []
        key = "Processors"
        # Get these entries, but does not fail if not found
        properties = [
            'Id',
            'InstructionSet',
            'Manufacturer',
            'MaxSpeedMHz',
            'Model',
            'Name',
            'Ppin',
            'ProcessorArchitecture',
            'ProcessorType',
            'Socket',
            'TotalCores',
            'TotalThreads',
            'Status'
        ]

        oem_properties = [
            'FrequencyMHz',
            'L1CacheKiB',
            'L2CacheKiB',
            'L3CacheKiB',
            'SerialNumber',
            'Temperature'
        ]

        # Search for 'key' entry and extract URI from it
        response = self.get_request(self.root_uri + systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        processors_uri = data[key]["@odata.id"]

        # Get a list of all CPUs and build respective URIs
        response = self.get_request(self.root_uri + processors_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for cpu in data[u'Members']:
            cpu_list.append(cpu[u'@odata.id'])

        for cpu_uri in cpu_list:
            cpu = {}
            uri = self.root_uri + cpu_uri
            response = self.get_request(uri)
            if response['ret'] is False:
                return response
            data = response['data']

            for prop in properties:
                if prop in data:
                    cpu[prop] = data[prop]

            oem_dict = data['Oem']['Public']
            for prop in oem_properties:
                if prop in oem_dict and prop not in cpu:
                    cpu[prop] = oem_dict[prop]

            cpu_results.append(cpu)
        result["entries"] = cpu_results
        return result

    def get_multi_memory_inventory(self):
        """
        Get multi memory information
        :return:
        """
        return self.aggregate_systems(self.get_memory_inventory)

    def get_memory_inventory(self, systems_uri):
        """
        Get memory information
        :param systems_uri: system resource uri
        :return:
        """
        result = {}
        memory_list = []
        memory_results = []
        key = "Memory"
        # Get these entries, but does not fail if not found
        properties = [
            'Id',
            'BaseModuleType',
            'CapacityMiB',
            'DeviceLocator',
            'ErrorCorrection',
            'IsRankSpareEnabled',
            'IsSpareDeviceEnabled',
            'Manufacturer',
            'MemoryDeviceType',
            'MemoryLocation',
            'Name',
            'OperatingSpeedMhz',
            'PartNumber',
            'RankCount',
            'SerialNumber',
            'Status'
        ]

        oem_properties = [
            'Authenticity',
            'Model',
            'Technology',
            'VDDQVolt'
        ]

        # Search for 'key' entry and extract URI from it
        response = self.get_request(self.root_uri + systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        memory_uri = data[key]["@odata.id"]

        # Get a list of all DIMMs and build respective URIs
        response = self.get_request(self.root_uri + memory_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for mem in data[u'Members']:
            memory_list.append(mem[u'@odata.id'])

        for memory_uri in memory_list:
            memory = {}
            uri = self.root_uri + memory_uri
            response = self.get_request(uri)
            if response['ret'] is False:
                return response
            data = response['data']

            if "Status" in data:
                if "State" in data["Status"]:
                    if data["Status"]["State"] == "Absent":
                        continue
            else:
                continue

            for prop in properties:
                if prop in data:
                    memory[prop] = data[prop]

            oem_dict = data['Oem']['Public']
            for prop in oem_properties:
                if prop in oem_dict and prop not in memory:
                    memory[prop] = oem_dict[prop]

            memory_results.append(memory)
        result["entries"] = memory_results
        return result

    def get_fan_inventory(self):
        """
        Get fan information
        :return:
        """
        result = {}
        fan_results = []
        key = "Thermal"
        # Get these entries, but does not fail if not found
        properties = [
            'MemberId',
            'Name',
            'MinReadingRange',
            'MaxReadingRange',
            'PartNumber',
            'Reading',
            'ReadingUnits',
            'Status'
        ]

        oem_properties = [
            'Position',
            'SlotNumber',
            'SpeedRatio'
        ]

        # Go through list
        for chassis_uri in self.chassis_uris:
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            if key in data:
                # match: found an entry for "Thermal" information = fans
                thermal_uri = data[key]["@odata.id"]
                response = self.get_request(self.root_uri + thermal_uri)
                if response['ret'] is False:
                    return response
                result['ret'] = True
                data = response['data']

                # Checking if fans are present
                if u'Fans' in data:
                    for device in data[u'Fans']:
                        fan = {}
                        for prop in properties:
                            if prop in device:
                                fan[prop] = device[prop]

                        oem_dict = device['Oem']['Public']
                        for prop in oem_properties:
                            if prop in oem_dict and prop not in fan:
                                fan[prop] = oem_dict[prop]

                        fan_results.append(fan)
                else:
                    return {'ret': False, 'msg': "No Fans present"}
        result["entries"] = fan_results
        return result

    def get_chassis_thermals(self):
        """
        Get temperature sensor information
        :return:
        """
        result = {}
        sensors = []
        key = "Thermal"

        # Get these entries, but does not fail if not found
        properties = [
            'LowerThresholdCritical',
            'LowerThresholdFatal',
            'LowerThresholdNonCritical',
            'MemberId',
            'Name',
            'PhysicalContext',
            'ReadingCelsius',
            'SensorNumber',
            'UpperThresholdCritical',
            'UpperThresholdFatal',
            'UpperThresholdNonCritical',
            'Status'
        ]

        # Go through list
        for chassis_uri in self.chassis_uris:
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            if key in data:
                thermal_uri = data[key]["@odata.id"]
                response = self.get_request(self.root_uri + thermal_uri)
                if response['ret'] is False:
                    return response
                result['ret'] = True
                data = response['data']
                if "Temperatures" in data:
                    for sensor in data[u'Temperatures']:
                        sensor_result = {}
                        for prop in properties:
                            if prop in sensor:
                                if sensor[prop] is not None:
                                    sensor_result[prop] = sensor[prop]
                        sensors.append(sensor_result)

        if sensors is None:
            return {'ret': False, 'msg': 'Key Temperatures was not found.'}

        result['entries'] = sensors
        return result

    def get_chassis_power(self):
        """
        Get Power Controller Information
        :return:
        """
        result = {}
        key = "Power"

        # Get these entries, but does not fail if not found
        properties = [
            'MaxNum',
            'MemberId',
            'Name',
            'PowerConsumedWatts',
            'PowerLimit',
            'PowerMetrics',
            'Status'
        ]

        oem_properties = [
            'CurrentCPUPowerWatts',
            'CurrentDiskPowerWatts',
            'CurrentFanPowerWatts',
            'CurrentMemoryPowerWatts'
        ]

        chassis_power_results = []
        # Go through list
        for chassis_uri in self.chassis_uris:
            chassis_power_result = {}
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            if key in data:
                response = self.get_request(self.root_uri + data[key]['@odata.id'])
                data = response['data']
                if 'PowerControl' in data:
                    if len(data['PowerControl']) > 0:
                        data = data['PowerControl'][0]
                        for prop in properties:
                            if prop in data:
                                chassis_power_result[prop] = data[prop]
                        oem_dict = data['Oem']['Public']
                        for prop in oem_properties:
                            if (prop in oem_dict and
                                    prop not in chassis_power_result):
                                chassis_power_result[prop] = oem_dict[prop]

                chassis_power_results.append(chassis_power_result)

        if len(chassis_power_results) > 0:
            result['entries'] = chassis_power_results
            return result
        else:
            return {'ret': False, 'msg': 'Power information not found.'}

    def get_chassis_inventory(self):
        """
        Get chassis information
        :return:
        """
        result = {}
        chassis_results = []

        # Get these entries, but does not fail if not found
        properties = [
            'Id',
            'ChassisType',
            'AssetTag',
            'IndicatorLED',
            'Manufacturer',
            'Model',
            'Name',
            'PartNumber',
            'PowerState',
            'SKU',
            'SerialNumber',
            'Status'
        ]

        # Go through list
        for chassis_uri in self.chassis_uris:
            response = self.get_request(self.root_uri + chassis_uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            chassis_result = {}
            for prop in properties:
                if prop in data:
                    chassis_result[prop] = data[prop]
            chassis_results.append(chassis_result)

        result["entries"] = chassis_results
        return result

    def get_multi_chassis_health_report(self):
        """
        Get multi chassis health report
        :return:
        """
        return self.aggregate_chassis(self.get_chassis_health_report)

    def get_chassis_health_report(self, chassis_uri):
        """
        Get chassis health report
        :param chassis_uri: chassis resource uri
        :return:
        """
        sub_systems = [
            'Power.PowerSupplies',
            'Thermal.Fans',
            'Links.PCIeDevices'
        ]
        return self.get_health_report('Chassis', chassis_uri, sub_systems)

    def get_health_report(self, category, uri, subsystems):
        result = {}
        health = {}
        status = 'Status'

        # Get health status of top level resource
        response = self.get_request(self.root_uri + uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        health[category] = {status: data.get(status, "Status not available")}

        # Get health status of subsystems
        for sub in subsystems:
            d = None
            if sub.startswith('Links.'):  # ex: Links.PCIeDevices
                sub = sub[len('Links.'):]
                d = data.get('Links', {})
            elif '.' in sub:  # ex: Thermal.Fans
                p, sub = sub.split('.')
                u = data.get(p, {}).get('@odata.id')
                if u:
                    r = self.get_request(self.root_uri + u)
                    if r['ret']:
                        d = r['data']
                if not d:
                    continue
            else:  # ex: Memory
                d = data
            health[sub] = []
            self.get_health_subsystem(sub, d, health)
            if not health[sub]:
                del health[sub]

        result["entries"] = health
        return result

    def get_health_subsystem(self, subsystem, data, health):
        """
        Get Subsystem Health Report
        :param subsystem: Subsystem
        :param data: resp
        :param health: health report
        :return: dict
        """
        if subsystem in data:
            sub = data.get(subsystem)
            if isinstance(sub, list):
                for r in sub:
                    if '@odata.id' in r:
                        uri = r.get('@odata.id')
                        expanded = None
                        if '#' in uri and len(r) > 1:
                            expanded = r
                        self.get_health_resource(subsystem, uri, health,
                                                 expanded)
            elif isinstance(sub, dict):
                if '@odata.id' in sub:
                    uri = sub.get('@odata.id')
                    self.get_health_resource(subsystem, uri, health, None)
        elif 'Members' in data:
            for m in data.get('Members'):
                u = m.get('@odata.id')
                r = self.get_request(self.root_uri + u)
                if r.get('ret'):
                    d = r.get('data')
                    self.get_health_subsystem(subsystem, d, health)

    def get_health_resource(self, subsystem, uri, health, expanded):
        """
        Get health resource information
        :param subsystem: Subsystem
        :param uri: uri
        :param health: health report
        :param expanded: expaned info
        :return:
        """
        status = 'Status'

        if expanded:
            d = expanded
        else:
            r = self.get_request(self.root_uri + uri)
            if r.get('ret'):
                d = r.get('data')
            else:
                return

        if 'Members' in d:  # collections case
            for m in d.get('Members'):
                u = m.get('@odata.id')
                r = self.get_request(self.root_uri + u)
                if r.get('ret'):
                    p = r.get('data')
                    if p:
                        e = {self.to_singular(subsystem.lower()) + '_uri': u,
                             status: p.get(status,
                                           "Status not available")}
                        health[subsystem].append(e)
        else:  # non-collections case
            e = {self.to_singular(subsystem.lower()) + '_uri': uri,
                 status: d.get(status,
                               "Status not available")}
            health[subsystem].append(e)

    @classmethod
    def to_singular(cls, resource_name):
        """
        Plural to singular
        :param resource_name: resource name
        :return:
        """
        # Change ending ies to y
        if resource_name.endswith('ies'):
            resource_name = resource_name[:-3] + 'y'
        # remove ending s
        elif resource_name.endswith('s'):
            resource_name = resource_name[:-1]
        return resource_name
