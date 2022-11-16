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

GET_HEADERS = {'accept': 'application/json', 'OData-Version': '4.0'}
POST_HEADERS = {'content-type': 'application/json',
                'accept': 'application/json',
                'OData-Version': '4.0'}
PATCH_HEADERS = {'content-type': 'application/json',
                 'accept': 'application/json',
                 'OData-Version': '4.0'}
DELETE_HEADERS = {'accept': 'application/json', 'OData-Version': '4.0'}

FAIL_MSG = 'ID of the target %(resource)s resource when there is more ' \
           'than one %(resource)s is no longer allowed. Use the ' \
           '`resource_id` option to specify the target %(resource)s ID.'


class HDMRedfishUtils(object):

    def __init__(self, creds, root_uri, timeout, module, resource_id=None,
                 data_modification=False, strip_etag_quotes=False):
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
                'msg': "HTTP Error %s on get request to '%s', "
                       "extended message: '%s'" % (e.code, uri, msg),
                'status': e.code}
        except URLError as e:
            return {'ret': False,
                    'msg': "URL Error on get request to '%s': '%s'"
                           % (uri, e.reason)}
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed get request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'data': data, 'headers': headers}

    def post_request(self, uri, pyld):
        req_headers = dict(POST_HEADERS)
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            resp = open_url(uri, data=json.dumps(pyld),
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
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed POST request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'headers': headers, 'resp': resp}

    def patch_request(self, uri, pyld):
        req_headers = dict(PATCH_HEADERS)
        r = self.get_request(uri)
        if r['ret']:
            etag = r['headers'].get('etag')
            if not etag:
                etag = r['data'].get('@odata.etag')
            if etag:
                if self.strip_etag_quotes:
                    etag = etag.strip('"')
                req_headers['If-Match'] = etag
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            resp = open_url(uri, data=json.dumps(pyld),
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
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed PATCH request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'resp': resp}

    def delete_request(self, uri, pyld=None):
        req_headers = dict(DELETE_HEADERS)
        username, password, basic_auth = self._auth_params(req_headers)
        try:
            data = json.dumps(pyld) if pyld else None
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
        except Exception as e:
            return {'ret': False,
                    'msg': "Failed DELETE request to '%s': '%s'" % (
                        uri, to_text(e))}
        return {'ret': True, 'resp': resp}

    @staticmethod
    def _get_extended_message(error):
        msg = http_client.responses.get(error.code, '')
        if error.code >= 400:
            try:
                body = error.read().decode('utf-8')
                data = json.loads(body)
                ext_info = data['error']['@Message.ExtendedInfo']
                try:
                    msg = ext_info[0]['Message']
                except (ValueError, Exception):
                    msg = str(data['error']['@Message.ExtendedInfo'])
            except (ValueError, Exception):
                pass
        return msg

    def _init_session(self):
        pass

    def _get_vendor(self):
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return {'ret': False, 'Vendor': ''}
        data = response['data']
        if 'Vendor' in data:
            return {'ret': True, 'Vendor': data["Vendor"]}
        else:
            return {'ret': True, 'Vendor': ''}

    def _find_accountservice_resource(self):
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

    def _get_resource_uri_by_id(self, uris, id_prop):
        for uri in uris:
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                continue
            data = response['data']
            if id_prop == data.get('Id'):
                return uri
        return None

    def _find_systems_resource(self):
        response = self.get_request(self.root_uri + self.service_root)
        if response['ret'] is False:
            return response
        data = response['data']
        if 'Systems' not in data:
            return {'ret': False, 'msg': "Systems resource not found"}
        response = self.get_request(
            self.root_uri + data['Systems']['@odata.id'])
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
            elif len(self.systems_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'System'})
        return {'ret': True}

    def _find_managers_resource(self):
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
            elif len(self.manager_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'Manager'})
        return {'ret': True}

    def _find_account_uri(self, username=None, acct_id=None):
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
        if not user.get('account_username'):
            return {'ret': False, 'msg':
                    'Must provide account_username for AddUser command'}

        response = self._find_account_uri(
            username=user.get('account_username'))
        if response['ret']:
            # account_username already exists
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

    def delete_user(self, user):
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            if response.get('no_match'):
                # account does not exist
                return {'ret': True, 'changed': False}
            else:
                return response
        uri = response['uri']
        response = self.delete_request(self.root_uri + uri)
        if not response['ret']:
            return response
        return {'ret': True}

    def update_user_role(self, user):
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
            return {'ret': True, 'changed': False}

        payload = {
            'RoleId': user.get('account_roleid'),
            'Locked': data.get('Locked'),
            'Enabled': data.get('Enabled'),
        }
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def update_user_password(self, user):
        response = self._find_account_uri(
            username=user.get('account_username'),
            acct_id=user.get('account_id'))
        if not response['ret']:
            return response
        uri = response['uri']
        data = response['data']
        payload = {
            'Password': user['account_password'],
            'Locked': data.get('Locked'),
            'Enabled': data.get('Enabled'),
            'RoleId': data.get('RoleId')
        }
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def update_user_name(self, user):
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
        payload = {
            'UserName': user['account_updatename'],
            'Locked': data.get('Locked'),
            'Enabled': data.get('Enabled'),
            'RoleId': data.get('RoleId')
        }
        response = self.patch_request(self.root_uri + uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def set_ntp_server(self, mgr_attributes):
        payload = {}
        attr_name = mgr_attributes["mgr_attr_name"]
        attr_value = mgr_attributes["mgr_attr_value"]
        if attr_name == "ServiceEnabled":
            payload["ServiceEnabled"] = attr_value
        if attr_name == "PreferredNtpServer":
            payload["PreferredNtpServer"] = attr_value
        if attr_name in {"RefreshInterval", "TertiaryNtpServer", "TimeZone"}:
            payload["Oem"] = {
                "Public": {attr_name: attr_value}
            }
        service_uri = "/redfish/v1/Managers/1/NtpService"
        response = self.patch_request(self.root_uri + service_uri, payload)
        if not response["ret"]:
            return response

        return {
            "ret": True,
            "changed": True,
            "msg": "Modified %s" % mgr_attributes["mgr_attr_name"],
        }

    def set_bios_attributes(self, attributes):
        warning = ""
        # Construct payload and issue PATCH command
        payload = {"Attributes": attributes}
        set_bios_attr_uri = "/redfish/v1/Systems/1/Bios/SD"
        response = self.patch_request(
            self.root_uri + set_bios_attr_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True,
                'msg': "Modified BIOS attributes %s" % payload,
                'warning': warning}

    def set_boot_override(self, boot_opts):
        result = {}
        key = "Boot"

        bootdevice = boot_opts.get('bootdevice')
        uefi_target = boot_opts.get('uefi_target')
        boot_next = boot_opts.get('boot_next')
        override_enabled = boot_opts.get('override_enabled')
        boot_override_mode = boot_opts.get('boot_override_mode')

        if not bootdevice and override_enabled != 'Disabled':
            return {'ret': False,
                    'msg': "bootdevice option required for temporary boot override"}

        response = self.get_request(self.root_uri + self.systems_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        if key not in data:
            return {'ret': False, 'msg': "Key %s not found" % key}

        boot = data[key]

        if override_enabled != 'Disabled':
            annotation = 'BootSourceOverrideTarget@Redfish.AllowableValues'
            if annotation in boot:
                allowable_values = boot[annotation]
                if isinstance(allowable_values, list) and bootdevice not in allowable_values:
                    return {'ret': False,
                            'msg': "Boot device %s not in list of allowable values (%s)" %
                                   (bootdevice, allowable_values)}

        # read existing values
        cur_enabled = boot.get('BootSourceOverrideEnabled')
        target = boot.get('BootSourceOverrideTarget')
        cur_uefi_target = boot.get('UefiTargetBootSourceOverride')
        cur_boot_next = boot.get('BootNext')
        cur_override_mode = boot.get('BootSourceOverrideMode')

        if override_enabled == 'Disabled':
            payload = {
                'Boot': {
                    'BootSourceOverrideEnabled': override_enabled
                }
            }
        elif bootdevice == 'UefiTarget':
            if not uefi_target:
                return {'ret': False,
                        'msg': "uefi_target option required to SetOneTimeBoot for UefiTarget"}
            if override_enabled == cur_enabled and target == bootdevice and uefi_target == cur_uefi_target:
                # If properties are already set, no changes needed
                return {'ret': True, 'changed': False}
            payload = {
                'Boot': {
                    'BootSourceOverrideEnabled': override_enabled,
                    'BootSourceOverrideTarget': bootdevice,
                    'UefiTargetBootSourceOverride': uefi_target
                }
            }
        elif bootdevice == 'UefiBootNext':
            if not boot_next:
                return {'ret': False,
                        'msg': "boot_next option required to SetOneTimeBoot for UefiBootNext"}
            if cur_enabled == override_enabled and target == bootdevice and boot_next == cur_boot_next:
                # If properties are already set, no changes needed
                return {'ret': True, 'changed': False}
            payload = {
                'Boot': {
                    'BootSourceOverrideEnabled': override_enabled,
                    'BootSourceOverrideTarget': bootdevice,
                    'BootNext': boot_next
                }
            }
        else:
            if (cur_enabled == override_enabled and target == bootdevice and
                    (cur_override_mode == boot_override_mode or not boot_override_mode)):
                # If properties are already set, no changes needed
                return {'ret': True, 'changed': False}
            payload = {
                'Boot': {
                    'BootSourceOverrideEnabled': override_enabled,
                    'BootSourceOverrideTarget': bootdevice
                }
            }
            if boot_override_mode:
                payload['Boot']['BootSourceOverrideMode'] = boot_override_mode

        response = self.patch_request(self.root_uri + self.systems_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True}

    def _map_reset_type(self, reset_type, allowable_values):
        equiv_types = {
            'On': 'ForceOn',
            'ForceOn': 'On',
            'ForceOff': 'GracefulShutdown',
            'GracefulShutdown': 'ForceOff',
            'GracefulRestart': 'ForceRestart',
            'ForceRestart': 'GracefulRestart'
        }

        if reset_type in allowable_values:
            return reset_type
        if reset_type not in equiv_types:
            return reset_type
        mapped_type = equiv_types[reset_type]
        if mapped_type in allowable_values:
            return mapped_type
        return reset_type

    def _get_all_action_info_values(self, action):
        """Retrieve all parameter values for an Action from ActionInfo.
        Fall back to AllowableValue annotations if no ActionInfo found.
        Return the result in an ActionInfo-like dictionary, keyed
        by the name of the parameter. """
        ai = {}
        if '@Redfish.ActionInfo' in action:
            ai_uri = action['@Redfish.ActionInfo']
            response = self.get_request(self.root_uri + ai_uri)
            if response['ret'] is True:
                data = response['data']
                if 'Parameters' in data:
                    params = data['Parameters']
                    ai = dict((p['Name'], p)
                              for p in params if 'Name' in p)
        if not ai:
            ai = dict((k[:-24],
                       {'AllowableValues': v}) for k, v in action.items()
                      if k.endswith('@Redfish.AllowableValues'))
        return ai

    def manage_system_power(self, command):
        return self.manage_power(command, self.systems_uri,
                                 '#ComputerSystem.Reset')

    def manage_manager_power(self, command):
        return self.manage_power(command, self.manager_uri,
                                 '#Manager.Reset')

    def manage_power(self, command, resource_uri, action_name):
        key = "Actions"
        reset_type_values = ['On', 'ForceOff', 'GracefulShutdown',
                             'GracefulRestart', 'ForceRestart', 'Nmi',
                             'ForceOn', 'PushPowerButton', 'PowerCycle']

        # command should be PowerOn, PowerForceOff, etc.
        if not command.startswith('Power'):
            return {'ret': False, 'msg': 'Invalid Command (%s)' % command}
        reset_type = command[5:]

        # map Reboot to a ResetType that does a reboot
        if reset_type == 'Reboot':
            reset_type = 'GracefulRestart'

        if reset_type not in reset_type_values:
            return {'ret': False, 'msg': 'Invalid Command (%s)' % command}

        # read the resource and get the current power state
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        data = response['data']
        power_state = data.get('PowerState')

        # if power is already in target state, nothing to do
        if power_state == "On" and reset_type in ['On', 'ForceOn']:
            return {'ret': True, 'changed': False}
        if power_state == "Off" and reset_type in ['GracefulShutdown', 'ForceOff']:
            return {'ret': True, 'changed': False}
        # if power is already in target state, nothing to do
        if power_state == "On" and reset_type in ['On', 'ForceOn']:
            return {'ret': True, 'changed': False}
        if power_state == "Off" and reset_type in ['GracefulRestart',
                                                  'ForceRestart', 'PowerCycle']:
            return {'ret': False, 'msg':
                '(%s) command not available in shutdown state' % command}

        # get the reset Action and target URI
        if key not in data or action_name not in data[key]:
            return {'ret': False, 'msg': 'Action %s not found' % action_name}
        reset_action = data[key][action_name]
        if 'target' not in reset_action:
            return {'ret': False,
                    'msg': 'target URI missing from Action %s' % action_name}
        action_uri = reset_action['target']

        # get AllowableValues
        ai = self._get_all_action_info_values(reset_action)
        allowable_values = ai.get('ResetType', {}).get('AllowableValues', [])

        # map ResetType to an allowable value if needed
        if reset_type not in allowable_values:
            reset_type = self._map_reset_type(reset_type, allowable_values)

        # define payload
        payload = {'ResetType': reset_type}

        # POST to Action URI
        response = self.post_request(self.root_uri + action_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True, 'changed': True}

    def set_ipv4(self, info):
        if not info.get('net_id'):
            return {'ret': False, 'msg':
                    'Must provide net_id for SetIPv4 command'}
        resource_uri = ("/redfish/v1/Managers/1/EthernetInterfaces/%s" %
                        info.get("net_id"))
        # read the resource and get the current ip info
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response

        data = response['data']
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
        response = self.patch_request(self.root_uri + resource_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def set_ipv6(self, info):
        if not info.get('net_id'):
            return {'ret': False, 'msg':
                    'Must provide net_id for SetIPv6 command'}
        resource_uri = ("/redfish/v1/Managers/1/EthernetInterfaces/%s" %
                        info.get("net_id"))
        # read the resource and get the current ip info
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
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
        response = self.patch_request(self.root_uri + resource_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def create_logical_driver(self, details):
        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for CreateLogicalDrive command'}
        resource_uri = ("/redfish/v1/Systems/1/Storages/RAIDStorage%s" %
                        details.get('storage_id'))
        # read the resource and get the current ip info
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        payload = {"Oem": details.get("raid")}
        resource_uri = "%s/Volumes" % resource_uri
        response = self.post_request(self.root_uri + resource_uri, payload)
        if not response['ret']:
            return response
        return {'ret': True}

    def delete_logical_driver(self, details):
        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for DeleteLogicalDrive command'}
        if not details.get('logical_id'):
            return {'ret': False, 'msg':
                    'Must provide logical_id for DeleteLogicalDrive command'}
        resource_uri = ("/redfish/v1/Systems/1/Storages/RAIDStorage%s/Volumes"
                        "/LogicalDrive%s" %
                        (details['storage_id'], details['logical_id']))
        response = self.delete_request(self.root_uri + resource_uri)
        if not response['ret']:
            return response
        return {'ret': True}

    def modify_logical_driver(self, details):

        if not details.get('storage_id'):
            return {'ret': False, 'msg':
                    'Must provide storage_id for ModifyLogicalDrive command'}
        if not details.get('logical_id'):
            return {'ret': False, 'msg':
                    'Must provide logical_id for ModifyLogicalDrive command'}
        resource_uri = ("/redfish/v1/Systems/1/Storages/RAIDStorage%s/Volumes"
                        "/LogicalDrive%s" %
                        (details['storage_id'], details['logical_id']))
        # read the resource and get the current ip info
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        payload = {
            "Oem": {
                "Public":
                    {
                        "WritePolicy": details.get("write_policy"),
                        "ReadPolicy": details.get("read_policy")
                    }
            }
        }
        response = self.patch_request(self.root_uri + resource_uri, payload)
        if response['ret'] is False:
            return response
        return {'ret': True}

    def get_bios_attributes(self, systems_uri):
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
        return self.aggregate_systems(self.get_bios_attributes)

    def aggregate_systems(self, func):
        return self.aggregate(func, self.systems_uris, 'system_uri')

    def aggregate(self, func, uri_list, uri_name):
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
        return self.aggregate_systems(self.get_psu_inventory)

    def get_psu_inventory(self):
        result = {}
        psu_list = []
        psu_results = []
        key = "PowerSupplies"
        # get these entries, but does not fail if not found
        properties = ['Name', 'Model', 'SerialNumber', 'PartNumber', 'Manufacturer',
                      'FirmwareVersion', 'PowerCapacityWatts', 'PowerSupplyType',
                      'Status']

        # get a list of all Chassis and build URIs, then get all PowerSupplies
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
            for psu in psu_list:
                psu_not_present = False
                psu_data = {}
                for property in properties:
                    if property in psu:
                        if psu[property] is not None:
                            if property == 'Status':
                                if 'State' in psu[property]:
                                    if psu[property]['State'] == 'Absent':
                                        psu_not_present = True
                            psu_data[property] = psu[property]
                if psu_not_present:
                    continue
                psu_results.append(psu_data)

        result["entries"] = psu_results
        if not result["entries"]:
            return {'ret': False, 'msg': "No PowerSupply objects found"}
        return result

    def _find_chassis_resource(self):
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
                self.chassis_uri = self._get_resource_uri_by_id(self.chassis_uris,
                                                                self.resource_id)
                if not self.chassis_uri:
                    return {
                        'ret': False,
                        'msg': "Chassis resource %s not found" % self.resource_id}
            elif len(self.chassis_uris) > 1:
                self.module.fail_json(msg=FAIL_MSG % {'resource': 'Chassis'})
        return {'ret': True}

    def _find_updateservice_resource(self):
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
            if 'SoftwareInventory' in data:
                self.software_uri = data['SoftwareInventory'][u'@odata.id']
            return {'ret': True}

    def get_firmware_inventory(self):
        if self.firmware_uri is None:
            return {'ret': False, 'msg': 'No FirmwareInventory resource found'}
        else:
            return self._software_inventory(self.firmware_uri)

    def get_software_inventory(self):
        if self.software_uri is None:
            return {'ret': False, 'msg': 'No SoftwareInventory resource found'}
        else:
            return self._software_inventory(self.software_uri)

    def _software_inventory(self, uri):
        result = {}
        response = self.get_request(self.root_uri + uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        result['entries'] = []
        for member in data[u'Members']:
            uri = self.root_uri + member[u'@odata.id']
            # get details for each software or firmware member
            response = self.get_request(uri)
            if response['ret'] is False:
                return response
            result['ret'] = True
            data = response['data']
            software = {}
            # get these standard properties if present
            for key in ['Name', 'Id', 'Status', 'Version', 'Updateable',
                        'SoftwareId', 'LowestSupportedVersion', 'Manufacturer',
                        'ReleaseDate']:
                if key in data:
                    software[key] = data.get(key)
            result['entries'].append(software)
        return result


    # def get_multi_psu_inventory(self):
    #     return self.aggregate_systems(self.get_psu_inventory)

    def get_multi_nic_inventory(self, resource_type):
        ret = True
        entries = []

        #  Given resource_type, use the proper URI
        if resource_type == 'Systems':
            resource_uris = self.systems_uris
        elif resource_type == 'Manager':
            resource_uris = self.manager_uris
        elif resource_type == 'Chassis':
            resource_uris = self.chassis_uris
        for resource_uri in resource_uris:
            inventory = self.get_nic_inventory(resource_uri)
            ret = inventory.pop('ret') and ret
            if 'entries' in inventory:
                entries = inventory['entries']
        return dict(ret=ret, entries=entries)

    def get_nic_inventory(self, resource_uri):
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

        ethernetinterfaces_uri = data[key]["@odata.id"]

        # get a list of all network controllers and build respective URIs
        response = self.get_request(self.root_uri + ethernetinterfaces_uri)
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
        result = {}
        properties = ['Name', 'Id', 'Model', 'Manufacturer', 'Status']
        oem_properties = ['CapableSpeedGbs', 'CardManufacturer', 'CardModel',
                          'DeviceLocator', 'FirmwareVersion',
                          'NetworkTechnology', 'Position', 'RootBDF',
                          'SerialNumber', 'SlotNumber', 'TemperatureCelsius']
        response = self.get_request(self.root_uri + resource_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']
        nic = {}
        for property in properties:
            if property in data:
                nic[property] = data[property]
        oem_data = data["Oem"]["Public"]
        for property in oem_properties:
            if property in oem_data:
                nic[property] = oem_data[property]
        controller_list = []
        if isinstance(data.get("Controllers"), list):
            controller_resource = data.get("Controllers")
            for ctrl in controller_resource:
                network_ports = []
                if isinstance(ctrl.get("Links"), dict):
                    if isinstance(ctrl["Links"].get(
                            "NetworkPorts"), list):
                        network_ports = ctrl["Links"].get(
                            "NetworkPorts")
                nic["ports"] = self.package_port_info(network_ports)
        result['entries'] = nic
        return result

    def package_port_info(self, ports):
        result = []
        for port in ports:
            port_uri = port.get("@odata.id", None)
            response = self.get_request(self.root_uri + port_uri)
            if response['ret'] is False:
                return response
            data = response['data']
            port_dict = {"id": data.get("Id"),
                         "mac_address": data.get(
                             "AssociatedNetworkAddresses"),
                         "link_status": data.get("LinkStatus")}
            if isinstance(data.get("Oem"),
                          dict) and isinstance(
                data["Oem"].get(
                    "Public"), dict):
                oem_resp = data["Oem"]["Public"]
                port_dict["media_type"] = oem_resp.get("PortType")
            result.append(port_dict)
        return result

    def get_sessions(self):
        result = {}
        # listing all users has always been slower than other operations, why?
        session_list = []
        sessions_results = []
        # get these entries, but does not fail if not found
        properties = ['Description', 'Id', 'Name', 'UserName']

        response = self.get_request(self.root_uri + self.sessions_uri)
        if response['ret'] is False:
            return response
        result['ret'] = True
        data = response['data']

        for sessions in data[u'Members']:
            session_list.append(
                sessions[u'@odata.id'])  # session_list[] are URIs

        # for each session, get details
        for uri in session_list:
            session = {}
            response = self.get_request(self.root_uri + uri)
            if response['ret'] is False:
                return response
            data = response['data']

            for property in properties:
                if property in data:
                    session[property] = data[property]

            sessions_results.append(session)
        result["entries"] = sessions_results
        return result

    def clear_sessions(self):
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
        if not session_uri:
            return {'ret': False, 'msg':
                    'Must provide the session_uri parameter for the '
                    'DeleteSession command'}

        response = self.delete_request(self.root_uri + session_uri)
        if response['ret'] is False:
            return response

        return {'ret': True, 'changed': True,
                'msg': 'Session deleted successfully'}
