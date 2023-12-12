#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) H3C.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.h3c_bmc.hdm.plugins.module_utils.hdm_redfish_utils \
    import HDMRedfishUtils
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


RETURN = '''
msg:
    description: Message with action result or error description
    returned: always
    type: str
    sample: "Action was successful"
'''


# More will be added as module features are expanded
CATEGORY_COMMANDS_ALL = {
    "Systems": ["SetBiosAttributes", "SetOneTimeBoot", "SetBootDevice",
                "PowerOn", "PowerForceOff", "PowerForceRestart",
                "PowerGracefulRestart",
                "PowerGracefulShutdown", "PowerReboot", "CreateLogicalDrive",
                "DeleteLogicalDrive", "ModifyLogicalDrive"],
    "Chassis": ["IndicatorLedOn"],
    "Accounts": ["AddUser", "DeleteUser",
                 "UpdateUserRole", "UpdateUserPassword", "UpdateUserName"],
    "Sessions": ["ClearSessions", "CreateSession", "DeleteSession"],
    "Manager": ["SetNTPServers", "SetTimeZone", "SetIPv4Static", "SetIPv4DHCP",
                "SetIPv6Static", "SetIPv6DHCP"]
}


def main():
    result = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True),
            command=dict(required=True, type='list', elements='str'),
            baseuri=dict(required=True),
            username=dict(),
            password=dict(no_log=True),
            auth_token=dict(no_log=True),
            session_uri=dict(),
            id=dict(aliases=["account_id"]),
            new_username=dict(aliases=["account_username"]),
            new_password=dict(aliases=["account_password"], no_log=True),
            roleid=dict(aliases=["account_roleid"]),
            update_username=dict(type='str', aliases=["account_updatename"]),
            timeout=dict(type='int', default=60),

            # Des: Modify parameter name
            boot_enable=dict(),
            boot_mode=dict(),
            boot_target=dict(),

            # Des: Modify parameter name
            resource_id=dict(),
            attribute_name=dict(),
            attribute_value=dict(),
            bios_attributes=dict(type='dict', default={}),
            network_interface_id=dict(),
            new_address=dict(),
            new_address_origin=dict(),
            new_gateway=dict(),
            new_subnetmask=dict(),
            new_prefix_length=dict(type='int'),
            storage_id=dict(),
            raid_details=dict(type='dict', default={}),
            logical_id=dict(),
            write_policy=dict(),
            read_policy=dict(),

            # Des: G6
            access_policy=dict(),
            drive_cache=dict()

            # Des: G6 

        ),
        required_together=[
            ('username', 'password'),
        ],
        required_one_of=[
            ('username', 'auth_token'),
        ],
        mutually_exclusive=[
            ('username', 'auth_token'),
        ],
        supports_check_mode=False
    )

    category = module.params['category']
    command_list = module.params['command']

    # admin credentials used for authentication
    creds = {
        'user': module.params['username'],
        'pswd': module.params['password'],
        'token': module.params['auth_token']}

    # user to add/modify/delete
    user = {
        'account_id': module.params['id'],
        'account_username': module.params['new_username'],
        'account_password': module.params['new_password'],
        'account_roleid': module.params['roleid'],
        'account_updatename': module.params['update_username']
    }

    # timeout
    timeout = module.params['timeout']

    mgr_attributes = {
        "mgr_attr_name": module.params["attribute_name"],
        "mgr_attr_value": module.params["attribute_value"],
    }

    # Boot override options
    boot_opts = {
        'boot_enable': module.params['boot_enable'],
        'boot_mode': module.params['boot_mode'],
        'boot_target': module.params['boot_target']
    }

    bios_attributes = module.params["bios_attributes"]

    ipv4_info = {
        "net_id":  module.params['network_interface_id'],
        "new_addr": module.params['new_address'],
        "new_origin": module.params['new_address_origin'],
        "new_gateway": module.params['new_gateway'],
        "new_sub": module.params['new_subnetmask'],
    }

    ipv6_info = {
        "net_id":  module.params['network_interface_id'],
        "new_addr": module.params['new_address'],
        "new_origin": module.params['new_address_origin'],
        "new_gateway": module.params['new_gateway'],
        "prefix_length": module.params['new_prefix_length'],
    }

    raid_detail = {
        "storage_id": module.params['storage_id'],
        "raid": module.params['raid_details']
    }

    logical_detail = {
        "storage_id": module.params['storage_id'],
        "logical_id": module.params['logical_id'],
        "write_policy": module.params['write_policy'],
        "read_policy": module.params['read_policy'],

        # Des: G6
        "access_policy": module.params['access_policy'],
        "drive_cache": module.params['drive_cache'],

        # Des: G6
    }

    # Build root URI
    root_uri = "https://" + module.params['baseuri']
    rf_utils = HDMRedfishUtils(creds, root_uri, timeout,
                               module, data_modification=True)

    # Check that Category is valid
    if category not in CATEGORY_COMMANDS_ALL:
        module.fail_json(
            msg=to_native(
                "Invalid Category '%s'. Valid Categories = %s" %
                (category, list(
                    CATEGORY_COMMANDS_ALL.keys()))))

    # Check that all commands are valid
    for cmd in command_list:
        # Fail if even one command given is invalid
        if cmd not in CATEGORY_COMMANDS_ALL[category]:
            module.fail_json(
                msg=to_native(
                    "Invalid Command '%s'. Valid Commands = %s" %
                    (cmd, CATEGORY_COMMANDS_ALL[category])))

    # Organize by Categories / Commands
    if category == "Accounts":
        ACCOUNTS_COMMANDS = {
            "AddUser": rf_utils.add_user,
            "DeleteUser": rf_utils.delete_user,
            "UpdateUserRole": rf_utils.update_user_role,
            "UpdateUserPassword": rf_utils.update_user_password,
            "UpdateUserName": rf_utils.update_user_name
        }

        # execute only if we find an Account service resource
        result = rf_utils._find_accountservice_resource()
        if result['ret'] is False:
            module.fail_json(msg=to_native(result['msg']))

        for command in command_list:
            result = ACCOUNTS_COMMANDS[command](user)

    elif category == "Systems":
        # execute only if we find a System resource
        result = rf_utils._find_systems_resource()
        if result['ret'] is False:
            module.fail_json(msg=to_native(result['msg']))

        for command in command_list:
            if command.startswith('Power'):
                result = rf_utils.manage_system_power(command)
            elif command == "SetBiosAttributes":
                result = rf_utils.set_bios_attributes(bios_attributes)
            elif command == "SetOneTimeBoot":
                boot_opts['boot_enable'] = 'Once'
                result = rf_utils.set_boot_override(boot_opts)
            elif command == "SetBootDevice":

                # Des: unforced assignment
                result = rf_utils.set_boot_override(boot_opts)

                # Des: unforced assignment
            elif command == "CreateLogicalDrive":
                result = rf_utils.create_logical_driver(raid_detail)
            elif command == "DeleteLogicalDrive":
                result = rf_utils.delete_logical_driver(logical_detail)
            elif command == "ModifyLogicalDrive":
                result = rf_utils.modify_logical_driver(logical_detail)

    elif category == "Chassis":
        result = rf_utils._find_chassis_resource()
        if result['ret'] is False:
            module.fail_json(msg=to_native(result['msg']))

        led_commands = ["IndicatorLedOn"]

        # Check if more than one led_command is present
        num_led_commands = sum(
            [command in led_commands for command in command_list])
        if num_led_commands > 1:
            result = {
                'ret': False,
                'msg': "Only one IndicatorLed command should be sent at a time."
            }
        else:
            for command in command_list:
                if command in led_commands:
                    result = rf_utils.manage_chassis_indicator_led(command)

    elif category == "Sessions":
        # execute only if we find SessionService resources
        resource = rf_utils._find_sessionservice_resource()
        if resource['ret'] is False:
            module.fail_json(msg=resource['msg'])

        for command in command_list:
            if command == "ClearSessions":
                result = rf_utils.clear_sessions()
            elif command == "CreateSession":
                result = rf_utils.create_session()
            elif command == "DeleteSession":
                result = rf_utils.delete_session(module.params['session_uri'])

    elif category == "Manager":
        # execute only if we find a Manager service resource
        result = rf_utils._find_managers_resource()
        if result['ret'] is False:
            module.fail_json(msg=to_native(result['msg']))

        for command in command_list:
            if command == 'SetNTPServers' or command == "SetTimeZone":
                result = rf_utils.set_ntp_server(mgr_attributes)
            elif command.startswith("SetIPv4"):
                result = rf_utils.set_ipv4(ipv4_info)
            elif command.startswith("SetIPv6"):
                result = rf_utils.set_ipv6(ipv6_info)

    # Return data back or fail with proper message
    if result['ret'] is True:
        del result['ret']
        changed = result.get('changed', True)
        session = result.get('session', dict())
        module.exit_json(changed=changed, session=session,
                         msg='Action was successful')
    else:
        module.fail_json(msg=to_native(result['msg']))


if __name__ == '__main__':
    main()
