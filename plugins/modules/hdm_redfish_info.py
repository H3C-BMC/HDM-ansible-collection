#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) H3C.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


RETURN = '''
result:
    description: different results depending on task
    returned: always
    type: dict
    sample: List of CPUs on system
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.h3c_bmc.hdm.plugins.module_utils.hdm_redfish_utils import HDMRedfishUtils

CATEGORY_COMMANDS_ALL = {
    "Systems": ["GetSystemInventory", "GetPsuInventory", "GetCpuInventory",
                "GetMemoryInventory", "GetHealthReport",
                "GetBiosAttributes", "GetBootOverride",
                "GetLogicalDriveInventory", "GetRaidStorageInventory"],
    "Chassis": ["GetFanInventory", "GetPsuInventory", "GetNicInventory",
                "GetPhysicalDriveInventory"],
    "Accounts": ["ListUsers"],
    "Sessions": ["GetSessions"],
    "Update": ["GetFirmwareInventory"]
}


CATEGORY_COMMANDS_DEFAULT = {
    "Systems": "GetSystemInventory",
    "Chassis": "GetFanInventory",
    "Accounts": "ListUsers",
    "Update": "GetFirmwareInventory",
    "Sessions": "GetSessions",
    "Manager": "GetManagerNicInventory"
}


def main():
    result = {}
    category_list = []
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(type='list', elements='str', default=['Systems']),
            command=dict(type='list', elements='str'),
            baseuri=dict(required=True),
            username=dict(),
            password=dict(no_log=True),
            auth_token=dict(no_log=True),
            timeout=dict(type='int', default=60)
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
        supports_check_mode=True,
    )

    # admin credentials used for authentication
    creds = {'user': module.params['username'],
             'pswd': module.params['password'],
             'token': module.params['auth_token']}

    # timeout
    timeout = module.params['timeout']

    # Build root URI
    root_uri = "https://" + module.params['baseuri']
    rf_utils = HDMRedfishUtils(creds, root_uri, timeout, module)

    # Build Category list
    if "all" in module.params['category']:
        for entry in CATEGORY_COMMANDS_ALL:
            category_list.append(entry)
    else:
        # one or more categories specified
        category_list = module.params['category']

    for category in category_list:
        command_list = []
        # Build Command list for each Category
        if category in CATEGORY_COMMANDS_ALL:
            if not module.params['command']:
                # True if we don't specify a command --> use default
                command_list.append(CATEGORY_COMMANDS_DEFAULT[category])
            elif "all" in module.params['command']:
                for entry in range(len(CATEGORY_COMMANDS_ALL[category])):
                    command_list.append(CATEGORY_COMMANDS_ALL[category][entry])
            # one or more commands
            else:
                command_list = module.params['command']
                # Verify that all commands are valid
                for cmd in command_list:
                    # Fail if even one command given is invalid
                    if cmd not in CATEGORY_COMMANDS_ALL[category]:
                        module.fail_json(msg="Invalid Command: %s" % cmd)
        else:
            # Fail if even one category given is invalid
            module.fail_json(msg="Invalid Category: %s" % category)

        # Organize by Categories / Commands
        if category == "Systems":
            # execute only if we find a Systems resource
            resource = rf_utils._find_systems_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetSystemInventory":
                    result["system"] = rf_utils.get_multi_system_inventory()
                elif command == "GetCpuInventory":
                    result["cpu"] = rf_utils.get_multi_cpu_inventory()
                elif command == "GetMemoryInventory":
                    result["memory"] = rf_utils.get_multi_memory_inventory()
                elif command == "GetBiosAttributes":
                    result["bios_attribute"] = \
                        rf_utils.get_multi_bios_attributes()
                elif command == "GetLogicalDriveInventory":
                    result["logicals"] = rf_utils.get_logical_drive_inventory()
                elif command == "GetRaidStorageInventory":
                    result["raids"] = rf_utils.get_raid_storage_inventory()

        elif category == "Chassis":
            # execute only if we find Chassis resource
            resource = rf_utils._find_chassis_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetFanInventory":
                    result["fan"] = rf_utils.get_fan_inventory()
                elif command == "GetPsuInventory":
                    result["psu"] = rf_utils.get_psu_inventory()
                elif command == "GetChassisThermals":
                    result["thermals"] = rf_utils.get_chassis_thermals()
                elif command == "GetChassisPower":
                    result["chassis_power"] = rf_utils.get_chassis_power()
                elif command == "GetChassisInventory":
                    result["chassis"] = rf_utils.get_chassis_inventory()
                elif command == "GetHealthReport":
                    result["health_report"] = \
                        rf_utils.get_multi_chassis_health_report()
                elif command == "GetNicInventory":
                    result["nic"] = rf_utils.get_multi_nic_inventory(category)
                elif command == "GetPhysicalDriveInventory":
                    result["physicals"] = \
                        rf_utils.get_physical_drive_inventory()

        elif category == "Accounts":
            # execute only if we find an Account service resource
            resource = rf_utils._find_accountservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "ListUsers":
                    result["user"] = rf_utils.list_users()

        elif category == "Update":
            # execute only if we find UpdateService resources
            resource = rf_utils._find_updateservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetFirmwareInventory":
                    result["firmware"] = rf_utils.get_firmware_inventory()

        elif category == "Sessions":
            # execute only if we find SessionService resources
            resource = rf_utils._find_sessionservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetSessions":
                    result["session"] = rf_utils.get_sessions()

    # Return data back
    module.exit_json(redfish_facts=result)


if __name__ == '__main__':
    main()
