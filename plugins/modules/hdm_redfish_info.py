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
    type: dict
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.h3c.hdm.plugins.module_utils.hdm_redfish_utils import HDMRedfishUtils

CATEGORY_COMMANDS_ALL = {
    "Systems": ["GetSystemInventory", "GetPsuInventory", "GetCpuInventory",
                "GetMemoryInventory", "GetHealthReport",
                "GetBiosAttributes", "GetBootOverride"],
    "Chassis": ["GetFanInventory", "GetPsuInventory", "GetNicInventory"],
    "Accounts": ["ListUsers"],
    "Sessions": ["GetSessions"],
    "Update": ["GetFirmwareInventory"],
    "Manager": ["GetManagerNicInventory"]
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

    creds = {'user': module.params['username'],
             'pswd': module.params['password'],
             'token': module.params['auth_token']}

    # timeout
    timeout = module.params['timeout']

    root_uri = "https://" + module.params['baseuri']
    rf_utils = HDMRedfishUtils(creds, root_uri, timeout, module)

    if "all" in module.params['category']:
        for entry in CATEGORY_COMMANDS_ALL:
            category_list.append(entry)
    else:
        category_list = module.params['category']

    for category in category_list:
        command_list = []
        if category in CATEGORY_COMMANDS_ALL:
            if not module.params['command']:
                command_list.append(CATEGORY_COMMANDS_DEFAULT[category])
            elif "all" in module.params['command']:
                for entry in range(len(CATEGORY_COMMANDS_ALL[category])):
                    command_list.append(CATEGORY_COMMANDS_ALL[category][entry])
            else:
                command_list = module.params['command']
                for cmd in command_list:
                    if cmd not in CATEGORY_COMMANDS_ALL[category]:
                        module.fail_json(msg="Invalid Command: %s" % cmd)
        else:
            module.fail_json(msg="Invalid Category: %s" % category)

        if category == "Systems":
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
                    result["bios_attribute"] = rf_utils.get_multi_bios_attributes()

        elif category == "Chassis":
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
                    result["health_report"] = rf_utils.get_multi_chassis_health_report()
                elif command == "GetNicInventory":
                    result["nic"] = rf_utils.get_multi_nic_inventory(category)

        elif category == "Accounts":
            resource = rf_utils._find_accountservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "ListUsers":
                    result["user"] = rf_utils.list_users()

        elif category == "Update":
            resource = rf_utils._find_updateservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetFirmwareInventory":
                    result["firmware"] = rf_utils.get_firmware_inventory()

        elif category == "Sessions":
            resource = rf_utils._find_sessionservice_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetSessions":
                    result["session"] = rf_utils.get_sessions()

        elif category == "Manager":
            resource = rf_utils._find_managers_resource()
            if resource['ret'] is False:
                module.fail_json(msg=resource['msg'])

            for command in command_list:
                if command == "GetManagerNicInventory":
                    result["manager_nics"] = rf_utils.get_multi_nic_inventory(category)
                elif command == "GetVirtualMedia":
                    result["virtual_media"] = rf_utils.get_multi_virtualmedia(category)
                elif command == "GetLogs":
                    result["log"] = rf_utils.get_logs()
                elif command == "GetNetworkProtocols":
                    result["network_protocols"] = rf_utils.get_network_protocols()
                elif command == "GetHealthReport":
                    result["health_report"] = rf_utils.get_multi_manager_health_report()
                elif command == "GetHostInterfaces":
                    result["host_interfaces"] = rf_utils.get_hostinterfaces()
                elif command == "GetManagerInventory":
                    result["manager"] = rf_utils.get_multi_manager_inventory()

    # Return data back
    module.exit_json(redfish_facts=result)


if __name__ == '__main__':
    main()
