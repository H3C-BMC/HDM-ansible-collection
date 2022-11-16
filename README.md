# Ansible Collection - h3c.hdm

# Introduction

Ansible playbooks and roles for H3C server HDM using Redfish APIs.

This repository can be integrated into complex playbooks for you own needs and the examples suggest how to create your own playbooks. 

# Prerequisites
*	HDM-3.16 or later. Some commands might require specific HDM versions using redfish api. For more information, see the HDM redfish documents.
*	ansible >= 2.9
*	python 3 up to version 3.10

# Use the command tool
To use the command tool:
*  Local operating system configuration python 3 environment.
  *Copy the tool project file to the operating system. 
  *Enter the corresponding command and then press Enter to execute the command.

   `python main.py -H host -p port -U username -P password <command>`


Copyright and License
---------------------

Copyright 2022 New H3C Technologies Co., Ltd.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
