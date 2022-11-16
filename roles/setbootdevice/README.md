Role Name
=========
Set boot device

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - bootdevice: Hdd
  roles:
    - setbootdevice
License
-------

BSD

Author Information
------------------

- H3C-BMC

