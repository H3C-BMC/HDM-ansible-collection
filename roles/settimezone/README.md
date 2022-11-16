Role Name
=========
Set timezone

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - attribute_value: UTC+8
  roles:
    - settimezone

License
-------

BSD

Author Information
------------------

- H3C-BMC

