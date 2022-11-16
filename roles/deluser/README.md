Role Name
=========
Delete hdm user

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - loginname: test
    - timeout: 30 
  roles:
    - deluser

License
-------

BSD

Author Information
------------------

- H3C-BMC

