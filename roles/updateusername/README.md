Role Name
=========
Update user name

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - account_username: test12
    - account_updatename: test_mod
  roles:
    - updateusername

License
-------

BSD

Author Information
------------------

- H3C-BMC

