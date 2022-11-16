updateuserpass
=========
Update hdm user password

Example Playbook
----------------

- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
   - account_username: test_mod
   - new_pass: Password@_
  roles:
    - updateuserpass

License
-------

BSD

Author Information
------------------

- H3C-BMC

