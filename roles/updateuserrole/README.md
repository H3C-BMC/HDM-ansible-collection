updateuserrole
=========
update user role

Example Playbook
----------------

- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
   - account_username: test_mod
   - roleid: Administrator
  roles:
    - updateuserrole

License
-------

BSD

Author Information
------------------

- H3C-BMC

