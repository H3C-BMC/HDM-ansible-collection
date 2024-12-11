adduserg6g7
=========

add hdm accout for g6 g7

Example Playbook
----------------

- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
  
  - new_pass: Password@_ 
  - new_user: test12  
  - role_id: Operator
  - timeout: 30
  
  roles:
  
  - adduserg6g7

License
-------

BSD

Author Information
------------------

- H3C-BMC
