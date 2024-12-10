adduser_G6_G7
=========
add hdm accout

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
	- adduser_G6_G7

License
-------

BSD

Author Information
------------------

- H3C-BMC

