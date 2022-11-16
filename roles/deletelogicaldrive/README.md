Role Name
=========
Delete logical drive

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - storage_id: "0"
    - logical_id: "2"

  roles:
    - deletelogicaldrive
	
License
-------

BSD

Author Information
------------------

- H3C-BMC

