Role Name
=========
Modify logical drive

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - storage_id: "0"
    - logical_id: "0"
    - write_policy: "Write Through"
    - read_policy: "Read Ahead"

  roles:
    - modifylogicaldrive

License
-------

BSD

Author Information
------------------

- H3C-BMC

