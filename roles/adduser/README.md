Role Name
=========

adduser

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
        - adduser

License
-------

BSD

Author Information
------------------

- H3C-BMC

