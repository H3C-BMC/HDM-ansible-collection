Role Name
=========
Set ntp server

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - attribute_name: TertiaryNtpServer 
    - attribute_value: 192.168.11.22
  roles:
    - setntpservers

License
-------

BSD

Author Information
------------------

- H3C-BMC

