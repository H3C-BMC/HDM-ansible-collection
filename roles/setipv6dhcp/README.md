Role Name
=========
Set ipv6 DHCP

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - net_id: eth1 

  roles:
    - setipv6dhcp


License
-------

BSD

Author Information
------------------

- H3C-BMC

