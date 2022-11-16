Role Name
=========
Set ipv6 static

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - net_id: eth1 
    - new_addr: 2022::22  
    - new_gateway: 2022::1
    - prefix_length: 64

  roles:
    - setipv6static

License
-------

BSD

Author Information
------------------

- H3C-BMC

