Role Name
=========
Set ipv4 static

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - net_id: eth1 
    - new_addr: 172.16.3.49  
    - new_sub: 255.255.255.0
    - new_gateway: 0.0.0.0

  roles:
    - setipv4static

License
-------

BSD

Author Information
------------------

- H3C-BMC

