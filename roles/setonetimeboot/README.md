Role Name
=========
Set onetime boot

Example Playbook
----------------
- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - bootdevice: Pxe
  roles:
    - setonetimeboot

License
-------

BSD

Author Information
------------------

- H3C-BMC

