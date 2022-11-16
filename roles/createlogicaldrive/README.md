Role Name
=========
Create logical dirve

Example Playbook
----------------

- hosts: hdmhosts
  connection: local
  gather_facts: False
  vars:
    - storage_id: 0
    - raid: {
        "Name": "test1",
        "InitState": "No",
        "StripSize": "64KB",
        "Level": "RAID 0",
        "SpanNum": 1,
        "NumDrives": 1,
        "ReadPolicy": "Read Ahead",
        "WritePolicy": "Write Through",
        "IOPolicy": "Direct",
        "DriveCache": "Disable",
        "AccessPolicy": "Blocked",
        "Size": 199,
        "SizeUnit": "GB",
        "PhysicalDiskList":[
            {
                "group_id": 0,
                "id": 11         # physical disk connection id
            }
        ]
    }

  roles:
    - createlogicaldrive

License
-------

BSD

Author Information
------------------

- H3C-BMC

