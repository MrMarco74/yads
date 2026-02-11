from yads.core.license import license_manager
import json

key = "eyJzdWIiOiAiQWxleGFuZGVyIFN0ZWluYnJlY2hlciIsICJtYXhfdGFyZ2V0cyI6IDUsICJleHAiOiAxNzcxNTM5NDMyLCAiaWF0IjogMTc2ODk0NzQzMiwgImZlYXR1cmVzIjogWyJyZXBvcnRzIiwgImFwaSIsICJzY2hlZHVsZWRfc2NhbnMiLCAib3NpbnQiLCAid2ViaG9va3MiLCAidGVuYW50cyJdfQ.sGmBBH5o2KDzML3Yyhg881hZKaI5SGa7qapl_qKFg98EvX4iFkU2Djmv0QMju_vapme0WK9BLxyA4aKVFD5zDQ"

data = license_manager.verify(key)
if data:
    print("SUCCESS: License is valid!")
    print(json.dumps(data, indent=4))
else:
    print("FAILURE: License is invalid for this configuration.")
