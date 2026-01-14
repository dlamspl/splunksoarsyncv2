#!/usr/bin/python 


import json
import sys
sys.path.insert(1, '/opt/phantom/apps/splunksoarsync_8086a301-7019-4387-94bc-fb0a2221b6cd/dependencies')

try:
    
    import soarsync_connector
    from phantom.base_connector import BaseConnector
except Exception as e:
    raise Exception('Could not resolve name of connector object in the app: {error}'.format(error=str(e)))

with open('/tmp/8086a301-7019-4387-94bc-fb0a2221b6cd_2025_09_22_18_45_52.json', 'r') as f:
	in_json_serialized = f.read()

user_session_token = sys.argv[1]

in_json = json.loads(in_json_serialized)
in_json["user_session_token"] = user_session_token
Connector = BaseConnector.__subclasses__()[0]

connector = Connector()
connector.print_progress_message = True

ret_val = connector._handle_action(json.dumps(in_json), None)

print(ret_val)

if json.loads(ret_val).get("status","failed") != "success":
    raise Exception("Action Failed")
