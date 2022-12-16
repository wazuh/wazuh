import sys
from os import path
from aws_bucket import AWSBucket, AWSCustomBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import tools


class AWSGuardDutyBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'guardduty'
        AWSCustomBucket.__init__(self, **kwargs)

    def send_event(self, event):
        # Send the message (split if it is necessary)
        for msg in self.reformat_msg(event):
            self.send_msg(msg)

    def reformat_msg(self, event):
        tools.debug('++ Reformat message', 3)
        if event['aws']['source'] == 'guardduty' and 'service' in event['aws'] and \
                'action' in event['aws']['service'] and \
                'portProbeAction' in event['aws']['service']['action'] and \
                'portProbeDetails' in event['aws']['service']['action']['portProbeAction'] and \
                len(event['aws']['service']['action']['portProbeAction']['portProbeDetails']) > 1:

            port_probe_details = event['aws']['service']['action']['portProbeAction']['portProbeDetails']
            for detail in port_probe_details:
                event['aws']['service']['action']['portProbeAction']['portProbeDetails'] = detail
                yield event
        else:
            AWSBucket.reformat_msg(self, event)
            yield event

