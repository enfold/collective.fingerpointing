# -*- coding: utf-8 -*-
"""Event subscriber handler for IActionSucceededEvent."""
from collective.fingerpointing.config import AUDIT_MESSAGE
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.logger import log_info
from collective.fingerpointing.utils import get_request_information
from plone import api


def workflow_logger(event):
    """Log workflow transitions."""
    name = IFingerPointingSettings.__identifier__ + '.audit_workflow'
    audit_workflow = api.portal.get_registry_record(name, default=False)
    if not audit_workflow:
        return

    user, ip = get_request_information()

    action = 'workflow transition'
    extra_info = {'object': event.object,
                  'transition': event.action}

    extras = log_info.format_extras('registry',
                                    event,
                                    action,
                                    extra_info)
    log_info(AUDIT_MESSAGE.format(user, ip, action, extras))
