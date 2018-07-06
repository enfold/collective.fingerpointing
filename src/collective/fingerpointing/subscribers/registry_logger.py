# -*- coding: utf-8 -*-
from collective.fingerpointing.config import AUDIT_MESSAGE
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.logger import log_info
from collective.fingerpointing.utils import get_request_information
from plone import api
from plone.registry.interfaces import IRecordModifiedEvent

import six


def safe_utf8(s):
    if isinstance(s, six.text_type):
        s = s.encode('utf-8')
    return s


def registry_logger(event):
    """Log registry events like records being modified."""
    name = IFingerPointingSettings.__identifier__ + '.audit_registry'
    audit_registry = api.portal.get_registry_record(name, default=False)
    if not audit_registry:
        return

    user, ip = get_request_information()

    if IRecordModifiedEvent.providedBy(event):
        action = 'modify'
        extra_info = {'object': event.record,
                      'value': safe_utf8(event.record.value)}
    else:  # should never happen
        action = '-'
        extra_info = {'object': event.record}

    extras = log_info.format_extras('registry',
                                    event,
                                    action,
                                    extra_info)
    log_info(AUDIT_MESSAGE.format(user, ip, action, extras))
