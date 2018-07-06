# -*- coding: utf-8 -*-
from collective.fingerpointing.config import AUDIT_MESSAGE
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.logger import log_info
from collective.fingerpointing.utils import get_request_information
from plone import api
from plone.app.iterate.interfaces import ICancelCheckoutEvent
from plone.app.iterate.interfaces import ICheckinEvent
from plone.app.iterate.interfaces import ICheckoutEvent


def iterate_logger(event):
    """Log events like content editing checkouts and checkins, if
    plone.app.iterate is installed.
    """
    name = IFingerPointingSettings.__identifier__ + '.audit_iterate'
    audit_iterate = api.portal.get_registry_record(name, default=False)
    if not audit_iterate:
        return

    user, ip = get_request_information()

    if ICheckoutEvent.providedBy(event):
        action = 'checkout'
        extra_info = {'object': event.object,
                      'working_copy': event.working_copy}
    elif ICheckinEvent.providedBy(event):
        action = 'checkin'
        extra_info = {'object': event.object,
                      'baseline': event.baseline}
    elif ICancelCheckoutEvent.providedBy(event):
        action = 'cancel checkout'
        extra_info = {'object': event.object,
                      'baseline': event.baseline}
    else:  # should never happen
        action = '-'
        extra_info = {'object': event.object}

    extras = log_info.format_extras('iterate',
                                    event,
                                    action,
                                    extra_info)
    log_info(AUDIT_MESSAGE.format(user, ip, action, extras))
