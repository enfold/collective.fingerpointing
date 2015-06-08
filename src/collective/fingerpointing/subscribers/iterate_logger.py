# -*- coding: utf-8 -*-
from collective.fingerpointing.config import AUDIT_MESSAGE
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.logger import logger
from collective.fingerpointing.utils import get_request_information
from plone import api
from plone.app.iterate.interfaces import ICancelCheckoutEvent
from plone.app.iterate.interfaces import ICheckinEvent
from plone.app.iterate.interfaces import ICheckoutEvent


def iterate_logger(event):
    """Log events like content editing checkouts and checkins, if
    plone.app.iterate is installed.
    """
    record = IFingerPointingSettings.__identifier__ + '.audit_iterate'
    if api.portal.get_registry_record(record):
        user, ip = get_request_information()

        if ICheckoutEvent.providedBy(event):
            action = 'object checked out'
            extras = 'object={0} working_copy={1}'.format(
                event.object, event.working_copy)
        if ICheckinEvent.providedBy(event):
            action = 'working copy checked in'
            extras = 'object={0} baseline={1}'.format(
                event.object, event.baseline)
        if ICancelCheckoutEvent.providedBy(event):
            action = 'working copy cancelled'
            extras = 'object={0} baseline={1}'.format(
                event.object, event.baseline)

        logger.info(AUDIT_MESSAGE.format(user, ip, action, extras))
