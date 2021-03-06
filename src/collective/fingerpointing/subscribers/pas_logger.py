# -*- coding: utf-8 -*-
from collective.fingerpointing.config import AUDIT_MESSAGE
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.logger import log_info
from collective.fingerpointing.utils import get_request_information
from plone import api
from Products.PluggableAuthService.interfaces.events import IGroupDeletedEvent
from Products.PluggableAuthService.interfaces.events import IPrincipalCreatedEvent  # noqa: E501
from Products.PluggableAuthService.interfaces.events import IPrincipalDeletedEvent  # noqa: E501
from Products.PluggableAuthService.interfaces.events import IUserLoggedInEvent
from Products.PluggableAuthService.interfaces.events import IUserLoggedOutEvent
from zope.component.interfaces import ComponentLookupError


def pas_logger(event):
    """Log authentication events like users logging in and loggin out."""
    name = IFingerPointingSettings.__identifier__ + '.audit_pas'
    try:
        audit_pas = api.portal.get_registry_record(name, default=False)
    except ComponentLookupError:  # plonectl adduser
        return

    if not audit_pas:
        return

    user, ip = get_request_information()

    if IUserLoggedInEvent.providedBy(event):
        action = 'login'
        extra_info = {}
    elif IUserLoggedOutEvent.providedBy(event):
        action = 'logout'
        extra_info = {}
    elif IPrincipalCreatedEvent.providedBy(event):
        action = 'create'
        extra_info = {'principal': str(event.principal)}
    elif IPrincipalDeletedEvent.providedBy(event):
        action = 'remove'
        extra_info = {'user': str(event.principal)}
    elif IGroupDeletedEvent.providedBy(event):
        action = 'remove'
        extra_info = {'group': str(event.principal)}
    else:  # should never happen
        action = 'UNKNOWN'
        extra_info = {}

    extras = log_info.format_extras('pas',
                                    event,
                                    action,
                                    extra_info)
    log_info(AUDIT_MESSAGE.format(user, ip, action, extras))
