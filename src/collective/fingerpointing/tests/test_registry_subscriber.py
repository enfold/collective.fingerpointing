# -*- coding: utf-8 -*-
from collective.fingerpointing.interfaces import IFingerPointingSettings
from collective.fingerpointing.testing import INTEGRATION_TESTING
from logging import INFO
from plone import api
from testfixtures import LogCapture

import unittest


class RegistrySubscribersTestCase(unittest.TestCase):

    """Tests for plone.app.registry subscribers."""

    layer = INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']

    def test_record_modified(self):
        with LogCapture(level=INFO) as log:
            record = IFingerPointingSettings.__identifier__ + '.audit_pas'
            api.portal.set_registry_record(record, False)
            log.check(
                ('collective.fingerpointing', 'INFO', 'user=test ip=127.0.0.1 action=record modified object=<Record collective.fingerpointing.interfaces.IFingerPointingSettings.audit_pas> value=False'),
            )
