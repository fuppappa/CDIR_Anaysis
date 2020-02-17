# -*- coding: utf-8 -*-
"""This file contains a MRUList Registry plugin.

Also see:
  https://github.com/libyal/winreg-kb/wiki/MRU-keys
"""

from parsers.logs import general


class MRUListEventData(general.PlasoGeneralEvent):
    """MRUList event data attribute container.

    Attributes:
      entries (str): most recently used (MRU) entries.
      key_path (str): Windows Registry key path.
    """

    DATA_TYPE = 'windows:registry:mrulist'

    def __init__(self):
        """Initializes event data."""
        super(MRUListEventData, self).__init__(data_type=self.DATA_TYPE)
        self.entries = None
        self.key_path = None

    def SetEventAttribute(self, event):
        self.entries = event['entries']
        self.key_path = event['key_path']

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)
