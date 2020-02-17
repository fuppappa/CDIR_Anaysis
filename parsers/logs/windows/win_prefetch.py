from parsers.logs import general


class WinPrefetchExecutionEventData(general.PlasoGeneralEvent):
    """Windows Prefetch event data.
    Attributes:
      executable (str): executable filename.
      format_version (int): format version.
      mapped_files (list[str]): mapped filenames.
      number_of_volumes (int): number of volumes.
      path (str): path to the executable.
      prefetch_hash (int): prefetch hash.
      run_count (int): run count.
      volume_device_paths (list[str]): volume device paths.
      volume_serial_numbers (list[int]): volume serial numbers.
    """

    DATA_TYPE = 'windows:prefetch:execution'

    def __init__(self):
        """Initializes event data."""
        super(WinPrefetchExecutionEventData, self).__init__(
            data_type=self.DATA_TYPE)
        self.executable = None
        self.mapped_files = None
        self.number_of_volumes = None
        self.path = None
        self.prefetch_hash = None
        self.run_count = None
        self.version = None
        self.volume_device_paths = None
        self.volume_serial_numbers = None

    def SetAttribute(self, event):
        self.executable = event["executable"]
        self.mapped_files = event["mapped_files"]
        self.number_of_volumes = event["number_of_volumes"]
        self.path = event["path"]
        self.prefetch_hash = event["prefetch_hash"]
        self.run_count = event["run_count"]
        self.version = event["version"]
        self.volume_device_paths = event["volume_device_paths"]
        self.volume_serial_numbers = event["volume_serial_numbers"]

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__ne__(other)
