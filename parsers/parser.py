import time, sys
from datetime import datetime, timezone, timedelta
from parsers.managers.manager import EventManagerInterface

PARSE_TIMEZONE = timezone(timedelta(hours=+9), 'JST')

"""
@Parser Object
GeneralParser is General purpose analysing Class
Instance of This class is analyser object each data type 
"""


class PlasoLogParser(object):

    def __init__(self, event):
        """Plaso json_line log Parser Object

        Attributes:
            event: Dictionary object generated Plaso json_line log
            data_type: Event of Plaso event data type @https://github.com/log2timeline/plaso/blob/master/plaso/parsers
            parser: Plaso parser type analysed self event
            timestamp: Event occurrence time
            PlasoEvent　Plaso event management object
        """

        self.event = event
        self.timestamp = self.event["timestamp"]
        self.PlasoEventObject = None

    def EventAnalysis(self, **AnalysisOption):
        self.PlasoEventObject = EventManagerInterface.GetEventObject(self.event["data_type"])
        self.PlasoEventObject.SetEventAttribute(self.event)
