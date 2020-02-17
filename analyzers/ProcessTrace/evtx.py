import xml.etree.ElementTree as Et
from parsers.logs.windows import win_eventlog
import re


class EvtxProcessLife(object):
    Attribute = frozenset(['application_execution'])

    EVENT_IDENTIFIER = {
        'execution': 4688,
        'termination': 4689
    }

    PATH = 'Security.evtx'

    SOURCE = 'Microsoft-Windows-Security-Auditing'

    _SEARCH_KEYWORD = {
        'NewProcessName': 'path',
        'ParentProcessName': 'ppath',
        'ProcessId': 'ppid',
        'NewProcessId': 'pid',
        'SubjectUserSid': 'sid'
    }

    def __init__(self):
        self.path = None
        self.ppath = None
        self.ppid = None
        self.pid = None
        self.sid = None
        self.life_range = None
        self.PlasoObject = None

    def ExtractExecution(self, evtx, process_name, *execution_mediator, **kwargs):
        # TODO 大文字小文字の区別をつけない検索方法
        # TODO プロセス名比較を無視する条件(kwargs)

        """"""
        if 'windows:evtx:record' != evtx.data_type or self.EVENT_IDENTIFIER['execution'] != evtx.event_identifier:
            return False

        if self.SOURCE == evtx.source_name and self.EVENT_IDENTIFIER['execution'] == evtx.event_identifier:
            self.path = []
            self.ppath = []
            self.ppid = []
            self.pid = []
            self.sid = []

            self.XmlParse(evtx.xml_string)
            """
            pname (str): process name in self
            mediator (str): parent process name in self
            """
            pname = re.findall(r'(\w+.exe)$', self.path)[0]

            # ここに解析条件を

            if execution_mediator:
                mediator = re.findall(r'(\w+.exe)$', self.ppath)[0]
                med = []
                for _med in execution_mediator:
                    if _med.find('.exe') == -1:
                        _med += '.exe'
                    med.append(_med)
                if mediator not in med:
                    return False

            if kwargs:
                user_sid = kwargs['user_sid']
                if not user_sid == self.sid:
                    return False

            if process_name.find('.exe') == -1:
                process_name += '.exe'

            if pname != process_name:
                return False

            self.life_range = []
            self.life_range.append(evtx.timestamp)
            return True

    def ExtractTermination(self, evtx, process_name, pid, **kwargs):
        # TODO 大文字小文字の区別をつけない検索方法
        # TODO プロセス名比較を無視する条件(kwargs)

        """"""
        if 'windows:evtx:record' != evtx.data_type or self.EVENT_IDENTIFIER['termination'] != evtx.event_identifier:
            return False

        if self.SOURCE == evtx.source_name and self.EVENT_IDENTIFIER == evtx.event_identifier:
            self.XmlParse(evtx.xml_string)
            """
            pname (str): process name in self
            mediator (str): parent process name in self
            """
            pname = re.findall(r'(\w+.exe)$', self.path)[0]

            if kwargs:
                user_sid = kwargs['user_sid']
                if not user_sid == self.sid:
                    return False

            if process_name.find('.exe') == -1:
                process_name += '.exe'

            if pname != process_name:
                return False

            self.life_range = []
            self.life_range.append(evtx.timestamp)
            return True

    def XmlParse(self, xml):
        """

        :param xml (str): string xml event log([windows event log name].evtx)
        :return:
        """
        root_attr = Et.fromstring(xml)
        xmln = re.findall(r'\{\S+\}', root_attr.tag)[0]
        system = root_attr[0]
        event_data = root_attr[1]

        for event in event_data.iter(xmln + 'Data'):
            for xml_key in self._SEARCH_KEYWORD:
                if event.attrib['Name'] == xml_key:
                    setattr(self, self._SEARCH_KEYWORD[xml_key], event.text)
