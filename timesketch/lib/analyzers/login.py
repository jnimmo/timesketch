"""Sketch analyzer plugin for login and logoff events."""
from __future__ import unicode_literals

import logging

import six

from timesketch.lib import emojis
from timesketch.lib.analyzers import interface
from timesketch.lib.analyzers import manager


logger = logging.getLogger("timesketch.analyzers.login")
LOGON_TYPES = {
    "0": "Unknown",
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def parse_evtx_logoff_event(string_list):
    """Parse logoff events and return a dict with attributes.

    Args:
        string_list: a list of strings extracted from the Event Log.

    Returns:
        Dict with attributes parsed out of the logoff events.
    """
    if not len(string_list) == 5:
        return {}

    attributes = {}
    attributes["username"] = string_list[1]
    attributes["logon_domain"] = string_list[2]
    attributes["session_id"] = string_list[3]

    logon_type_code = string_list[4]
    attributes["logon_type"] = LOGON_TYPES.get(logon_type_code, LOGON_TYPES.get("0"))

    return attributes

def parse_ntlm_logon_event(string_list, string_parsed):
    if len(string_list) < 4:
        return {}

    if not string_parsed:
        string_parsed = {}
        
    attributes = {}
    attributes["logon_type"] = "NTLM"
    attributes["username"] = string_parsed.get("target_user_name", string_list[1])
    attributes["workstation"] = string_parsed.get("workstation", string_list[2])
    attributes["status"] = string_parsed.get("status", string_list[3])
    return attributes
        
        
def parse_evtx_logon_event(string_list, string_parsed):
    """Parse logon events and return a count of event processed.

    Args:
        string_list: a list of strings extracted from the Event Log.
        string_parsed: a dict with strings extracted from the Event log.

    Returns:
        Dict with attributes parsed out of the logon events.
    """
    if len(string_list) < 20:
        return {}

    if not string_parsed:
        string_parsed = {}
        string_parsed["target_user_id"] = string_list[4]
        string_parsed["target_user_name"] = string_list[5]
        string_parsed["hostname"] = string_list[11]
        string_parsed["source_user_name"] = string_list[1]

    attributes = {}
    logon_type_code = string_list[8]
    attributes["logon_type"] = LOGON_TYPES.get(logon_type_code, LOGON_TYPES.get("0"))

    win_domain = string_list[2]
    if win_domain:
        attributes["windows_domain"] = win_domain

    username = string_parsed.get("target_user_name")
    if username:
        attributes["username"] = username

    user_id = string_parsed.get("target_user_id")
    if user_id:
        attributes["user_id"] = user_id

    logon_process_name = string_list[9]
    if logon_process_name:
        attributes["logon_process"] = logon_process_name

    workstation_name = string_list[11]
    if workstation_name == "-":
        attributes["workstation"] = "localhost"
    elif workstation_name:
        attributes["workstation"] = workstation_name

    ip_address = string_list[18]
    if ip_address and ip_address != "-":
        attributes["source_address"] = ip_address

    hostname = string_parsed.get("target_machine_name", "N/A")
    if hostname:
        attributes["hostname"] = hostname

    session_id = string_list[3]
    if session_id:
        attributes["session_id"] = session_id

    source_username = string_parsed.get("source_user_name")
    if source_username:
        attributes["source_username"] = source_username

    return attributes

def parse_rdp_logon_event(string_list, string_parsed, event_id):
    if len(string_list) < 3:
        return {}
    if not string_parsed:
        string_parsed = {}
       
    attributes = {}
    attributes["logon_type"] = LOGON_TYPES.get("RDP")
    if event_id == 1149:
        attributes["username"] = string_list[0]
        attributes["windows_domain"] = string_list[1]
        attributes["source_address"] = string_list[2]
    elif event_id == 21 and string_list[2] != "LOCAL":
        attributes["source_address"] = string_parsed.get("address", string_list[2])
        attributes["username"] = string_parsed.get("user", string_list[0])
        attributes["session_id"] = string_parsed.get("session_id", string_list[1])
        username = string_list[0].split("\\")
        if len(username) > 1:
            attributes["username"] = username[-1]
            attributes["windows_domain"] = username[0]
    return attributes


class LoginSketchPlugin(interface.BaseAnalyzer):
    """Analyzer for Login and Logoff related activity."""

    NAME = "login"
    DISPLAY_NAME = "Windows logon/logoff events"
    DESCRIPTION = "Mark Windows logon and logoff events"

    DEPENDENCIES = frozenset()

    def run(self):
        """Entry point for the analyzer.

        Returns:
            String with summary of the analyzer result
        """
        login_emoji = emojis.get_emoji("unlock")
        logoff_emoji = emojis.get_emoji("lock")
        screen_emoji = emojis.get_emoji("screen")
        screensaver_logon = LOGON_TYPES.get("7")
        login_counter = 0
        rdp_login_counter = 0
        logoff_counter = 0

        # TODO: Add EVT lookups, ID 528 for logon and 538, 540 for logoff.
        # TODO: Add RDP EVT lookups, ID 682 for logon and 683 for logoff.
        query = (
            'data_type:"windows:evtx:record" AND '
            '(event_identifier:(4624 OR 4634 OR 4647 OR 4776 OR 4778 OR 4779) OR '
            "(source_name:TerminalServices AND event_identifier:(21 OR 1149)"
        )

        return_fields = [
            "message",
            "data_type",
            "strings",
            "strings_parsed",
            "event_identifier",
        ]

        # Generator of events based on your query.
        events = self.event_stream(query_string=query, return_fields=return_fields)

        for event in events:
            strings = event.source.get("strings")
            strings_parsed = event.source.get("strings_parsed")
            identifier = event.source.get("event_identifier")
            emojis_to_add = []
            tags_to_add = []
            attribute_dict = {}

            if isinstance(identifier, six.text_type):
                try:
                    identifier = int(identifier, 10)
                except ValueError:
                    logger.warning(
                        (
                            "Unable to convert EVTX identifier to an integer, "
                            "value is {0:s}"
                        ).format(identifier)
                    )
                    continue

            if identifier in (4624, 4776):
                if identifier == 4776:
                    attribute_dict = parse_ntlm_logon_event(strings, strings_parsed)
                else: 
                    attribute_dict = parse_evtx_logon_event(strings, strings_parsed)
                if not attribute_dict:
                    continue
                emojis_to_add.append(login_emoji)
                tags_to_add.append("logon-event")
                login_counter += 1
            
            elif identifier in (21, 1149):
                attribute_dict = parse_rdp_logon_event(strings, strings_parsed, identifier)
                if not attribute_dict:
                    continue
                emojis_to_add.append(login_emoji)
                tags_to_add.append("logon-event")
                tags_to_add.append("rdp")
                rdp_login_counter += 1

            elif identifier in (4634, 4647):
                attribute_dict = parse_evtx_logoff_event(strings)
                if not attribute_dict:
                    continue
                emojis_to_add.append(logoff_emoji)
                tags_to_add.append("logoff-event")
                logoff_counter += 1

            # TODO: Add support for RDP events, ID 4778 (logon) and 4779
            # (logoff).
            if not attribute_dict:
                continue
            event.add_attributes(attribute_dict)

            # Want to add an emoji in case this is a screensaver unlock.
            if attribute_dict.get("logon_type", "") == screensaver_logon:
                emojis_to_add.append(screen_emoji)

            event.add_emojis(emojis_to_add)
            event.add_tags(tags_to_add)

            # Commit the event to the datastore.
            event.commit()

        # TODO: Add support for Linux syslog logon/logoff events.
        # TODO: Add support for Mac OS X logon/logoff events.

        return (f"Logon events: {login_counter}, logoff events: {logoff_counter}, RDP logons: {rdp_login_counter}")


manager.AnalysisManager.register_analyzer(LoginSketchPlugin)
