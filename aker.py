#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       Copyright 2016 ahmed@nazmy.io
#
# For license information see LICENSE.txt


# Meta
__version__ = '0.4.5'
__version_info__ = (0, 4, 5)
__license__ = "AGPLv3"
__license_info__ = {
    "AGPLv3": {
        "product": "aker",
        "users": 0,  # 0 being unlimited
        "customer": "Unsupported",
        "version": __version__,
        "license_format": "1.0",
    }
}

import getpass
import logging
import os
import signal
import sys
import uuid

import paramiko
from configparser import ConfigParser, NoOptionError

import tui
from hosts import Hosts
from session import SSHSession
from snoop import SSHSniffer


def signal_handler(signal, frame):
    logging.debug("Core: user tried an invalid signal {}".format(signal))


# Capture CTRL-C
signal.signal(signal.SIGINT, signal_handler)

config_file = "/etc/aker/aker.ini"
log_file = '/var/log/aker/aker.log'
session_log_dir = '/var/log/aker/'


class Configuration(object):
    def __init__(self, filename):
        remote_connection = os.environ.get('SSH_CLIENT', '0.0.0.0 0')
        self.src_ip = remote_connection.split()[0]
        self.src_port = remote_connection.split()[1]
        self.session_uuid = uuid.uuid1()
        # TODO: Check file existence, handle exception
        self.configparser = ConfigParser()
        if filename:
            self.configparser.read(filename)
            self.log_level = self.configparser.get('General', 'log_level')
            self.ssh_port = self.configparser.get('General', 'ssh_port')

    def get(self, *args):
        if len(args) == 3:
            try:
                return self.configparser.get(args[0], args[1])
            except NoOptionError:
                return args[2]
        if len(args) == 2:
            return self.configparser.get(args[0], args[1])
        else:
            return self.configparser.get('General', args[0])


class User(object):
    def __init__(self, username):
        self.name = username
        gateway_hostgroup = config.get('gateway_group')
        idp = config.get('idp')
        logging.debug("Core: using Identity Provider {0}".format(idp))
        self.hosts = Hosts(config, self.name, gateway_hostgroup, idp)
        self.allowed_ssh_hosts, self.hostgroups = self.hosts.list_allowed()

    def get_priv_key(self):
        agent = paramiko.Agent()
        keys = agent.get_keys()
        if keys:
            logging.info("SSHClient: Authenticating using Agent")
            return keys[0]
        try:
            privkey = paramiko.RSAKey.from_private_key_file(
                os.path.expanduser("~/.ssh/id_rsa"))
        except Exception as e:
            logging.error(
                "Core: Invalid Private Key for user {0} : {1} ".format(
                    self.name, e.message))
            raise Exception("Core: Invalid Private Key")
        else:
            return privkey

    def refresh_allowed_hosts(self, fromcache):
        logging.info(
            "Core: reloading hosts for user {0} from backened identity provider".format(
                self.name))
        self.allowed_ssh_hosts, self.hostgroups = self.hosts.list_allowed(
            from_cache=fromcache)


class Aker(object):
    """ Aker core module, this is the management module
    """

    def __init__(self):
        global config
        config = Configuration(config_file)
        self.config = config
        self.posix_user = getpass.getuser()
        self.log_level = config.log_level
        self.port = config.ssh_port
        self.tui = None

        # Setup logging first thing
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=log_file,
            level=config.log_level)
        logging.info(
            "Core: Starting up, user={0} from={1}:{2}".format(
                self.posix_user,
                config.src_ip,
                config.src_port))

        self.user = User(self.posix_user)

    def build_tui(self):
        logging.debug("Core: Drawing TUI")
        self.tui = tui.Window(self)
        self.tui.draw()
        self.tui.start()

    def init_connection(self, host):
        screen_size = self.tui.loop.screen.get_cols_rows()
        logging.debug("Core: pausing TUI")
        self.tui.pause()
        session_uuid = uuid.uuid4()
        session = SSHSession(self, host, session_uuid)
        sniffer = SSHSniffer(
            self.posix_user,
            config.src_port,
            host,
            session_uuid,
            screen_size)
        session.attach_sniffer(sniffer)
        logging.info(
            "Core: Starting session UUID {0} for user {1} to host {2}".format(
                session_uuid, self.posix_user, host))
        session.connect(screen_size)
        try:
            session.start_session()
        finally:
            session.stop_sniffer()
            self.tui.stop()
            self.tui.hostlist.search.clear()  # Clear selected hosts

    def session_end_callback(self, session):
        logging.info(
            "Core: Finished session UUID {0} for user {1} to host {2}".format(
                session.uuid,
                self.posix_user,
                session.host))


def main():
    os.popen('kinit -k').read()
    aker = Aker()
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '').strip()
    is_proxy = 'host=' in command
    if is_proxy:
        port = 22
        host = None
        for term in command.split(' '):
            if term.startswith('host='):
                host = term[5:]
            if term.startswith('port='):
                port = term[5:]
        assert host is not None
        screen_size = [os.getenv('LINES', 80), os.getenv('COLUMNS', 300)]

        session_uuid = uuid.uuid4()
        session = SSHSession(aker, host, session_uuid, port)

        sniffer = SSHSniffer(
            aker.posix_user,
            config.src_port,
            host,
            session_uuid,
            screen_size)
        session.attach_sniffer(sniffer)
        logging.info(
            "Core: Starting session UUID {0} for user {1} to host {2}".format(
                session_uuid, aker.posix_user, host))
        session.connect(screen_size)
        try:
            session.start_session()
        finally:
            session.stop_sniffer()
    else:
        aker.build_tui()


if __name__ == '__main__':
    main()
