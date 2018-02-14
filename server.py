#!/usr/bin/env python3

import ts3
import requests
from threading import Thread
import socket
import os

# ApiHost = 'http://wgauth.mir-ts.ru'
ApiHost = 'http://wg-auth.service-voice.com'


def log_add(level, message, thread_name=''):
    if thread_name is '':
        print("[", level, "]", message)
    else:
        print("[", level, "]", "[", thread_name, "]", message)


class TeamSpeakServerBot(Thread):
    def __init__(self, ip='127.0.0.1', port=10011, login='serveradmin', password='', server_uid='',
                 module_config={None}):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.login = login
        self.password = password
        self.server_uid = server_uid
        self.module_config = module_config
        self.last_raw_event = ''
        self.event_callback = {}
        self.exit_flag = False

    def return_server_id_by_uid(self, uid):
        for VirtualServer in self.ts3.serverlist(uid=True):
            if uid == VirtualServer["virtualserver_unique_identifier"]:
                return VirtualServer["virtualserver_id"]

    def return_client_uid_by_clid(self, clid):
        return self.ts3.clientinfo(clid=clid)[0]["client_unique_identifier"]

    def return_client_dbid_by_clid(self, clid):
        return self.ts3.clientinfo(clid=clid)[0]["client_database_id"]

    def return_default_server_group_id(self):
        return self.ts3.serverinfo()[0]["virtualserver_default_server_group"]

    def client_is_joined_default_server_group(self, cldbid):
        if self.ts3.servergroupsbyclientid(cldbid=cldbid)[0].get('sgid') == self.return_default_server_group_id():
            return True
        else:
            return False

    def run(self):
        self.ts3 = ts3.query.TS3Connection(self.ip, self.port)
        self.ts3.login(client_login_name=self.login, client_login_password=self.password)
        self.ts3.use(sid=self.return_server_id_by_uid(self.server_uid))
        if self.module_config is None:
            log_add('info', 'В конфигурации не были указаны модули для загрузки', thread_name=self.getName())
        else:
            for modules in self.module_config:
                try:
                    getattr(self, str(modules))()
                    log_add('info', 'модуль загружен: ' + str(modules), thread_name=self.getName())
                except AttributeError:
                    log_add('info', 'модуль не загружен: ' + str(modules), thread_name=self.getName())
        self.ts3.servernotifyregister(event="server")
        self.ts3.servernotifyregister(event="channel", id_=0)
        self.ts3.servernotifyregister(event="textprivate")
        while True:
            self.ts3.send_keepalive()
            try:
                # This method blocks, but we must sent the keepalive message at
                # least once in 10 minutes. So we set the timeout parameter to
                # 9 minutes.
                events = self.ts3.wait_for_event(timeout=5)

                if self.exit_flag is True:
                    exit(0)

            except ts3.query.TS3TimeoutError:
                pass
            else:
                if self.last_raw_event == str(events[0]):
                    continue
                else:
                    log_add('info', 'наступило событие ' + events.event, thread_name=self.getName())
                    self.call_callback_event(events.event, events[0])
                self.last_raw_event = str(events[0])

    def hello_bot(self):
        self.add_event_callback('notifycliententerview', 'hello_bot_callback')

    def hello_bot_callback(self, event_data):
        try:
            if self.client_is_joined_default_server_group(self.return_client_dbid_by_clid(event_data.get("clid"))):
                self.ts3.sendtextmessage(targetmode=1, target=event_data.get("clid"),
                                         msg=self.module_config.get('hello_bot').get('message'))
                log_add('info', 'пользователю с id ' + event_data.get(
                    "clid") + ' было отправлено сообщение "' + self.module_config.get(
                    'hello_bot').get('message') + '"', thread_name=self.getName())
            else:
                log_add('info', 'пользователь с id ' + event_data.get(
                    "clid") + ' уже авторизирован, и ему сообщение не отправлялось', thread_name=self.getName())
        except ts3.query.TS3QueryError as e:
            log_add('error',
                    'в модуле hello_bot возникла ошибка: ' + str(e.resp.error["msg"]) + ' данные события: \n' + str(
                        event_data),
                    thread_name=self.getName())
            raise

    def wg_auth_bot(self):
        self.add_event_callback('notifyclientmoved', 'wg_auth_bot_callback')

    def wg_auth_bot_callback(self, event_data):
        try:
            if event_data.get("ctid") == self.module_config.get('wg_auth_bot').get('cid'):
                if self.client_is_joined_default_server_group(self.return_client_dbid_by_clid(event_data.get("clid"))):
                    log_add('info', 'пользователь с id: ' + event_data.get("clid") + ' перешел в канал для авторизации',
                            thread_name=self.getName())

                    client_uid = self.return_client_uid_by_clid(event_data.get("clid"))

                    r = requests.post(self.module_config.get('wg_auth_bot').get('url'),
                                      json={"client_uid": client_uid, "server_uid": self.server_uid})
                    data = r.json()
                    if data["verify"] == 'successfully':
                        message = 'Вы были успешно авторизированы'
                    elif data["verify"] == 'ClanNotAllowedOrNoClan':
                        message = 'Вы не состоите в клане или состоите в недопустимом клане или кеш данных ещё не обновился, попробуйте через 30 минут.'
                    elif data["verify"] == 'ModuleIsDisabled':
                        message = 'Данный модуль отключен для этого сервера, не понятно как вы смогли получить ссылку'
                    elif data["verify"] == 'ServerNotFound':
                        message = 'Сервер не найден в базе данных'
                    elif data["verify"] == 'AuthorizationRequired':
                        message = 'Перейдите по ссылке: [url]' + str(self.module_config.get('wg_auth_bot').get('url')) + "/" + str(
                            data["verify_id"])+'[/url]'

                    self.ts3.sendtextmessage(targetmode=1, target=event_data.get("clid"),
                                             msg=message)

        except ts3.query.TS3QueryError as e:
            log_add('error',
                    'в модуле hello_bot возникла ошибка: ' + str(e.resp.error["msg"]) + ' данные события: \n' + str(
                        event_data),
                    thread_name=self.getName())
            raise

    def nickname_change(self):
        self.ts3.clientupdate(client_nickname=self.module_config.get('nickname_change').get('nickname'))

    def add_event_callback(self, event_name, functions):
        if self.event_callback.get(event_name, 0) == 0:
            self.event_callback[event_name] = list()
            self.event_callback[event_name].append(functions)
        else:
            self.event_callback[event_name].append(functions)

    def call_callback_event(self, event_name, event_data):
        if self.event_callback.get(event_name, 0) == 0:
            return
        else:
            for callback in self.event_callback[event_name]:
                try:
                    getattr(self, str(callback))(event_data)
                    log_add('info', 'модуль ' + str(callback) + ' успешно завершил работу при событии: ' + event_name,
                            thread_name=self.getName())
                except Exception:
                    log_add('error',
                            'модуль ' + str(callback) + ' завершил работу с ошибкой при событии: ' + event_name,
                            thread_name=self.getName())

    def exit(self):
        self.exit_flag = True


class TelnetInterfaces(Thread):
    admin_port = 4000

    def __init__(self):
        Thread.__init__(self)

    def run(self):
        SendClientText = ''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', self.admin_port))
        s.listen(3)
        log_add('warn', 'Прослушивается административный интерфейс на порту: ' + str(self.admin_port),
                thread_name=self.getName())

        conn, addr = s.accept()

        log_add('warn', 'К административному интерфейсу подключился клиент с ip: ' + str(addr),
                thread_name=self.getName())
        while 1:
            data = conn.recv(3024)
            if not data: break
            log_add('warn', 'Была получена команда:' + str(data.decode()))
            if str(data.decode()) == 'stop':
                os._exit(os.F_OK)
            if str(data.decode()) == 'quit':
                break
        conn.close()


class AdminInterfaces:
    def __init__(self):
        self.bot_config = dict()
        self.threads = {}

    def kill_all_bot(self):
        for ServerUID in self.threads:
            self.threads[ServerUID].exit()

    def start_all_bot(self):
        for ServerUID, Server in self.bot_config.items():
            self.threads[ServerUID] = TeamSpeakServerBot(ip=Server.get('ip'), port=Server.get('port'),
                                                         password=Server.get('password'),
                                                         server_uid=Server.get('uid'),
                                                         module_config=Server.get('module'))
            self.threads[ServerUID].setName(ServerUID)
            self.threads[ServerUID].start()
            self.threads[ServerUID].join(1)

    def reload_all_bot_config(self):
        log_add("info", "Загрузка конфигурации воркеров")
        r = requests.get(ApiHost + '/teamspeak/worker/config')
        log_add("info", "Конфигурация воркера:")
        self.bot_config = r.json()
        log_add("info", self.bot_config)


if __name__ == "__main__":
    AdminInterfaces = AdminInterfaces()
    AdminInterfaces.reload_all_bot_config()
    AdminInterfaces.start_all_bot()

    TelnetInterfaces = TelnetInterfaces()
    TelnetInterfaces.setName("AdminInterfaces")
    TelnetInterfaces.start()
