#!/usr/bin/env python3

import ts3
import requests
from threading import Thread
import socket
import os
import time

ApiHost = 'http://wgauth.mir-ts.ru'
# ApiHost = 'http://wg-auth.service-voice.com'


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
        # self.ts3.servernotifyregister(event="textprivate")
        while True:
            self.ts3.send_keepalive()
            try:
                # This method blocks, but we must sent the keepalive message at
                # least once in 10 minutes. So we set the timeout parameter to
                # 9 minutes.
                events = self.ts3.wait_for_event(timeout=1)

                if self.exit_flag is True:
                    self.ts3.quit()
                    log_add('warn', 'Поток остановлен ', thread_name=self.getName())
                    return
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
        if event_data.get('client_type') == '1':
            return
        try:
            if self.client_is_joined_default_server_group(self.return_client_dbid_by_clid(event_data.get("clid"))):
                if self.module_config.get('hello_bot').get('message_type') == 'message':
                    self.ts3.sendtextmessage(targetmode=1, target=event_data.get("clid"),
                                             msg=self.module_config.get('hello_bot').get('message'))
                    log_add('info', 'пользователю с id ' + event_data.get(
                        "clid") + ' было отправлено сообщение "' + self.module_config.get(
                        'hello_bot').get('message') + '"', thread_name=self.getName())
                elif self.module_config.get('hello_bot').get('message_type') == 'poke':
                    result = self.module_config.get('hello_bot').get('message').split('-')
                    for message in result:
                        self.ts3.clientpoke(clid=event_data.get("clid"),
                                            msg=message)
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

    def return_default_channel_id(self):
        for channel in self.ts3.channellist(flags=True):
            if channel.get('channel_flag_default') == '1':
                return channel.get('cid')

    def wg_auth_bot_callback(self, event_data):
        try:
            if event_data.get("ctid") == self.module_config.get('wg_auth_bot').get('cid'):
                if self.client_is_joined_default_server_group(self.return_client_dbid_by_clid(event_data.get("clid"))):
                    log_add('info', 'пользователь с id: ' + event_data.get("clid") + ' перешел в канал для авторизации',
                            thread_name=self.getName())

                    client_uid = self.return_client_uid_by_clid(event_data.get("clid"))

                    r = requests.post(self.module_config.get('wg_auth_bot').get('url'),
                                      json={"client_uid": client_uid, "server_uid": self.server_uid})
                    if r.status_code == 200:
                        data = r.json()
                        if data["verify"] == 'successfully':
                            message = self.module_config.get('wg_auth_bot').get('message_success')
                            if self.module_config.get('wg_auth_bot').get('move_to_default_channel') == 'enable':
                                self.ts3.clientmove(clid=event_data.get("clid"), cid=self.return_default_channel_id())
                        elif data["verify"] == 'ClanNotAllowedOrNoClan':
                            message = self.module_config.get('wg_auth_bot').get(
                                'message_error_clan_not_allowed_or_no_clan')
                            if self.module_config.get('wg_auth_bot').get('move_to_default_channel') == 'enable':
                                self.ts3.clientmove(clid=event_data.get("clid"), cid=self.return_default_channel_id())
                        elif data["verify"] == 'ModuleIsDisabled':
                            message = self.module_config.get('wg_auth_bot').get('message_error_module_is_disabled')
                            if self.module_config.get('wg_auth_bot').get('move_to_default_channel') == 'enable':
                                self.ts3.clientmove(clid=event_data.get("clid"), cid=self.return_default_channel_id())
                        elif data["verify"] == 'ServerNotFound':
                            message = self.module_config.get('wg_auth_bot').get('message_error_server_not_found')
                            if self.module_config.get('wg_auth_bot').get('move_to_default_channel') == 'enable':
                                self.ts3.clientmove(clid=event_data.get("clid"), cid=self.return_default_channel_id())
                        elif data["verify"] == 'AuthorizationRequired':
                            if self.module_config.get('wg_auth_bot').get('message_type') == 'message':
                                message = self.module_config.get('wg_auth_bot').get(
                                    'message_authorization_required') % str(
                                    str(
                                        self.module_config.get('wg_auth_bot').get('url')) + '/' + str(
                                        data["verify_id"]))
                            elif self.module_config.get('wg_auth_bot').get('message_type') == 'poke':
                                result = self.module_config.get('wg_auth_bot').get(
                                    'message_authorization_required').split('-')
                                message = result[0]
                                url = result[1] % str(str(self.module_config.get('wg_auth_bot').get('url')) + '/' + str(
                                    data["verify_id"]))
                        if self.module_config.get('wg_auth_bot').get('message_type') == 'message':
                            self.ts3.sendtextmessage(targetmode=1, target=event_data.get("clid"),
                                                     msg=message)
                            log_add('info', 'пользователю с id ' + event_data.get(
                                "clid") + ' было отправлено сообщение "' + message + '"', thread_name=self.getName())
                        elif self.module_config.get('wg_auth_bot').get('message_type') == 'poke':
                            self.ts3.clientpoke(clid=event_data.get("clid"), msg=message)
                            if url != None:
                                self.ts3.clientpoke(clid=event_data.get("clid"), msg=url)
                                log_add('info', 'пользователю с id ' + event_data.get(
                                    "clid") + ' было отправлено сообщение "' + url + '"',
                                        thread_name=self.getName())
                            log_add('info', 'пользователю с id ' + event_data.get(
                                "clid") + ' было отправлено сообщение "' + message + '"', thread_name=self.getName())

                    else:
                        log_add('error',
                                'в модуле wg_auth_bot возникла ошибка: ' + str(r.text),
                                thread_name=self.getName())
        except ts3.query.TS3QueryError as e:
            log_add('error',
                    'в модуле hello_bot возникла ошибка: ' + str(e.resp.error["msg"]) + ' данные события: \n' + str(
                        event_data),
                    thread_name=self.getName())
            raise

    def nickname_change(self):
        try:
            self.ts3.clientupdate(client_nickname=self.module_config.get('nickname_change').get('nickname'))
        except ts3.query.TS3QueryError as e:
            log_add('error',
                    'в модуле nickname_change возникла ошибка: ' + str(e.resp.error["msg"]), thread_name=self.getName())

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
            if str(data.decode()) == 'reload':
                AdminInterfaces.reload_all_bot_config()
        conn.close()


class AdminInterfaces:
    def __init__(self):
        self.bot_config = dict()
        self.bot_config_new = dict()
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
        if len(self.bot_config) != 0:
            log_add("info", "Конфигурация бота уже была загружена, начинаем процесс обновления конфига")
            r = requests.get(ApiHost + '/teamspeak/worker/config')
            log_add("info", "Новая конфигурация воркера:")
            self.bot_config_new = r.json()
            log_add("info", self.bot_config_new)
            for ServerUID, Server in self.bot_config.items():
                if ServerUID in self.bot_config_new:
                    for key, val in self.bot_config_new[ServerUID].items():
                        if key in self.bot_config[ServerUID]:
                            if key != 'module' and self.bot_config[ServerUID][key] != val:
                                self.threads[ServerUID].exit()
                                self.threads[ServerUID] = TeamSpeakServerBot(ip=self.bot_config_new[ServerUID]['ip'],
                                                                             port=self.bot_config_new[ServerUID][
                                                                                 'port'],
                                                                             password=self.bot_config_new[ServerUID][
                                                                                 'password'],
                                                                             server_uid=self.bot_config_new[ServerUID][
                                                                                 'uid'],
                                                                             module_config=
                                                                             self.bot_config_new[ServerUID][
                                                                                 'module'])
                                self.threads[ServerUID].setName(ServerUID)
                                self.threads[ServerUID].start()
                            if key == 'module':
                                for key_module, val_module in self.bot_config_new[ServerUID][key].items():
                                    if key_module in self.bot_config[ServerUID][key]:
                                        if self.bot_config[ServerUID][key][key_module] != val_module:
                                            self.threads[ServerUID].exit()
                                            self.threads[ServerUID] = TeamSpeakServerBot(
                                                ip=self.bot_config_new[ServerUID]['ip'],
                                                port=self.bot_config_new[ServerUID]['port'],
                                                password=self.bot_config_new[ServerUID][
                                                    'password'],
                                                server_uid=self.bot_config_new[ServerUID][
                                                    'uid'],
                                                module_config=self.bot_config_new[ServerUID][
                                                    'module'])
                                            self.threads[ServerUID].setName(ServerUID)
                                            self.threads[ServerUID].start()
                else:
                    self.threads[ServerUID].exit()
            if len(self.bot_config_new) > 0:
                for ServerUID, Server in self.bot_config_new.items():
                    if ServerUID in self.bot_config:
                        print('')
                    else:
                        self.threads[ServerUID] = TeamSpeakServerBot(ip=Server.get('ip'), port=Server.get('port'),
                                                                     password=Server.get('password'),
                                                                     server_uid=Server.get('uid'),
                                                                     module_config=Server.get('module'))
                        self.threads[ServerUID].setName(ServerUID)
                        self.threads[ServerUID].start()
                        self.threads[ServerUID].join(1)

            log_add("info", "Перезагрузка конфигурации воркеров успешно завершена")
            return
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
