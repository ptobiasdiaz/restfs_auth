#!/usr/bin/env python3

'''
    Implementacion del servicio de autenticacion
'''

import json
import logging
import os.path
import secrets
import threading

from restfs_common.constants import ADMIN, USER_TOKEN_SIZE, USER_TOKEN_AGE_INTERVAL,\
    USER_TOKEN_MAX_AGE, AGE, OWNER, DEFAULT_ENCODING
from restfs_common.errors import Unauthorized, ObjectAlreadyExists, ObjectNotFound


_DEB = logging.debug
_WRN = logging.warning


def _initialize_(db_file):
    '''Create an empty JSON file'''
    _WRN(f'Initializing new database in file "{db_file}"')
    with open(db_file, 'w', encoding=DEFAULT_ENCODING) as contents:
        json.dump({}, contents)


def _new_token_():
    '''Create a new token'''
    return secrets.token_urlsafe(USER_TOKEN_SIZE)


class AuthDB:
    '''
        Controla la base de datos persistente del servicio de autenticacion
    '''
    def __init__(self, db_file):
        if not os.path.exists(db_file):
            _initialize_(db_file)
        self._db_file_ = db_file
        self.token_manager = None

        self._users_ = {}

        self._read_db_()

    def _read_db_(self):
        with open(self._db_file_, 'r', encoding=DEFAULT_ENCODING) as contents:
            self._users_ = json.load(contents)

    def _commit_(self):
        with open(self._db_file_, 'w', encoding=DEFAULT_ENCODING) as contents:
            json.dump(self._users_, contents, indent=2, sort_keys=True)

    def new_user(self, username, password_hash):
        '''Add new user to DB'''
        if (username == ADMIN) or (username in self._users_):
            raise ObjectAlreadyExists(f'User "{username}"')
        self._users_[username] = password_hash
        self._commit_()

    def remove_user(self, username):
        '''Remove user from DB'''
        if username not in self._users_:
            raise ObjectNotFound(f'User "{username}"')
        del self._users_[username]
        self._commit_()
        if isinstance(self.token_manager, TokenManager):
            try:
                self.token_manager.remove_token_of(username)
            except ObjectNotFound: # pragma: no cover
                pass

    def change_password_hash(self, username, new_password_hash):
        '''Change password hash of a given user'''
        if username not in self._users_:
            raise ObjectNotFound(f'User "{username}"')
        self._users_[username] = new_password_hash
        self._commit_()

    def exists(self, username):
        '''Return if a given user exists or not'''
        return username in [ADMIN] + list(self._users_.keys())

    def valid_hash(self, password_hash, username):
        '''Return if a given hash is valid or not'''
        if username == ADMIN and (self.token_manager is not None):
            return password_hash == self.token_manager.admin_token
        if username not in self._users_:
            return False
        return self._users_[username] == password_hash


class TokenManager:
    '''
        Controla la base de datos volatil del servicio de autenticacion
    '''
    def __init__(self, admin_token, authdb,
                 age_interval=USER_TOKEN_AGE_INTERVAL, max_token_age=USER_TOKEN_MAX_AGE):
        self._admin_token_ = admin_token
        # Attach TokenManager() with AuthDB()
        self._authdb_ = authdb
        authdb.token_manager = self
        self._token_ = {}

        self._timers_ = {}
        self._age_interval = age_interval
        self._max_token_age_ = max_token_age

    @property
    def admin_token(self):
        '''Return the admin token'''
        return self._admin_token_

    def new_token(self, username, password_hash):
        '''Create new token for a given username. Check credentials'''
        if not self._authdb_.valid_hash(password_hash, username):
            _WRN(f'Reject to create new token for user "{username}"')
            raise Unauthorized(username, 'Invalid password hash')

        token = _new_token_()
        self._token_[token] = {
            OWNER: username,
            AGE: 0
        }
        self._new_timer_for_token_(token)
        return token

    def _increase_age_(self, token):
        '''Increase the age of a given token'''
        if token not in self._token_: # pragma: no cover
            _WRN(f'Token "{token}" already removed!')
            return
        current_age = self._token_[token][AGE]
        current_age += 1
        if current_age >= self._max_token_age_:
            _DEB(f'Token "{token}" expired!')
            self._remove_token_(token)
            return

        self._token_[token][AGE] = current_age
        self._new_timer_for_token_(token)

    def _new_timer_for_token_(self, token):
        '''Create new timer for a given token'''
        self._timers_[token] = threading.Timer(self._age_interval, self._increase_age_, (token,))
        self._timers_[token].start()

    def stop(self):
        '''Cancel all timers'''
        for timer in list(self._timers_.values()):
            timer.cancel()
        self._token_ = {}
        self._timers_ = {}

    def remove_token_of(self, user):
        '''Remove token for the given user (if exists)'''
        target_token = None
        for token, token_config in self._token_.items():
            if token_config[OWNER] == user:
                target_token = token
                break
        if target_token:
            self._remove_token_(target_token)

    def _remove_token_(self, token):
        '''Remove given token'''
        if token in self._timers_:
            self._timers_[token].cancel()
            del self._timers_[token]
        if token in self._token_:
            del self._token_[token]

    def owner_of(self, token):
        '''Return the owner of a token or exception is token not exists'''
        if token not in self._token_:
            raise ObjectNotFound(f'Token #{token}')
        return self._token_[token][OWNER]

    def reset_age_of(self, token):
        '''Reset the age of a given token'''
        if token not in self._token_:
            raise ObjectNotFound(f'Token #{token}')
        self._token_[token][AGE] = 0
