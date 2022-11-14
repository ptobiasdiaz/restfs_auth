#!/usr/bin/env python3

'''Auth server for RestFS'''

import sys
import json
import logging
import secrets
import argparse

from flask import Flask, make_response, request

from restfs_common.errors import Unauthorized, ObjectAlreadyExists, ObjectNotFound
from restfs_common.constants import USER, TOKEN, ADMIN, ADMIN_TOKEN, USER_TOKEN, HASH_PASS,\
    DEFAULT_AUTH_SERVICE_PORT, DEFAULT_AUTH_DB, HTTPS_DEBUG_MODE

from restfs_auth.service import AuthDB, TokenManager


def routeApp(app, AUTHDB, TOKENMAN):
    '''Enruta la API REST a la webapp'''

    @app.route('/v1/user/login', methods=['POST'])
    def do_login():
        '''Genera un token si el usuario es valido'''
        if not request.is_json:
            return make_response('Missing JSON', 400)
        request_data = request.get_json()
        if (USER not in request_data) or (HASH_PASS not in request_data):
            return make_response(f'Missing "{USER}" and/or "{HASH_PASS}" key', 400)
        try:
            token = TOKENMAN.new_token(request_data[USER], request_data[HASH_PASS])
        except Unauthorized:
            return make_response('Wrong user/password', 401)
        response = json.dumps({
            USER: request_data[USER],
            TOKEN: token
        })
        return make_response(response, 200)

    @app.route('/v1/user/<user>', methods=['PUT'])
    def add_user(user):
        '''Crea un nuevo usuario'''
        if not request.is_json:
            return make_response('Missing JSON', 400)

        request_data = request.get_json()
        if HASH_PASS not in request_data:
            return make_response(f'Missing "{HASH_PASS}" key', 400)

        admin_token = request.headers.get(ADMIN_TOKEN, None)
        if admin_token != TOKENMAN.admin_token:
            return make_response('Invalid admin token', 401)

        try:
            AUTHDB.new_user(user, request_data[HASH_PASS])
        except ObjectAlreadyExists as error:
            return make_response(f'Cannot create user: {error}', 409)

        response = {USER: user }
        return make_response(json.dumps(response), 201)

    @app.route('/v1/user/<user>', methods=['POST'])
    def change_user_password(user):
        '''Cambiar password-hash de usuario'''
        if not request.is_json:
            return make_response('Missing JSON', 400)
        request_data = request.get_json()
        if HASH_PASS not in request_data:
            return make_response(f'Missing "{HASH_PASS}" key', 400)

        admin_token = request.headers.get(ADMIN_TOKEN, None)
        user_token = request.headers.get(USER_TOKEN, None)

        expected_user = None
        if user_token:
            try:
                expected_user = TOKENMAN.owner_of(user_token)
            except ObjectNotFound:
                pass

        if ((admin_token == TOKENMAN.admin_token) or (user == expected_user)):
            try:
                AUTHDB.change_password_hash(user, request_data[HASH_PASS])
            except ObjectNotFound as error:
                return make_response(f'Object not found: {error}', 404)
            return make_response(json.dumps({USER: user }), 202)

        return make_response('Unauthorized', 400)

    @app.route('/v1/user/<user>', methods=['GET'])
    def exists_user(user):
        '''Indica si un usuario existe o no'''
        if user == ADMIN:
            admin_token = request.headers.get(ADMIN_TOKEN, None)
            if admin_token == TOKENMAN.admin_token:
                return make_response('', 204)
            return make_response('Invalid admin', 401)
        if AUTHDB.exists(user):
            return make_response('', 204)
        return make_response('User not found', 404)

    @app.route('/v1/user/<user>', methods=['DELETE'])
    def delete_user(user):
        '''Elimina un usuario'''
        admin_token = request.headers.get(ADMIN_TOKEN, None)
        if admin_token != TOKENMAN.admin_token:
            return make_response('Not authorized', 401)
        try:
            AUTHDB.remove_user(user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)

        return make_response('', 204)

    @app.route('/v1/token/<token>', methods=['GET'])
    def token_owner(token):
        '''Comprueba el usuario de un token'''
        try:
            owner = TOKENMAN.owner_of(token)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        return make_response(json.dumps({USER: owner}), 200)


class AuthService:
    '''Wrap all components used by the service'''
    def __init__(self, db_file, admin_token, host='0.0.0.0', port=DEFAULT_AUTH_SERVICE_PORT):
        self._authdb_ = AuthDB(db_file)
        self._tokenman_ = TokenManager(admin_token, self._authdb_)

        self._host_ = host
        self._port_ = port

        self._app_ = Flask(__name__.split('.', maxsplit=1)[0])
        routeApp(self._app_, self._authdb_, self._tokenman_)

    @property
    def base_uri(self):
        '''Get the base URI to access the API'''
        host = '127.0.0.1' if self._host_ in ['0.0.0.0'] else self._host_
        return f'http://{host}:{self._port_}'

    def start(self):
        '''Start HTTP server'''
        self._app_.run(host=self._host_, port=self._port_, debug=HTTPS_DEBUG_MODE)

    def stop(self):
        '''Cancel all remaining timers'''
        self._tokenman_.stop()


def main():
    '''Entry point for the auth server'''
    user_options = parse_commandline()
    if not user_options.admin_token:
        user_options.admin_token = secrets.token_urlsafe(20)
        print(f'Admin token: {user_options.admin_token}')

    service = AuthService(
        user_options.db_file, user_options.admin_token, user_options.address, user_options.port
    )
    try:
        print(f'Starting service on: {service.base_uri}')
        service.start()
    except Exception as error: # pylint: disable=broad-except
        logging.error('Cannot start API: %s', error)
        sys.exit(1)

    service.stop()
    sys.exit(0)


def parse_commandline():
    '''Parse command line'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '-a', '--admin-token', type=str, default=None,
        help='Admin token', dest='admin_token'
    )
    parser.add_argument(
        '-p', '--port', type=int, default=DEFAULT_AUTH_SERVICE_PORT,
        help='Listening port (default: %(default)s)', dest='port'
    )
    parser.add_argument(
        '-l', '--listening', type=str, default='0.0.0.0',
        help='Listening address (default: all interfaces)', dest='address'
    )
    parser.add_argument(
        '-d', '--db', type=str, default=DEFAULT_AUTH_DB,
        help='Database to use (default: %(default)s', dest='db_file'
    )
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    main()
