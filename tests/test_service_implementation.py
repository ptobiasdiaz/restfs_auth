#!/usr/bin/env python3

import time
import os.path
import tempfile
import unittest
from pathlib import Path

from restfs_common.errors import Unauthorized, ObjectAlreadyExists, ObjectNotFound
from restfs_common.constants import ADMIN

from restfs_auth.service import AuthDB, TokenManager


ADMIN_TOKEN = 'test_admin_token'
WRONG_TOKEN = 'this_token_should_not_exists'
USER1 = 'test_user1'
USER2 = 'test_user2'
HASH1 = 'test_user1_hash'
NEW_HASH1 = 'test_user1_hash_new'
WRONG_HASH1 = 'test_user1_hash_but_wrong'


class TestPersistentDB(unittest.TestCase):

    def test_creation(self):
        '''Test initialization'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            self.assertFalse(os.path.exists(dbfile))
            authdb = AuthDB(db_file=dbfile)
            self.assertTrue(os.path.exists(dbfile))
            self.assertTrue(authdb.exists(ADMIN))

    def test_create_user(self):
        '''Test create user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            self.assertFalse(authdb.valid_hash(HASH1, USER1))
            self.assertFalse(authdb.exists(USER1))
            authdb.new_user(USER1, HASH1)
            self.assertTrue(authdb.valid_hash(HASH1, USER1))
            self.assertTrue(authdb.exists(USER1))

    def test_create_admin_user(self):
        '''Test create admin'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            with self.assertRaises(ObjectAlreadyExists):
                authdb.new_user(ADMIN, HASH1)

    def test_create_duplicated_user(self):
        '''Test create añready-exists user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            authdb.new_user(USER1, HASH1)
            with self.assertRaises(ObjectAlreadyExists):
                authdb.new_user(USER1, HASH1)

    def test_remove_user(self):
        '''Test remove user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            authdb.new_user(USER1, HASH1)
            self.assertTrue(authdb.valid_hash(HASH1, USER1))
            self.assertTrue(authdb.exists(USER1))
            authdb.remove_user(USER1)
            self.assertFalse(authdb.valid_hash(HASH1, USER1))
            self.assertFalse(authdb.exists(USER1))

    def test_remove_user_with_token(self):
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb)

            authdb.new_user(USER1, HASH1)
            token = tokenman.new_token(USER1, HASH1)

            authdb.remove_user(USER1)
            with self.assertRaises(ObjectNotFound):
                tokenman.owner_of(token)

    def test_remove_not_exists_user(self):
        '''Test remove not-exists user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            with self.assertRaises(ObjectNotFound):
                authdb.remove_user(USER1)

    def test_change_user_hash(self):
        '''Test change password hash of an user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            authdb.new_user(USER1, HASH1)
            self.assertTrue(authdb.valid_hash(HASH1, USER1))
            authdb.change_password_hash(USER1, NEW_HASH1)
            self.assertFalse(authdb.valid_hash(HASH1, USER1))
            self.assertTrue(authdb.valid_hash(NEW_HASH1, USER1))

    def test_change_wrong_user_hash(self):
        '''Test change password hash of a wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            with self.assertRaises(ObjectNotFound):
                authdb.change_password_hash(USER1, NEW_HASH1)

    def test_valid_hash_of_admin(self):
        '''Test check valid hash of admin'''
        class TokenManagerMock:
            admin_token = ADMIN_TOKEN
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            authdb.token_manager = TokenManagerMock()

            self.assertTrue(authdb.valid_hash(ADMIN_TOKEN, ADMIN))

    def test_exists_admin_user(self):
        '''Test check if admin user exists'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)

            self.assertTrue(authdb.exists(ADMIN))


class TestTokenManager(unittest.TestCase):

    def test_creation(self):
        '''Test creation of a new TokenManager()'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb)

            self.assertIs(authdb.token_manager, tokenman)
            self.assertEqual(ADMIN_TOKEN, tokenman.admin_token)
            tokenman.stop()

    def test_new_token(self):
        '''Test creation of a new token'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb)

            authdb.new_user(USER1, HASH1)

            token = tokenman.new_token(USER1, HASH1)
            self.assertEqual(USER1, tokenman.owner_of(token))

            tokenman.stop()

    def test_new_token_wrong_hash(self):
        '''Test creation of a new token with wrong hash'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb)

            authdb.new_user(USER1, HASH1)

            with self.assertRaises(Unauthorized):
                token = tokenman.new_token(USER1, WRONG_HASH1)

            tokenman.stop()

    def test_token_expiration(self):
        '''Test token expiration'''
        with tempfile.TemporaryDirectory() as workspace:
            TEST_AGE_INTERVAL = 1.0
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb, age_interval=TEST_AGE_INTERVAL, max_token_age=2)

            authdb.new_user(USER1, HASH1)

            token = tokenman.new_token(USER1, HASH1)
            self.assertEqual(USER1, tokenman.owner_of(token))
            time.sleep(TEST_AGE_INTERVAL * 3.0)
            with self.assertRaises(ObjectNotFound):
                tokenman.owner_of(token)

            tokenman.stop()

    def test_token_age_reset(self):
        '''Test token age reset'''
        with tempfile.TemporaryDirectory() as workspace:
            TEST_AGE_INTERVAL = 1.0
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb, age_interval=TEST_AGE_INTERVAL, max_token_age=2)

            authdb.new_user(USER1, HASH1)

            token = tokenman.new_token(USER1, HASH1)
            self.assertEqual(USER1, tokenman.owner_of(token))
            time.sleep(TEST_AGE_INTERVAL * 1.0)
            tokenman.reset_age_of(token)
            time.sleep(TEST_AGE_INTERVAL * 2.0)
            with self.assertRaises(ObjectNotFound):
                tokenman.owner_of(token)

            tokenman.stop()

    def test_token_age_reset_wrong_token(self):
        '''Test token age reset of wrong token'''
        with tempfile.TemporaryDirectory() as workspace:
            TEST_AGE_INTERVAL = 1.0
            dbfile = Path(workspace).joinpath('dbfile.json')
            authdb = AuthDB(db_file=dbfile)
            tokenman = TokenManager(ADMIN_TOKEN, authdb, age_interval=TEST_AGE_INTERVAL, max_token_age=2)

            with self.assertRaises(ObjectNotFound):
                tokenman.reset_age_of(WRONG_TOKEN)

            tokenman.stop()
