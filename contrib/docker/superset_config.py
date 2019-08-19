# # Licensed to the Apache Software Foundation (ASF) under one
# # or more contributor license agreements.  See the NOTICE file
# # distributed with this work for additional information
# # regarding copyright ownership.  The ASF licenses this file
# # to you under the Apache License, Version 2.0 (the
# # "License"); you may not use this file except in compliance
# # with the License.  You may obtain a copy of the License at
# #
# #   http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing,
# # software distributed under the License is distributed on an
# # "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# # KIND, either express or implied.  See the License for the
# # specific language governing permissions and limitations
# # under the License.
# import os
#
#
# def get_env_variable(var_name, default=None):
#     """Get the environment variable or raise exception."""
#     try:
#         return os.environ[var_name]
#     except KeyError:
#         if default is not None:
#             return default
#         else:
#             error_msg = 'The environment variable {} was missing, abort...' \
#                 .format(var_name)
#             raise EnvironmentError(error_msg)
#
#
# POSTGRES_USER = get_env_variable('POSTGRES_USER')
# POSTGRES_PASSWORD = get_env_variable('POSTGRES_PASSWORD')
# POSTGRES_HOST = get_env_variable('POSTGRES_HOST')
# POSTGRES_PORT = get_env_variable('POSTGRES_PORT')
# POSTGRES_DB = get_env_variable('POSTGRES_DB')
#
# # The SQLAlchemy connection string.
# SQLALCHEMY_DATABASE_URI = 'postgresql://%s:%s@%s:%s/%s' % (POSTGRES_USER,
#                                                            POSTGRES_PASSWORD,
#                                                            POSTGRES_HOST,
#                                                            POSTGRES_PORT,
#                                                            POSTGRES_DB)
#
# REDIS_HOST = get_env_variable('REDIS_HOST')
# REDIS_PORT = get_env_variable('REDIS_PORT')
#
#
# class CeleryConfig(object):
#     BROKER_URL = 'redis://%s:%s/0' % (REDIS_HOST, REDIS_PORT)
#     CELERY_IMPORTS = ('superset.sql_lab',)
#     CELERY_RESULT_BACKEND = 'redis://%s:%s/1' % (REDIS_HOST, REDIS_PORT)
#     CELERY_ANNOTATIONS = {'tasks.add': {'rate_limit': '10/s'}}
#     CELERY_TASK_PROTOCOL = 1
#
#
# CELERY_CONFIG = CeleryConfig
#
# from flask_appbuilder.baseviews import expose
# from flask_appbuilder.security.manager import AUTH_OID
# from flask_oidc import OpenIDConnect
#
# from superset.security import SupersetSecurityManager
#
#
# class CustomSecurityManager(SupersetSecurityManager):
#
#     def __init__(self, appbuilder):
#         super(CustomSecurityManager, self).__init__(appbuilder)
#         if self.auth_type == AUTH_OID:
#             self.oid = OpenIDConnect(self.appbuilder.get_app)
#         self.authoidview = AuthOIDCView
#
#     def find_user(self, username=None, email=None):
#         return super().find_user(username, email)
#
#     # def whatever_you_want_to_override(self, ...):
#
#
# #
# # class OIDCSecurityManager(SupersetSecurityManager):
# #
# #     def __init__(self, appbuilder):
# #         super(OIDCSecurityManager, self).__init__(appbuilder)
# #         if self.auth_type == AUTH_OID:
# #             self.oid = OpenIDConnect(self.appbuilder.get_app)
# #         self.authoidview = AuthOIDCView
#
#
# from flask_appbuilder.security.views import AuthOIDView
# from flask_login import login_user
# from urllib import parse
# from flask import request
# from flask import redirect
#
#
# class AuthOIDCView(AuthOIDView):
#
#     @expose('/login/', methods=['GET', 'POST'])
#     def login(self, flag=True):
#         sm = self.appbuilder.sm
#         oidc = sm.oid
#
#         @self.appbuilder.sm.oid.require_login
#         def handle_login():
#             user = sm.auth_user_oid(oidc.user_getfield('email'))
#
#             if user is None:
#                 info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
#                 user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
#                                    info.get('email'), sm.find_role('Gamma'))
#
#
#             print(user, "$$$")
#             login_user(user, remember=False)
#             return redirect(self.appbuilder.get_url_for_index)
#
#         return handle_login()
#
#     @expose('/logout/', methods=['GET', 'POST'])
#     def logout(self):
#         oidc = self.appbuilder.sm.oid
#
#         oidc.logout()
#         super(AuthOIDCView, self).logout()
#         redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
#
#         return redirect(
#             oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?redirect_uri=' + parse.quote(
#                 redirect_url))
#
# import os
#
# '''
# AUTHENTICATION
# '''
# AUTH_TYPE = AUTH_OID
# # OIDC_CLIENT_SECRETS = 'client_secrets.json'
# OIDC_ID_TOKEN_COOKIE_SECURE = False
# OIDC_REQUIRE_VERIFIED_EMAIL = False
# CUSTOM_SECURITY_MANAGER = CustomSecurityManager
# AUTH_USER_REGISTRATION = True
# AUTH_USER_REGISTRATION_ROLE = 'Gamma'
