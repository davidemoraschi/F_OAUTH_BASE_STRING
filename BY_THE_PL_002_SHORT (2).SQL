/* Formatted on 2010/08/10 21:23 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';

   oauth_get_request_token_url   VARCHAR2 (1000) := 'http://1daylater.com/get_request_token';
   oauth_authorize_url           VARCHAR2 (1000) := 'http://1daylater.com/authorize';
   oauth_get_access_token_url    VARCHAR2 (1000) := 'http://1daylater.com/get_access_token';
   oauth_consumer_key            VARCHAR2 (50) := 'NHx8CZzuf9XEF6C2ksimwDkS7Fw=';
   oauth_consumer_secret         VARCHAR2 (50) := '7XF7YN/rNzYcqDlJFsTqyC81KWw=';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_signature               VARCHAR2 (100);
   oauth_token                   VARCHAR2 (500) := 'bJmvayPVSgr6vk1Gq8lEeasvTgY=';
   oauth_token_secret            VARCHAR2 (500) := 'tNy8Xe5GugLIEGykkCCjVvgzPAA=';
   oauth_verifier                VARCHAR2 (500) := 'UfAtkasJ';
   oauth_access_token            VARCHAR2 (500);
   oauth_access_token_secret     VARCHAR2 (500);
   v_http_req_url                VARCHAR2 (4000);
   return_html                   VARCHAR2 (32767);
BEGIN
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   UTL_HTTP.set_wallet (PATH => con_str_wallet_path, PASSWORD => con_str_wallet_pass);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);

   SELECT urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT TO_CHAR ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400)
                   - (TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600))
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_signature :=
      oauth.signature (oauth.base_string_token (oauth_get_access_token_url
                                               ,oauth_consumer_key
                                               ,oauth_timestamp
                                               ,oauth_nonce
                                               ,oauth_token
                                               ,oauth_verifier)
                      ,oauth.key_token (oauth_consumer_secret, oauth_token_secret));
   v_http_req_url :=
      oauth.http_req_url_token (oauth_get_access_token_url
                               ,oauth_consumer_key
                               ,oauth_timestamp
                               ,oauth_nonce
                               ,oauth_signature
                               ,oauth_token
                               ,oauth_verifier);

   SELECT UTL_HTTP.request (v_http_req_url)
   INTO   return_html
   FROM   DUAL;

   SELECT oauth.get_token (oauth.get_token (return_html, 1, '&'), 2, '=')
   INTO   oauth_access_token
   FROM   DUAL;

   SELECT oauth.get_token (oauth.get_token (return_html, 2, '&'), 2, '=')
   INTO   oauth_access_token_secret
   FROM   DUAL;

   DBMS_OUTPUT.put_line ('return_html=' || return_html);
   DBMS_OUTPUT.put_line ('oauth_access_token=' || utl_url.unescape (oauth_access_token));
   DBMS_OUTPUT.put_line ('oauth_access_token_secret=' || utl_url.unescape (oauth_access_token_secret));
END;
/