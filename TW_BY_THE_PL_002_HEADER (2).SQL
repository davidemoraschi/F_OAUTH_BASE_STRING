/* Formatted on 2010/08/11 11:04 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'GET';
   http_req                      UTL_HTTP.req;
   http_resp                     UTL_HTTP.resp;
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_get_request_token_url   VARCHAR2 (1000) := 'https://api.twitter.com/oauth/request_token';
   oauth_authorize_url           VARCHAR2 (1000) := 'https://api.twitter.com/oauth/authorize';
   oauth_get_access_token_url    VARCHAR2 (1000) := 'https://api.twitter.com/oauth/access_token';
   oauth_consumer_key            VARCHAR2 (50) := '5HFrVcwi7Hp1KpEQc4gfZQ';
   oauth_consumer_secret         VARCHAR2 (50) := 'FV3fn9H6ZR3yrgNjfmb21I6zF58KmZLydWq4jXHqhA';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_base_string             VARCHAR2 (1000);
   oauth_signature               VARCHAR2 (100);
   oauth_token                   VARCHAR2 (500) := 'o8FMyhajIrJbbuYyZ7vjspXVHZzfkfQ04IDNPpR1b6M';
   oauth_token_secret            VARCHAR2 (500) := '70tR1pvMtL09NcXx9U2Xv9DPbECqWcKibd3KPtc';
   oauth_verifier                VARCHAR2 (500) := '1320951';
   h_name                        VARCHAR2 (255);
   h_value                       VARCHAR2 (1023);
   res_value                     VARCHAR2 (32767);
   var_http_authorization_header VARCHAR2 (1024);
   show_header                   NUMBER := 0;
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

   oauth_base_string :=
                    oauth.base_string (http_method, oauth_get_request_token_url, oauth_consumer_key, oauth_timestamp, oauth_nonce);
   oauth_signature := oauth.signature (oauth_base_string, oauth.KEY (oauth_consumer_secret));
   var_http_authorization_header :=
                           oauth.authorization_header_no_token (oauth_consumer_key, oauth_timestamp, oauth_nonce, oauth_signature);
--   http_req := UTL_HTTP.begin_request (oauth_get_access_token_url, http_method, UTL_HTTP.http_version_1_1);
--   UTL_HTTP.set_response_error_check (TRUE);
--   UTL_HTTP.set_detailed_excp_support (TRUE);
--   UTL_HTTP.set_body_charset (http_req, 'UTF-8');
--   UTL_HTTP.set_header (http_req, 'User-Agent', 'Mozilla/4.0');
--   UTL_HTTP.set_header (r => http_req, NAME => 'Authorization', VALUE => var_http_authorization_header);

   DBMS_OUTPUT.put_line ('oauth_consumer_key=' || oauth_consumer_key);
   DBMS_OUTPUT.put_line ('oauth_timestamp=' || oauth_timestamp);
   DBMS_OUTPUT.put_line ('oauth_nonce=' || oauth_nonce);
   DBMS_OUTPUT.put_line ('oauth_consumer_secret=' || oauth_consumer_secret);
   DBMS_OUTPUT.put_line ('oauth_base_string=' || oauth_base_string);
   DBMS_OUTPUT.put_line ('oauth_signature=' || oauth_signature);
   DBMS_OUTPUT.put_line ('var_http_authorization_header=' || var_http_authorization_header);

--   http_resp := UTL_HTTP.get_response (http_req);

--   IF show_header = 1
--   THEN
--      DBMS_OUTPUT.put_line ('status code: ' || http_resp.status_code);
--      DBMS_OUTPUT.put_line ('reason phrase: ' || http_resp.reason_phrase);

--      FOR i IN 1 .. UTL_HTTP.get_header_count (http_resp)
--      LOOP
--         UTL_HTTP.get_header (http_resp, i, h_name, h_value);
--         DBMS_OUTPUT.put_line (h_name || ': ' || h_value);
--      END LOOP;
--   END IF;

--   BEGIN
--      WHILE 1 = 1
--      LOOP
--         UTL_HTTP.read_line (http_resp, res_value, TRUE);

--         IF INSTR (res_value, 'oauth_token') > 0
--         THEN
--            oauth_token :=
--               utl_url.unescape (SUBSTR (res_value
--                                        ,13
--                                        , INSTR (res_value, '&oauth_token_secre') - INSTR (res_value, 'oauth_token') - 12));
--            oauth_token_secret :=
--               utl_url.unescape (SUBSTR (res_value
--                                        , INSTR (res_value, '&oauth_token_secret') + 20
--                                        ,   INSTR (res_value, '&oauth_callback_confirmed')
--                                          - INSTR (res_value, '&oauth_token_secret')
--                                          - 20));
--            DBMS_OUTPUT.put_line ('oauth_token:' || oauth_token);
--            DBMS_OUTPUT.put_line ('oauth_token_secret:' || oauth_token_secret);
--            DBMS_OUTPUT.put_line (   'Please point your browser to: '
--                                  || oauth_authorize_url
--                                  || '?oauth_token='
--                                  || urlencode (oauth_token));
--            DBMS_OUTPUT.put_line ('Login and and note down the verifier code received');
--         END IF;
--      END LOOP;
--   EXCEPTION
--      WHEN UTL_HTTP.end_of_body
--      THEN
--         NULL;
--   END;

--   UTL_HTTP.end_response (http_resp);
EXCEPTION
   WHEN OTHERS
   THEN
      DBMS_OUTPUT.put_line (SQLERRM);
      RAISE;
END;
/