/* Formatted on 2010/08/10 18:30 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   oauth_get_request_token_url CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/get_request_token';
   oauth_authorize_url  CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/authorize';
   oauth_get_access_token_url CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/get_access_token';
   oauth_callback       CONSTANT VARCHAR2 (1000) := 'oob';
   oauth_consumer_key   CONSTANT VARCHAR2 (50) := urlencode ('NHx8CZzuf9XEF6C2ksimwDkS7Fw=');
   oauth_nonce                   VARCHAR2 (50);
   oauth_signature_method CONSTANT VARCHAR2 (10) := urlencode ('HMAC-SHA1');
   oauth_timestamp               VARCHAR2 (50);
   oauth_timestamp_offset        VARCHAR2 (50) := TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600;
   oauth_version        CONSTANT VARCHAR2 (5) := urlencode ('1.0');
   oauth_consumer_secret CONSTANT VARCHAR2 (50) := '7XF7YN/rNzYcqDlJFsTqyC81KWw=';
   oauth_token                   VARCHAR2 (500);
   oauth_token_secret            VARCHAR2 (500);
   --oauth_verifier                                VARCHAR2 (500) := 'vd3fgs3D';
   oauth_base_string             VARCHAR2 (4000);
   oauth_key                     VARCHAR2 (500) := urlencode (oauth_consumer_secret) || '&';       -- || urlencode (oauth_token);
   oauth_signature               VARCHAR2 (100);
   v_http_req_url                VARCHAR2 (4000);
   http_method                   VARCHAR2 (5) := 'GET';
   http_req                      UTL_HTTP.req;
   http_resp                     UTL_HTTP.resp;
   h_name                        VARCHAR2 (255);
   h_value                       VARCHAR2 (1023);
   res_value                     VARCHAR2 (32767);
   show_header                   NUMBER := 0;
   show_xml                      NUMBER := 1;
   return_html                   VARCHAR2 (32767);
BEGIN
   SELECT urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT TO_CHAR ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400)
                   - (TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600))
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_signature :=
      oauth.signature (oauth.base_string ('http://1daylater.com/get_request_token'
                                         ,'NHx8CZzuf9XEF6C2ksimwDkS7Fw='
                                         ,oauth_timestamp
                                         ,oauth_nonce)
                      ,oauth.KEY ('7XF7YN/rNzYcqDlJFsTqyC81KWw='));
   v_http_req_url :=
      oauth.http_req_url ('http://1daylater.com/get_request_token'
                         ,'NHx8CZzuf9XEF6C2ksimwDkS7Fw='
                         ,oauth_timestamp
                         ,oauth_nonce
                         ,oauth_signature);
   --         oauth_get_request_token_url
   --      || '?'
   --      || 'oauth_callback'
   --      || '='
   --      || oauth_callback
   --      || '&'
   --      || 'oauth_consumer_key'
   --      || '='
   --      || oauth_consumer_key
   --      || '&'
   --      || 'oauth_nonce'
   --      || '='
   --      || oauth_nonce
   --      || '&'
   --      || 'oauth_signature'
   --      || '='
   --      || urlencode (oauth_signature)
   --      || '&'
   --      || 'oauth_signature_method'
   --      || '='
   --      || oauth_signature_method
   --      || '&'
   --      || 'oauth_timestamp'
   --      || '='
   --      || oauth_timestamp
   --      || '&'
   --      || 'oauth_version'
   --      || '='
   --      || oauth_version;
      /* in case it's needed set proxy */
      /*+++++++++++++++++++++++++++++++*/
   UTL_HTTP.set_proxy ('10.234.23.117:8080');

   SELECT UTL_HTTP.request (v_http_req_url)
   INTO   return_html
   FROM   DUAL;

   DBMS_OUTPUT.put_line ('return_html=' || return_html);
--   /*+++++++++++++++++++++++++++++++*/
--   /* in case it's needed set proxy */
--   http_req := UTL_HTTP.begin_request (v_http_req_url, http_method, UTL_HTTP.http_version_1_1);
--   UTL_HTTP.set_response_error_check (TRUE);
--   UTL_HTTP.set_detailed_excp_support (TRUE);
--   UTL_HTTP.set_body_charset (http_req, 'UTF-8');
--   UTL_HTTP.set_header (http_req, 'User-Agent', 'Mozilla/4.0');

--   IF show_header = 1
--   THEN
--      DBMS_OUTPUT.put_line ('oauth_get_request_token_url=' || oauth_get_request_token_url);
--      DBMS_OUTPUT.put_line ('oauth_callback=' || oauth_callback);
--      DBMS_OUTPUT.put_line ('oauth_consumer_key=' || oauth_consumer_key);
--      DBMS_OUTPUT.put_line ('oauth_nonce=' || oauth_nonce);
--      DBMS_OUTPUT.put_line ('oauth_signature_method=' || oauth_signature_method);
--      DBMS_OUTPUT.put_line ('oauth_timestamp=' || oauth_timestamp);
--      DBMS_OUTPUT.put_line ('oauth_version=' || oauth_version);
--      DBMS_OUTPUT.put_line ('oauth_consumer_secret=' || oauth_consumer_secret);
--      DBMS_OUTPUT.put_line ('oauth_base_string=' || oauth_base_string);
--      DBMS_OUTPUT.put_line ('oauth_key:' || oauth_key);
--      DBMS_OUTPUT.put_line ('oauth_signature=' || oauth_signature);
--   --DBMS_OUTPUT.put_line ('l_sig_mac='||l_sig_mac);
--   --DBMS_OUTPUT.put_line ('http_req_url='||http_req_url);
--   END IF;

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

--   IF show_xml = 1
--   THEN
--      BEGIN
--         WHILE 1 = 1
--         LOOP
--            UTL_HTTP.read_line (http_resp, res_value, TRUE);
--            DBMS_OUTPUT.put_line ('res_value:' || res_value);

--            IF INSTR (res_value, 'oauth_token') > 0
--            THEN
--               oauth_token :=
--                  utl_url.unescape (SUBSTR (res_value
--                                           ,13
--                                           , INSTR (res_value, '&oauth_token_secre') - INSTR (res_value, 'oauth_token') - 12));
--               oauth_token_secret :=
--                  utl_url.unescape (SUBSTR (res_value
--                                           , INSTR (res_value, '&oauth_token_secret') + 20
--                                           ,   INSTR (res_value, '&oauth_callback_confirmed')
--                                             - INSTR (res_value, '&oauth_token_secret')
--                                             - 20));
--               oauth_key := urlencode (oauth_consumer_secret) || '&' || urlencode (oauth_token_secret);
--               DBMS_OUTPUT.put_line ('oauth_token:' || oauth_token);
--               DBMS_OUTPUT.put_line ('oauth_token_secret:' || oauth_token_secret);
--               --            DBMS_OUTPUT.put_line ('oauth_key:'||oauth_key);
--               DBMS_OUTPUT.put_line (   'Please point your browser to: '
--                                     || oauth_authorize_url
--                                     || '?oauth_token='
--                                     || urlencode (oauth_token));
--               DBMS_OUTPUT.put_line ('Login and and note down the verifier code received');
--            END IF;
--         END LOOP;
--      EXCEPTION
--         WHEN UTL_HTTP.end_of_body
--         THEN
--            NULL;
--      END;
--   END IF;

--   UTL_HTTP.end_response (http_resp);
EXCEPTION
   WHEN OTHERS
   THEN
      DBMS_OUTPUT.put_line (SQLERRM);
      RAISE;
END;
/