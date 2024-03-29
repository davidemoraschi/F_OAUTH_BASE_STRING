/* Formatted on 2010/08/11 12:49 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'POST';
   http_req                      UTL_HTTP.req;
   http_resp                     UTL_HTTP.resp;
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_api_url                 VARCHAR2 (1000) := 'http://api.twitter.com/1/statuses/update.xml';
   oauth_consumer_key            VARCHAR2 (50);
   oauth_consumer_secret         VARCHAR2 (50);
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_base_string             VARCHAR2 (1000);
   oauth_signature               VARCHAR2 (100);
   oauth_access_token            VARCHAR2 (500);
   oauth_access_token_secret     VARCHAR2 (500);
   var_http_req_url              VARCHAR2 (4000);
   return_xml                    VARCHAR2 (30000);
   var_http_authorization_header VARCHAR2 (1024);
   v_user_params                 VARCHAR2 (1024) := 'status='||urlencode('tenteras o no tenteras');
   show_header                   NUMBER := 0;
   h_name                        VARCHAR2 (255);
   h_value                       VARCHAR2 (1023);
   res_value                     VARCHAR2 (32767);
BEGIN
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   UTL_HTTP.set_wallet (PATH => con_str_wallet_path, PASSWORD => con_str_wallet_pass);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);

   SELECT oauth_consumer_key, oauth_consumer_secret, oauth_access_token, oauth_access_token_secret
   INTO   oauth_consumer_key, oauth_consumer_secret, oauth_access_token, oauth_access_token_secret
   FROM   oauth_parameters;

   SELECT urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT TO_CHAR ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400)
                   - (TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600))
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_base_string :=
         oauth.base_string_access_token (http_method
                                        ,oauth_api_url
                                        ,oauth_consumer_key
                                        ,oauth_timestamp
                                        ,oauth_nonce
                                        ,oauth_access_token)
      || urlencode ('&' || v_user_params);
   oauth_signature := oauth.signature (oauth_base_string, oauth.key_token (oauth_consumer_secret, oauth_access_token_secret));
   var_http_req_url :=
      oauth.http_req_url_access_token (oauth_api_url
                                      ,oauth_consumer_key
                                      ,oauth_timestamp
                                      ,oauth_nonce
                                      ,oauth_signature
                                      ,oauth_access_token);
   var_http_authorization_header :=
                oauth.authorization_header (oauth_consumer_key, oauth_access_token, oauth_timestamp, oauth_nonce, oauth_signature);
--   DBMS_OUTPUT.put_line ('oauth_consumer_key=' || oauth_consumer_key);
--   DBMS_OUTPUT.put_line ('oauth_timestamp=' || oauth_timestamp);
--   DBMS_OUTPUT.put_line ('oauth_nonce=' || oauth_nonce);
--   DBMS_OUTPUT.put_line ('oauth_consumer_secret=' || oauth_consumer_secret);
--   DBMS_OUTPUT.put_line ('oauth_access_token=' || oauth_access_token);
--   DBMS_OUTPUT.put_line ('oauth_access_token_secret=' || oauth_access_token_secret);
--   DBMS_OUTPUT.put_line ('oauth_base_string=' || oauth_base_string);
--   DBMS_OUTPUT.put_line ('oauth_signature=' || oauth_signature);
--   DBMS_OUTPUT.put_line ('var_http_authorization_header=' || var_http_authorization_header);
--   DBMS_OUTPUT.put_line ('oauth_api_url=' || oauth_api_url);
--   DBMS_OUTPUT.put_line ('http_method=' || http_method);
   http_req := UTL_HTTP.begin_request (oauth_api_url, http_method, UTL_HTTP.http_version_1_1);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);
   UTL_HTTP.set_body_charset (http_req, 'UTF-8');
   UTL_HTTP.set_header (http_req, 'User-Agent', 'Mozilla/4.0');
   UTL_HTTP.set_header (r => http_req, NAME => 'Authorization', VALUE => var_http_authorization_header);
   UTL_HTTP.set_header (r => http_req, NAME => 'Content-Type', VALUE => 'application/x-www-form-urlencoded');
   UTL_HTTP.set_header (r => http_req, NAME => 'Content-Length', VALUE => LENGTH (v_user_params));
   UTL_HTTP.write_text (http_req, v_user_params);
   http_resp := UTL_HTTP.get_response (http_req);

   IF show_header = 1
   THEN
      DBMS_OUTPUT.put_line ('status code: ' || http_resp.status_code);
      DBMS_OUTPUT.put_line ('reason phrase: ' || http_resp.reason_phrase);

      FOR i IN 1 .. UTL_HTTP.get_header_count (http_resp)
      LOOP
         UTL_HTTP.get_header (http_resp, i, h_name, h_value);
         DBMS_OUTPUT.put_line (h_name || ': ' || h_value);
      END LOOP;
   END IF;

   BEGIN
      WHILE 1 = 1
      LOOP
         UTL_HTTP.read_line (http_resp, res_value, TRUE);
         --DBMS_OUTPUT.put_line (res_value);
      END LOOP;
   EXCEPTION
      WHEN UTL_HTTP.end_of_body
      THEN
         NULL;
   END;

   UTL_HTTP.end_response (http_resp);
EXCEPTION
   WHEN OTHERS
   THEN
      DBMS_OUTPUT.put_line (SQLERRM);
      RAISE;
END;
/