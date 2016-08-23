/* Formatted on 2010/08/11 09:38 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'POST';
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
--   oauth_get_request_token_url   VARCHAR2 (1000) := 'https://api.twitter.com/oauth/request_token';
   oauth_api_url                 VARCHAR2 (1000) := 'http://api.twitter.com/1/statuses/update.json';
   oauth_consumer_key            VARCHAR2 (50) := '5HFrVcwi7Hp1KpEQc4gfZQ';
   oauth_consumer_secret         VARCHAR2 (50) := 'FV3fn9H6ZR3yrgNjfmb21I6zF58KmZLydWq4jXHqhA';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_base_string             VARCHAR2 (1000);
   oauth_signature               VARCHAR2 (100);
   oauth_access_token            VARCHAR2 (500) := '112395774-GpByGwXf2BPbsvboBA4eHmylKHffDzLHFNVhqaHV';
   oauth_access_token_secret     VARCHAR2 (500) := 'dd3aYnJNijI85nEillTqiA7TKCQHOSzWQfPOlqUVjJ0';
   v_http_req_url                VARCHAR2 (4000);
   var_http_request              UTL_HTTP.req;
   var_http_authorization_header VARCHAR2 (1024);
   var_http_request_params       VARCHAR2 (1024);
   var_http_response             UTL_HTTP.resp;
   var_http_value                VARCHAR2 (32767);
   ret_val                       VARCHAR2 (1024);
   base_string                   VARCHAR2 (4000);
BEGIN
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   UTL_HTTP.set_wallet (PATH => con_str_wallet_path, PASSWORD => con_str_wallet_pass);

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
                                     ,oauth_access_token);
   oauth_signature := oauth.signature (oauth_base_string, oauth.key_token (oauth_consumer_secret, oauth_access_token_secret));
   var_http_authorization_header :=
                oauth.authorization_header (oauth_consumer_key, oauth_access_token, oauth_timestamp, oauth_nonce, oauth_signature);
   var_http_request_params := 'status=oracle';
   DBMS_OUTPUT.put_line ('oauth_consumer_key=' || oauth_consumer_key);
   DBMS_OUTPUT.put_line ('oauth_timestamp=' || oauth_timestamp);
   DBMS_OUTPUT.put_line ('oauth_nonce=' || oauth_nonce);
   DBMS_OUTPUT.put_line ('oauth_consumer_secret=' || oauth_consumer_secret);
   DBMS_OUTPUT.put_line ('oauth_base_string=' || oauth_base_string);
   DBMS_OUTPUT.put_line ('oauth_signature=' || oauth_signature);
   DBMS_OUTPUT.put_line ('var_http_authorization_header=' || var_http_authorization_header);
   DBMS_OUTPUT.put_line ('var_http_request_params=' || var_http_request_params);
   var_http_request := UTL_HTTP.begin_request (url => oauth_api_url, method => http_method);
   UTL_HTTP.set_header (r => var_http_request, NAME => 'Content-Type', VALUE => 'application/x-www-form-urlencoded');
   UTL_HTTP.set_header (r => var_http_request, NAME => 'Authorization', VALUE => var_http_authorization_header);
   UTL_HTTP.set_header (r => var_http_request, NAME => 'Content-Length', VALUE => LENGTH (var_http_request_params));
   UTL_HTTP.write_text (var_http_request, var_http_request_params);
   var_http_response := UTL_HTTP.get_response (r => var_http_request);

   --   UTL_HTTP.set_header (r => var_http_request, NAME => 'Accept-Charset', VALUE => 'iso-8859-1');
         UTL_HTTP.set_body_charset (var_http_request, 'UTF8');
      --   UTL_HTTP.set_response_error_check (TRUE);
      --   UTL_HTTP.set_detailed_excp_support (TRUE);
   BEGIN
      ret_val := var_http_response.status_code || ' - ' || var_http_response.reason_phrase;

      LOOP
         UTL_HTTP.read_line (r => var_http_response, DATA => var_http_value, remove_crlf => TRUE);
         DBMS_OUTPUT.put_line (var_http_value);
      END LOOP;
   EXCEPTION
      WHEN UTL_HTTP.end_of_body
      THEN
         UTL_HTTP.end_response (r => var_http_response);
   END;
END;
/