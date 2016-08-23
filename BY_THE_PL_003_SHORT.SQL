/* Formatted on 2010/08/10 21:29 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_api_url                 VARCHAR2 (1000) := 'http://1daylater.com/api';
   oauth_consumer_key            VARCHAR2 (50) := 'NHx8CZzuf9XEF6C2ksimwDkS7Fw=';
   oauth_consumer_secret         VARCHAR2 (50) := '7XF7YN/rNzYcqDlJFsTqyC81KWw=';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_signature               VARCHAR2 (100);
   --oauth_token                   VARCHAR2 (500) := 'bJmvayPVSgr6vk1Gq8lEeasvTgY=';
   --oauth_token_secret            VARCHAR2 (500) := 'tNy8Xe5GugLIEGykkCCjVvgzPAA=';
   oauth_access_token            VARCHAR2 (500) := 'YuyaLKagohKRVEuRbC2LOND/ivQ=';
   oauth_access_token_secret     VARCHAR2 (500) := 'vinyeYhDmHPvlbN0Cn2nT7oBtSk=';
   oauth_verifier                VARCHAR2 (500) := 'UfAtkasJ';
   v_http_req_url                VARCHAR2 (4000);
   var_http_request              UTL_HTTP.req;
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

   oauth_signature :=
      oauth.signature (oauth.base_string_access_token (oauth_api_url
                                                      ,oauth_consumer_key
                                                      ,oauth_timestamp
                                                      ,oauth_nonce
                                                      ,oauth_access_token)
                      ,oauth.key_token (oauth_consumer_secret, oauth_access_token_secret));
   var_http_request_params :=
        'oauth_consumer_key='
      || oauth_consumer_key
      || '&oauth_nonce='
      || oauth_nonce
      || '&oauth_signature_method='
      || 'HMAC-SHA1'
      || '&oauth_timestamp='
      || oauth_timestamp
      || '&oauth_token='
      || oauth_access_token
      || '&oauth_version=1.0'
      || '&oauth_signature='
      || oauth_signature;
   var_http_request := UTL_HTTP.begin_request (url => oauth_api_url, method => 'POST');
   UTL_HTTP.set_header (r => var_http_request, NAME => 'Content-Type', VALUE => 'application/x-www-form-urlencoded');
   UTL_HTTP.set_header (r => var_http_request, NAME => 'Content-Length', VALUE => LENGTH (var_http_request_params));
   UTL_HTTP.write_text (var_http_request, var_http_request_params);
   var_http_response := UTL_HTTP.get_response (r => var_http_request);

   --   UTL_HTTP.set_header (r => var_http_request, NAME => 'Accept-Charset', VALUE => 'iso-8859-1');
   --   UTL_HTTP.set_body_charset (var_http_request, 'UTF8');
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