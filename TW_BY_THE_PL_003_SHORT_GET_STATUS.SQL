/* Formatted on 2010/08/11 12:11 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'GET';
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:C:\oracle';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_api_url                 VARCHAR2 (1000) := 'https://twitter.com/statuses/user_timeline.xml';
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
                                     ,oauth_access_token);
   oauth_signature := oauth.signature (oauth_base_string, oauth.key_token (oauth_consumer_secret, oauth_access_token_secret));
   var_http_req_url :=
      oauth.http_req_url_access_token (oauth_api_url
                                      ,oauth_consumer_key
                                      ,oauth_timestamp
                                      ,oauth_nonce
                                      ,oauth_signature
                                      ,oauth_access_token);

   SELECT UTL_HTTP.request (var_http_req_url)
   INTO   return_xml
   FROM   DUAL;

   DBMS_OUTPUT.put_line ('return_html=' || return_xml);
END;
/