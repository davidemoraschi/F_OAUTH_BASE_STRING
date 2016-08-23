/* Formatted on 2010/08/11 08:53 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'GET';
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:/u01/app/oracle/product/11.2.0/wallet';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_get_request_token_url   VARCHAR2 (1000) := 'https://api.linkedin.com/uas/oauth/requestToken';
   oauth_authorize_url           VARCHAR2 (1000) := 'https://api.twitter.com/oauth/authorize';
   oauth_consumer_key            VARCHAR2 (200) := '3cRzOaNPZ--tWaK1KxkJIzmr_w27LsARHif1_c8IiUcnPfMCchrE6izqIS4S7ni3';
   oauth_consumer_secret         VARCHAR2 (200) := 'z1mhC9OFvogBu66Bav4iyvGe6Y5f4tFTxbsopuCEY6Y0O2ZlX-tCoWMSJOp1tHIX';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_base_string             VARCHAR2 (1000);
   oauth_signature               VARCHAR2 (100);
   oauth_token                   VARCHAR2 (500);
   oauth_token_secret            VARCHAR2 (500);
   v_http_req_url                VARCHAR2 (4000);
   return_html                   VARCHAR2 (32767);
BEGIN
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   UTL_HTTP.set_wallet (PATH => con_str_wallet_path, PASSWORD => con_str_wallet_pass);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);

   SELECT utl_linkedin.urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT TO_CHAR ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400)
                   - (TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600))
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_base_string :=
                    utl_linkedin.base_string (http_method, oauth_get_request_token_url, oauth_consumer_key, oauth_timestamp, oauth_nonce);
   oauth_signature := utl_linkedin.signature (oauth_base_string, utl_linkedin.KEY (oauth_consumer_secret));
   v_http_req_url :=
               utl_linkedin.http_req_url (oauth_get_request_token_url, oauth_consumer_key, oauth_timestamp, oauth_nonce, oauth_signature);
   DBMS_OUTPUT.put_line ('oauth_consumer_key=' || oauth_consumer_key);
   DBMS_OUTPUT.put_line ('oauth_timestamp=' || oauth_timestamp);
   DBMS_OUTPUT.put_line ('oauth_nonce=' || oauth_nonce);
   DBMS_OUTPUT.put_line ('oauth_consumer_secret=' || oauth_consumer_secret);
   DBMS_OUTPUT.put_line ('oauth_base_string=' || oauth_base_string);
   DBMS_OUTPUT.put_line ('oauth_signature=' || oauth_signature);

   SELECT UTL_HTTP.request (v_http_req_url)
   INTO   return_html
   FROM   DUAL;

   SELECT utl_linkedin.get_token (utl_linkedin.get_token (return_html, 1, '&'), 2, '=')
   INTO   oauth_token
   FROM   DUAL;

   SELECT utl_linkedin.get_token (utl_linkedin.get_token (return_html, 2, '&'), 2, '=')
   INTO   oauth_token_secret
   FROM   DUAL;

   DBMS_OUTPUT.put_line ('oauth_token=' || oauth_token);
   DBMS_OUTPUT.put_line ('oauth_token_secret=' || oauth_token_secret);
   DBMS_OUTPUT.put_line ('Please point your browser to: ' || oauth_authorize_url || '?oauth_token=' || oauth_token);
   DBMS_OUTPUT.put_line ('Login and and note down the verifier code received');                                         --UfAtkasJ
END;
/