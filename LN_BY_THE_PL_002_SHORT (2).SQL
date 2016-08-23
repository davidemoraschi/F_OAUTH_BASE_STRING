/* Formatted on 2010/08/17 18:31 (Formatter Plus v4.8.8) */
SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #

DECLARE
   http_method          CONSTANT VARCHAR2 (5) := 'GET';
   con_str_wallet_path  CONSTANT VARCHAR2 (50) := 'file:/u01/app/oracle/product/11.2.0/wallet';
   con_str_wallet_pass  CONSTANT VARCHAR2 (50) := 'Lepanto1571';
   oauth_get_request_token_url   VARCHAR2 (1000) := 'https://api.linkedin.com/uas/oauth/requestToken';
   oauth_authorize_url           VARCHAR2 (1000) := 'https://www.linkedin.com/uas/oauth/authorize';
   oauth_get_access_token_url    VARCHAR2 (1000) := 'https://api.linkedin.com/uas/oauth/accessToken';
   oauth_consumer_key            VARCHAR2 (500);                                             -- := 'NHx8CZzuf9XEF6C2ksimwDkS7Fw=';
   oauth_consumer_secret         VARCHAR2 (500);                                             -- := '7XF7YN/rNzYcqDlJFsTqyC81KWw=';
   oauth_nonce                   VARCHAR2 (50);
   oauth_timestamp               VARCHAR2 (50);
   oauth_signature               VARCHAR2 (100);
   oauth_token                   VARCHAR2 (500) := '5c3e57a9-69fc-4f1a-9f7d-7e637c21544a';
   oauth_token_secret            VARCHAR2 (500) := 'e5fe9180-117c-4002-a17f-7ced09c982f3';
   oauth_verifier                VARCHAR2 (500) := '38308';
   oauth_access_token            VARCHAR2 (500);
   oauth_access_token_secret     VARCHAR2 (500);
   v_http_req_url                VARCHAR2 (4000);
   return_html                   VARCHAR2 (32767);
   v_oauth_access_token          VARCHAR2 (500);
   v_oauth_access_token_secret   VARCHAR2 (500);
BEGIN
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   UTL_HTTP.set_wallet (PATH => con_str_wallet_path, PASSWORD => con_str_wallet_pass);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);

   SELECT oauth_consumer_key, oauth_consumer_secret
   INTO   oauth_consumer_key, oauth_consumer_secret
   FROM   oauth_linkedin_parameters;

   SELECT pkg_oauth.urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT TO_CHAR ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400) - 6000)
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_signature :=
      pkg_oauth.signature (pkg_oauth.base_string_token (http_method, oauth_get_access_token_url
                                                       ,oauth_consumer_key
                                                       ,oauth_timestamp
                                                       ,oauth_nonce
                                                       ,oauth_token
                                                       ,oauth_verifier)
                          ,pkg_oauth.key_token (oauth_consumer_secret, oauth_token_secret));
   v_http_req_url :=
      utl_linkedin.http_req_url_token (oauth_get_access_token_url
                               ,oauth_consumer_key
                               ,oauth_timestamp
                               ,oauth_nonce
                               ,oauth_signature
                               ,oauth_token
                               ,oauth_verifier);

   SELECT UTL_HTTP.request (v_http_req_url)
   INTO   return_html
   FROM   DUAL;

   SELECT utl_linkedin.get_token (utl_linkedin.get_token (return_html, 1, '&'), 2, '=')
   INTO   v_oauth_access_token
   FROM   DUAL;

   SELECT utl_linkedin.get_token (utl_linkedin.get_token (return_html, 2, '&'), 2, '=')
   INTO   v_oauth_access_token_secret
   FROM   DUAL;

   DBMS_OUTPUT.put_line ('return_html=' || return_html);
   DBMS_OUTPUT.put_line ('oauth_access_token=' || utl_url.unescape (v_oauth_access_token));
   DBMS_OUTPUT.put_line ('oauth_access_token_secret=' || utl_url.unescape (v_oauth_access_token_secret));


   UPDATE oauth_linkedin_parameters
      SET oauth_access_token = v_oauth_access_token
         ,oauth_access_token_secret = v_oauth_access_token_secret;

   COMMIT;
END;
/